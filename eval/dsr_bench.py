"""DSR workflow benchmark on the 200,000-customer synthetic estate of eval/erasure_eval.py.

Workload: for each of 3 laws x 3 request types, N requests (default 60, so 540) run end to end through DSRService
(intake -> verify_identity -> process -> respond) with a hash-chained AuditLog. Every request uses a different
customer. Genuine claims carry two correct factors (one for the CCPA opt-out, see sdai/dsr.py). Per request and per
stage time is time.perf_counter. Then: residual rows after every erasure, identity-verification confusion matrix on a
labelled set of attempts, consent-withdrawal leftovers, a deterministic deadline sweep over 2027-2028, a seeded
near-deadline tracker demo, and audit-chain / log-leak checks. Hardware, command, seed and date are recorded.

Usage: .venv/bin/python eval/dsr_bench.py [requests_per_law_and_type]
"""
from __future__ import annotations

import json
import platform
import random
import statistics
import subprocess
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import duckdb  # noqa: E402

from sdai import deadlines as dl  # noqa: E402
from sdai.audit import AuditLog  # noqa: E402
from sdai.deadlines import Law, RequestType as T  # noqa: E402
from sdai.dsr import DSRequest, DSRService, FACTORS, _norm, tracker  # noqa: E402
from sdai.erasure import build_estate, identifiers, scan, shared_identifiers  # noqa: E402
from sdai.synth import customers  # noqa: E402

SEED = 42
N_CUSTOMERS = 200_000
RECEIVED = date(2026, 11, 23)  # fixed receipt/completion date: the service never reads the clock
STAGES = ("intake", "verify", "process", "respond")
COMBOS = [(lw, t) for lw in Law for t in T]
TABLES = ("crm.customers", "care.call_notes", "billing.invoices", "analytics.customer_snapshot", "marketing.contact_list")


def pct(xs, q):
    s = sorted(xs)
    return s[int(q * (len(s) - 1))]


def stats(xs):
    return {"n": len(xs), "p50": round(statistics.median(xs), 3), "p95": round(pct(xs, 0.95), 3),
            "mean": round(statistics.mean(xs), 3), "max": round(max(xs), 3)}


def sysctl(name):
    try:
        return subprocess.run(["sysctl", "-n", name], capture_output=True, text=True, timeout=5, check=True).stdout.strip()
    except Exception:  # noqa: BLE001 - not macOS, or no sysctl
        return None


def environment():
    mem = sysctl("hw.memsize")
    return {"platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
            "python": platform.python_version(), "duckdb": duckdb.__version__,
            "cpu_brand": sysctl("machdep.cpu.brand_string"), "ram_gb": round(int(mem) / 2**30, 1) if mem else None,
            "command": " ".join(getattr(sys, "orig_argv", sys.argv)), "seed": SEED,
            "date_run": datetime.now().astimezone().isoformat(timespec="seconds")}


def claims_for(row, factors, variants=False, rng=None):
    full = {"email": row["email"], "phone": row["phone"], "tckn_last4": row["tckn"][-4:]}
    c = {"customer_id": row["customer_id"], **{f: full[f] for f in factors}}
    if variants and rng:
        c = vary(c, rng)
    return c


PHONE_FORMS = [lambda d: "0" + d, lambda d: "+90 " + " ".join([d[:3], d[3:6], d[6:8], d[8:]]), lambda d: "+90" + d,
               lambda d: d, lambda d: "0 (" + d[:3] + ") " + d[3:6] + " " + d[6:8] + " " + d[8:],
               lambda d: "0" + d[:3] + "-" + d[3:6] + "-" + d[6:]]
EMAIL_FORMS = [str.upper, str.title, lambda e: "  " + e + " ", lambda e: e.upper() + " ", lambda e: e.swapcase()]


def vary(c, rng):
    c = dict(c)
    if "phone" in c:
        c["phone"] = rng.choice(PHONE_FORMS)("".join(ch for ch in c["phone"] if ch.isdigit())[-10:])
    if "email" in c:
        c["email"] = rng.choice(EMAIL_FORMS)(c["email"])
    return c


def build_attempts(rows, by_id, rng):
    """Labelled identity attempts: (category, law, type, claims, expected_accept)."""
    ids = list(by_id)
    two_factor = [x for x in COMBOS if x != (Law.CCPA, T.CONSENT_WITHDRAWAL)]
    OPTOUT = (Law.CCPA, T.CONSENT_WITHDRAWAL)
    out = []

    def pick():
        return by_id[rng.choice(ids)]

    def other(f, row):  # a value for factor f that normalises differently from row's, taken from another customer
        key = {"email": "email", "phone": "phone", "tckn_last4": "tckn"}[f]
        while True:
            o = by_id[rng.choice(ids)]
            v = o[key][-4:] if f == "tckn_last4" else o[key]
            if _norm(f, v) != _norm(f, row[key][-4:] if f == "tckn_last4" else row[key]):
                return v

    def add(cat, combo, claims, ok):
        out.append((cat, combo[0], combo[1], claims, ok))

    for _ in range(60):
        r = pick(); fs = rng.sample(FACTORS, 2)
        add("genuine: two correct factors", rng.choice(two_factor), claims_for(r, fs), True)
    for _ in range(40):
        add("genuine: three correct factors", rng.choice(two_factor), claims_for(pick(), FACTORS), True)
    for _ in range(60):  # phone written in another format, plus a correct e-mail or TCKN tail
        r = pick(); c = claims_for(r, ("phone", rng.choice(("email", "tckn_last4"))))
        c["phone"] = rng.choice(PHONE_FORMS)("".join(ch for ch in r["phone"] if ch.isdigit())[-10:])
        add("genuine: phone in another format", rng.choice(two_factor), c, True)
    for _ in range(60):  # e-mail in another case or with stray spaces, plus a correct phone or TCKN tail
        r = pick(); c = claims_for(r, ("email", rng.choice(("phone", "tckn_last4"))))
        c["email"] = rng.choice(EMAIL_FORMS)(r["email"])
        add("genuine: e-mail case or spacing variant", rng.choice(two_factor), c, True)
    for _ in range(60):
        r = pick()
        add("genuine: CCPA opt-out, one correct factor", OPTOUT, claims_for(r, [rng.choice(FACTORS)], variants=True, rng=rng), True)

    for _ in range(60):  # claimed id is A, the factors are all B's
        a, b = pick(), pick()
        while b is a or any(_norm(f, claims_for(a, [f])[f]) == _norm(f, claims_for(b, [f])[f]) for f in FACTORS):
            b = pick()
        add("impostor: another customer's factors", rng.choice(two_factor), {**claims_for(b, FACTORS), "customer_id": a["customer_id"]}, False)
    for _ in range(60):
        r = pick(); good, bad = rng.sample(FACTORS, 2)
        c = {**claims_for(r, [good]), bad: other(bad, r)}
        add("impostor: one correct, one wrong", rng.choice(two_factor), c, False)
    for _ in range(60):
        r = pick(); good, bad1, bad2 = rng.sample(FACTORS, 3)
        c = {**claims_for(r, [good]), bad1: other(bad1, r), bad2: other(bad2, r)}
        add("impostor: one correct, two wrong", rng.choice(two_factor), c, False)
    for _ in range(60):
        add("impostor: one correct factor only", rng.choice(two_factor + [(Law.CCPA, T.ACCESS)] * 3), claims_for(pick(), [rng.choice(FACTORS)]), False)
    for _ in range(60):
        r = pick()
        add("impostor: all factors wrong", rng.choice(two_factor), {"customer_id": r["customer_id"], **{f: other(f, r) for f in FACTORS}}, False)
    for _ in range(40):  # an id that does not exist, with another customer's real factors
        b = pick()
        add("impostor: unknown customer id", rng.choice(COMBOS), {**claims_for(b, FACTORS), "customer_id": 9_000_000 + rng.randrange(10**6)}, False)
    for _ in range(40):
        add("impostor: empty claims", rng.choice(COMBOS), rng.choice([{"customer_id": pick()["customer_id"]},
            {"customer_id": pick()["customer_id"], "email": "", "phone": "", "tckn_last4": ""},
            {"customer_id": pick()["customer_id"], "email": None, "phone": " ", "tckn_last4": "--"}]), False)
    for _ in range(20):
        r = pick()
        add("impostor: non-numeric customer id", rng.choice(COMBOS), {**claims_for(r, FACTORS), "customer_id": rng.choice(["abc", "1; DROP TABLE x", "", None])}, False)
    for _ in range(40):  # phone differs in the last digit, the e-mail is right: one factor only
        r = pick(); d = "".join(ch for ch in r["phone"] if ch.isdigit())[-10:]
        d = d[:-1] + str((int(d[-1]) + 1 + rng.randrange(8)) % 10)
        add("impostor: phone one digit off, e-mail right", rng.choice(two_factor), {**claims_for(r, ["email"]), "phone": "0" + d}, False)
    for _ in range(40):
        r = pick(); f = rng.choice(FACTORS)
        add("impostor: CCPA opt-out, one wrong factor", OPTOUT, {"customer_id": r["customer_id"], f: other(f, r)}, False)
    for _ in range(40):
        a, b = pick(), pick(); f = rng.choice(FACTORS)
        while b is a or _norm(f, claims_for(a, [f])[f]) == _norm(f, claims_for(b, [f])[f]):
            b = pick()
        add("impostor: CCPA opt-out, another customer's factor", OPTOUT, {**claims_for(b, [f]), "customer_id": a["customer_id"]}, False)
    for _ in range(20):
        add("impostor: CCPA opt-out, no factor", OPTOUT, {"customer_id": pick()["customer_id"]}, False)
    rng.shuffle(out)
    return out


def verification_eval(est, attempts):
    svc = DSRService(est)  # no audit log: only the decision is measured here
    cats, tp = {}, {"TA": 0, "FA": 0, "TR": 0, "FR": 0}
    for cat, law, rtype, claims, expected in attempts:
        req = svc.intake(law, rtype, RECEIVED, claims)
        got = svc.verify_identity(req, RECEIVED)
        k = ("TA" if got else "FR") if expected else ("FA" if got else "TR")
        tp[k] += 1
        c = cats.setdefault(cat, {"attempts": 0, "accepted": 0, "expected": "accept" if expected else "reject"})
        c["attempts"] += 1; c["accepted"] += got
    n = len(attempts)
    pos, neg = tp["TA"] + tp["FR"], tp["FA"] + tp["TR"]
    return {"attempts": n, "genuine": pos, "impostor": neg, **tp, "accuracy": round((tp["TA"] + tp["TR"]) / n, 4),
            "FAR": round(tp["FA"] / neg, 4), "FRR": round(tp["FR"] / pos, 4), "by_category": cats}


def deadline_sweep():
    days = [date(2027, 1, 1) + timedelta(days=i) for i in range((date(2028, 12, 31) - date(2027, 1, 1)).days + 1)]
    out, reps = {}, 50
    base = time.perf_counter_ns()
    for _ in range(reps):
        for d in days:
            pass
    empty_ns = (time.perf_counter_ns() - base) / (reps * len(days))
    for law, t in COMBOS:
        r = dl.rule(law, t)
        for ext in ((False, True) if r.extension else (False,)):
            due = [dl.due_date(law, t, d, ext) for d in days]
            span = [(u - d).days for u, d in zip(due, days)]
            t0 = time.perf_counter_ns()
            for _ in range(reps):
                for d in days:
                    dl.due_date(law, t, d, ext)
            ns = (time.perf_counter_ns() - t0) / (reps * len(days))
            e = {"rule": f"{r.base}{'+' + str(r.extension) if ext else ''} {r.unit}", "receipt_dates": len(days),
                 "min_days_to_due": min(span), "max_days_to_due": max(span),
                 "due_on_weekend": sum(u.weekday() >= 5 for u in due),
                 "ns_per_call": round(ns, 1), "ns_per_call_net_of_empty_loop": round(ns - empty_ns, 1)}
            if r.unit == "months":
                e["month_end_clamps"] = sum(u.day != d.day for u, d in zip(due, days))
                e["days_to_due_histogram"] = {str(k): span.count(k) for k in sorted(set(span))}
            out[f"{law.value}/{t.value}/{'extended' if ext else 'base'}"] = e
    gd = [date(2028, 1, 1) + timedelta(days=i) for i in range(366)]
    samples = {str(d): {f"{law.value}/{t.value}/{'extended' if ext else 'base'}": str(dl.due_date(law, t, d, ext))
                        for law, t in COMBOS for ext in ((False, True) if dl.can_extend(law, t) else (False,))}
               for d in (date(2028, 1, 31), date(2027, 11, 15))}
    return {"empty_loop_ns": round(empty_ns, 1), "rules": out, "gdpr_base_days_to_due_by_receipt_2028": [(dl.due_date(Law.GDPR, T.ACCESS, d) - d).days for d in gd],
            "samples": samples}


def tracker_demo(n=500, today=date(2027, 6, 15)):
    rng = random.Random(SEED)
    reqs = []
    for i in range(n):
        law, t = rng.choice(COMBOS); rec = today - timedelta(days=rng.randrange(0, 121))
        reqs.append(DSRequest(f"Q{i:03d}", law, t, rec, dl.due_date(law, t, rec)))
    t0 = time.perf_counter(); q = tracker(reqs, today); ms = (time.perf_counter() - t0) * 1000
    count = lambda rows: {s: sum(r["status"] == s for r in rows) for s in ("ok", "due_soon", "overdue")}  # noqa: E731
    return {"today": str(today), "requests": n, "receipt_window_days": 120, "warn_days": 7, **count(q),
            "by_law_type": {f"{lw.value}/{t.value}": count([r for r in q if (r["law"], r["type"]) == (lw.value, t.value)]) for lw, t in COMBOS},
            "sorted_by_due": all(q[i]["due"] <= q[i + 1]["due"] for i in range(len(q) - 1)), "tracker_ms": round(ms, 2)}


def main():
    n_per = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    t_start = time.perf_counter()
    rng = random.Random(SEED)
    rows = customers(N_CUSTOMERS)
    by_id = {r["customer_id"]: r for r in rows}
    t = time.perf_counter(); est = build_estate(rows); build_s = time.perf_counter() - t
    con = est.con
    print(f"estate built in {build_s:.1f}s", flush=True)

    # -- identity verification on a labelled set (before anything is erased) ------------------------------------
    verification = verification_eval(est, build_attempts(rows, by_id, random.Random(SEED + 1)))
    print("verification:", {k: verification[k] for k in ("attempts", "TA", "FA", "TR", "FR")}, flush=True)

    # -- pick a distinct customer for every request ---------------------------------------------------------------
    keyed = {est.subject_key(r["customer_id"]): r["customer_id"] for r in rows}
    holders = sorted(keyed[k] for k in est.subject_index)
    used = set()

    def take(pool, k):
        got = rng.sample([c for c in pool if c not in used], k); used.update(got); return got

    consenting = [r["customer_id"] for r in rows if r["consent_marketing"]]
    plan = []
    for law in Law:
        er = take(holders, n_per // 2) + take([r["customer_id"] for r in rows], n_per - n_per // 2)  # half with RAG tickets
        for cid in er:
            plan.append((law, T.ERASURE, cid))
        for cid in take(consenting, n_per):
            plan.append((law, T.CONSENT_WITHDRAWAL, cid))
        for cid in take([r["customer_id"] for r in rows], n_per):
            plan.append((law, T.ACCESS, cid))
    rng.shuffle(plan)
    subjects = [c for _, _, c in plan]
    full_ids = {c: identifiers(est, c) for c in subjects}
    con.execute("CREATE TEMP TABLE subj (customer_id INTEGER)")
    con.executemany("INSERT INTO subj VALUES (?)", [[c] for c in subjects])
    others = lambda tb: con.execute(f"SELECT count(*) FROM {tb} WHERE customer_id NOT IN (SELECT customer_id FROM subj)").fetchone()[0]  # noqa: E731
    others_before = {tb: others(tb) for tb in TABLES}
    sizes_before = {tb: con.execute(f"SELECT count(*) FROM {tb}").fetchone()[0] for tb in TABLES}

    raw = Path("results/raw"); raw.mkdir(parents=True, exist_ok=True)
    for f in ("dsr_audit.jsonl", "dsr_audit.anchor"):
        (raw / f).unlink(missing_ok=True)
    audit = AuditLog(raw / "dsr_audit.jsonl")
    svc = DSRService(est, audit)

    # -- the workload ---------------------------------------------------------------------------------------------
    timings, residual_rows, retained_rows, erasure_status, failures, n_shared = [], 0, 0, {}, [], 0
    for law, rtype, cid in plan:
        row = by_id[cid]
        if rtype is T.ERASURE:  # identifiers and shared flags are read before the data goes (outside the timed stages)
            shared = shared_identifiers(est, cid, full_ids[cid]); n_shared += bool(shared)
            own = {k: v for k, v in full_ids[cid].items() if k not in shared}
        factors = [rng.choice(FACTORS)] if (law, rtype) == (Law.CCPA, T.CONSENT_WITHDRAWAL) else rng.sample(FACTORS, 2)
        c0 = time.perf_counter(); req = svc.intake(law, rtype, RECEIVED, claims_for(row, factors))
        c1 = time.perf_counter(); ok = svc.verify_identity(req, RECEIVED)
        c2 = time.perf_counter()
        if ok:
            svc.process(req, RECEIVED)
        c3 = time.perf_counter()
        try:
            resp = svc.respond(req)
        except ValueError:
            resp = None
        c4 = time.perf_counter()
        if not ok or resp is None:
            failures.append({"request": req.id, "law": law.value, "type": rtype.value, "verified": ok, "state": req.state})
        if rtype is T.ERASURE:
            after = scan(est, cid, own)
            residual_rows += sum(v for k, v in after.items() if k != "billing.invoices")
            retained_rows += after["billing.invoices"]
            st = req.outcome.get("status"); erasure_status[st] = erasure_status.get(st, 0) + 1
        ms = [(b - a) * 1000 for a, b in ((c0, c1), (c1, c2), (c2, c3), (c3, c4))]
        timings.append({"law": law.value, "type": rtype.value, "request": req.id, **dict(zip(STAGES, ms)), "total": (c4 - c0) * 1000,
                        "on_time": resp["on_time"] if resp else None})
    workload_s = sum(x["total"] for x in timings) / 1000

    # -- aggregate ------------------------------------------------------------------------------------------------
    def agg(sel):
        return {"total": stats([x["total"] for x in sel]), **{s: stats([x[s] for x in sel]) for s in STAGES}}

    by_type = {t.value: agg([x for x in timings if x["type"] == t.value]) for t in T}
    by_law_type = {f"{lw.value}/{t.value}": agg([x for x in timings if (x["law"], x["type"]) == (lw.value, t.value)]) for lw, t in COMBOS}
    wd = [c for lw, rt, c in plan if rt is T.CONSENT_WITHDRAWAL]
    left = con.execute(f"SELECT count(*) FROM marketing.contact_list WHERE customer_id IN ({','.join(map(str, wd))})").fetchone()[0]
    consent_on = con.execute(f"SELECT count(*) FROM crm.customers WHERE consent_marketing AND customer_id IN ({','.join(map(str, wd))})").fetchone()[0]
    erased = [c for lw, rt, c in plan if rt is T.ERASURE]
    others_after = {tb: others(tb) for tb in TABLES}
    sizes_after = {tb: con.execute(f"SELECT count(*) FROM {tb}").fetchone()[0] for tb in TABLES}
    log_text = audit.path.read_text()
    leak = {k: sum(full_ids[c][k] in log_text for c in subjects) for k in ("tckn", "email", "phone", "iban", "card_number")}
    out = {
        "environment": environment(),
        "scale": {"customers": N_CUSTOMERS, "call_notes": 300_000, "invoices": 2 * N_CUSTOMERS, "rag_tickets": 5_000,
                  "estate_build_s": round(build_s, 1), "requests_per_law_and_type": n_per, "requests_total": len(plan),
                  "erasure_requests": len(erased), "erasure_subjects_with_rag_tickets": sum(c in set(holders) for c in erased),
                  "note": "same estate as eval/erasure_eval.py (build_estate defaults); every request has its own customer"},
        "latency_ms": {"by_request_type": by_type, "by_law_and_type": by_law_type, "all_requests": agg(timings),
                       "sum_of_request_times_s": round(workload_s, 1)},
        "workload_outcomes": {"completed_end_to_end": len(plan) - len(failures), "failed_or_open": failures,
                              "erasure_status_counts": erasure_status,
                              "on_time_true": sum(bool(x["on_time"]) for x in timings)},
        "erasure_residual": {"subjects": len(erased), "residual_rows_outside_retained_invoices": residual_rows,
                             "retained_invoice_rows": retained_rows, "subjects_with_shared_identifiers": n_shared},
        "other_customers_unchanged": {"method": "row count of rows whose customer_id is not one of the processed subjects, before vs after",
                                      "before": others_before, "after": others_after,
                                      "unchanged": {tb: others_before[tb] == others_after[tb] for tb in TABLES},
                                      "store_sizes_before": sizes_before, "store_sizes_after": sizes_after},
        "consent_withdrawal": {"subjects": len(wd), "contact_list_rows_left": left, "consent_flag_still_true": consent_on},
        "verification": verification,
        "deadlines": deadline_sweep(),
        "tracker_demo": tracker_demo(),
        "audit": {"entries": len(audit.entries()), "chain_verified": audit.verify().ok, "subjects_checked": len(subjects),
                  "raw_identifier_hits_in_log": leak, "tckn_and_email_hits": leak["tckn"] + leak["email"]},
    }
    out["wall_time_s"] = round(time.perf_counter() - t_start, 1)
    Path("results").mkdir(exist_ok=True)
    Path("results/dsr_bench.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
    (raw / "dsr_bench_timings.json").write_text(json.dumps(timings))
    print(json.dumps({k: out[k] for k in ("scale", "latency_ms", "erasure_residual", "consent_withdrawal", "audit", "wall_time_s")}, indent=1)[:6000])


if __name__ == "__main__":
    main()
