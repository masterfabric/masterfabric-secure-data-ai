"""One simulated working day written to the hash-chained audit log by the real components.

The policy engine, the guard's rule layer, the RAG retriever and the erasure service all write to one
AuditLog. Only the clock is simulated (2026-11-20, 08:00-20:00 Europe/Istanbul, more traffic around 10:00 and
15:00); every decision in the log is what the component actually decided. Then the log is verified, three
tampering drills are run on copies of it, and append/verify throughput is measured.
"""
from __future__ import annotations

import json
import math
import random
import re
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import owasp_llm as o  # noqa: E402
from policy_eval import BYPASS  # noqa: E402
from sdai.audit import AuditLog, verify  # noqa: E402
from sdai.erasure import build_estate, erase  # noqa: E402
from sdai.guard import check_input  # noqa: E402
from sdai.policy import AccessDenied, PolicyEngine, lock_down  # noqa: E402
from sdai.rag import PRINCIPALS, TOPICS, SecureRetriever, corpus  # noqa: E402
from sdai.synth import customers  # noqa: E402

TZ = timezone(timedelta(hours=3))
DAY = datetime(2026, 11, 20, 8, 0, tzinfo=TZ)
ACTORS = {"dpo": ["dpo.aylin"], "fraud_analyst": ["fraud.kerem", "fraud.selin"],
          "data_scientist": ["ds.emre", "ds.zeynep", "ds.burak"], "marketing": ["mkt.deniz", "mkt.elif"],
          "support_istanbul": ["cc.ali", "cc.merve", "cc.hasan", "cc.gul"]}
NORMAL = {
    "dpo": ["SELECT count(*) FROM dpo.customers WHERE consent_marketing", "SELECT * FROM dpo.customers WHERE customer_id = {cid}"],
    "fraud_analyst": ["SELECT full_name, iban FROM fraud_analyst.customers WHERE customer_id = {cid}",
                      "SELECT city, count(*) FROM fraud_analyst.customers GROUP BY city"],
    "data_scientist": ["SELECT city, segment, avg(monthly_spend_try) FROM data_scientist.customers GROUP BY ALL",
                       "SELECT birth_date, count(*) FROM data_scientist.customers GROUP BY 1"],
    "marketing": ["SELECT email FROM marketing.customers WHERE segment = 'business' LIMIT 500",
                  "SELECT city, count(*) FROM marketing.customers GROUP BY city"],
    "support_istanbul": ["SELECT full_name, phone FROM support_istanbul.customers WHERE customer_id = {cid}"],
}


def arrivals(rng, n):
    """n timestamps between 08:00 and 20:00 with peaks around 10:00 and 15:00."""
    out = []
    while len(out) < n:
        h = rng.uniform(0, 12)
        w = 0.25 + math.exp(-((h - 2) ** 2) / 2) + 0.8 * math.exp(-((h - 7) ** 2) / 3)
        if rng.uniform(0, 1.3) < w:
            out.append(DAY.timestamp() + h * 3600)
    return out


def reason_class(r: str) -> str:
    if "may only query" in r:
        return "table outside role view"
    if "table functions" in r:
        return "table function"
    if "single SELECT" in r or "one statement" in r:
        return "not a single SELECT"
    return r or "other"


def main():
    rng = random.Random(20)
    raw = Path("results/raw"); raw.mkdir(parents=True, exist_ok=True)
    for f in ("audit_sim.jsonl", "audit_sim.anchor"):
        (raw / f).unlink(missing_ok=True)
    now = [DAY.timestamp()]
    log = AuditLog(raw / "audit_sim.jsonl", clock=lambda: now[0])
    rows = customers(200_000)
    con = duckdb.connect()
    from sdai.policy import load_customers
    load_customers(con, rows)
    eng = PolicyEngine(con, "policies/customers.yaml", log)
    lock_down(con)
    retr = SecureRetriever(corpus(), audit=log)
    estate = build_estate(customers(20_000, seed=8), n_notes=30_000, n_tickets=1_000)
    held = [json.loads(line) for line in Path("eval/sets/injection_heldout.jsonl").open()]
    chat_benign = o.BENIGN + [h["text"] for h in held if h["kind"] == "benign"]
    chat_attack = o.DIRECT + o.LEAK + [h["text"] for h in held if h["kind"] == "direct"]
    events = []
    for ts in arrivals(rng, 1200):
        role = rng.choice(list(ACTORS)); actor = rng.choice(ACTORS[role])
        if rng.random() < 0.04:
            sql = rng.choice(list(BYPASS.values())).format(role=role, other="dpo" if role != "dpo" else "marketing")
        else:
            sql = rng.choice(NORMAL[role]).format(cid=rng.randint(100001, 300000))
        events.append((ts, "sql", (actor, role, sql)))
    for ts in arrivals(rng, 800):
        attack = rng.random() < 0.05
        events.append((ts, "chat", (f"web-{rng.randint(1000, 9999)}", rng.choice(chat_attack if attack else chat_benign))))
    for ts in arrivals(rng, 400):
        who = rng.choice(PRINCIPALS); topic = rng.choice(list(TOPICS))
        events.append((ts, "rag", (who, f"{topic} {' '.join(rng.sample(TOPICS[topic].split(), 2))}")))
    erasure_ids = rng.sample([r["customer_id"] for r in customers(20_000, seed=8)], 4)
    for ts, cid in zip(sorted(rng.uniform(DAY.timestamp() + 3600, DAY.timestamp() + 11 * 3600) for _ in range(4)), erasure_ids):
        events.append((ts, "erasure", (cid,)))
    events.sort(key=lambda e: e[0])
    for ts, kind, args in events:
        now[0] = ts
        if kind == "sql":
            try:
                eng.query(args[1], args[2], actor=args[0])
            except (AccessDenied, duckdb.Error):
                pass
        elif kind == "chat":
            check_input(args[1], audit=log, actor=args[0])
        elif kind == "rag":
            retr.search(args[0], args[1])
        else:
            erase(estate, args[0], "dpo.aylin", log)
    ents = log.entries()
    rep = log.verify()

    def drill(name, mutate):
        p, a = raw / f"tamper_{name}.jsonl", raw / f"tamper_{name}.anchor"
        shutil.copy(log.path, p); shutil.copy(log.anchor, a)
        lines = p.read_text().splitlines(); mutate(lines); p.write_text("\n".join(lines) + "\n")
        r = verify(p, a)
        return {"detected": not r.ok, "first_bad_seq": r.first_bad_seq, "problem": r.problem}

    target = next(e["seq"] for e in ents if e["decision"] == "deny")

    def edit(lines):
        e = json.loads(lines[target - 1]); e["decision"] = "allow"; lines[target - 1] = json.dumps(e, ensure_ascii=False)

    drills = {"flip a deny to allow": drill("edit", edit),
              "delete one entry": drill("delete", lambda lines: lines.pop(target - 1)),
              "cut the last 50 entries": drill("truncate", lambda lines: lines.__delitem__(slice(-50, None)))}
    for f in ("bench.jsonl", "bench.anchor"):
        (raw / f).unlink(missing_ok=True)
    bench = AuditLog(raw / "bench.jsonl")
    t = time.perf_counter()
    for i in range(20_000):
        bench.append("bench", "dpo", "sql.query", "allow", "", {"sql": "SELECT 1", "rows": i})
    append_us = (time.perf_counter() - t) / 20_000 * 1e6
    t = time.perf_counter(); ok = bench.verify().ok; verify_s = time.perf_counter() - t
    bench.close(); bench.path.unlink(); bench.anchor.unlink()
    hour = lambda e: datetime.fromtimestamp(e["ts"], TZ).hour  # noqa: E731
    per_hour = {h: {"allow": 0, "deny": 0, "error": 0} for h in range(8, 20)}
    for e in ents:
        per_hour[min(hour(e), 19)][e["decision"]] += 1
    denied = [e for e in ents if e["decision"] == "deny"]
    out = {
        "day": "2026-11-20 (simulated clock, Europe/Istanbul)", "entries": len(ents),
        "by_action": {a: dict(Counter(e["decision"] for e in ents if e["action"] == a))
                      for a in sorted({e["action"] for e in ents})},
        "per_hour": per_hour,
        "denials_by_reason": dict(Counter(reason_class(e["reason"]) for e in denied).most_common()),
        "denials_by_role": dict(Counter(e["role"] for e in denied).most_common()),
        "denials_by_actor": dict(Counter(e["actor"] for e in denied if not e["actor"].startswith("web-")).most_common(8)),
        "recent_denied": [{"time": datetime.fromtimestamp(e["ts"], TZ).strftime("%H:%M:%S"), "seq": e["seq"], "actor": e["actor"],
                           "role": e["role"], "action": e["action"], "reason": reason_class(e["reason"]),
                           "what": (e["detail"].get("sql") or e["detail"].get("text") or "")[:90]} for e in denied[-12:]],
        "erasures": [{"time": datetime.fromtimestamp(e["ts"], TZ).strftime("%H:%M:%S"), "seq": e["seq"],
                      "subject_ref": e["detail"]["subject_ref"], "decision": e["decision"],
                      "rows_deleted": sum(v for k, v in e["detail"]["actions"].items() if k.endswith(".deleted")),
                      "notes_redacted": e["detail"]["actions"]["care.call_notes.redacted"],
                      "rag_docs_removed": e["detail"]["actions"]["rag.documents.removed"],
                      "retained_rows": e["detail"]["retained_rows"], "review": e["detail"]["review"]}
                     for e in ents if e["action"] == "kvkk.erasure"],
        "chain": {"verified": rep.ok, "entries": rep.entries, "head": ents[-1]["hash"][:16]},
        "tamper_drills": drills,
        "throughput": {"append_us_per_entry": round(append_us, 1), "verify_20k_s": round(verify_s, 3), "verify_ok": ok},
    }
    Path("results/audit_sim.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(json.dumps({k: out[k] for k in ("entries", "by_action", "denials_by_reason", "chain", "tamper_drills", "throughput")}, indent=1))


if __name__ == "__main__":
    main()
