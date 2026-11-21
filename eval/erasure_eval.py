"""KVKK erasure on 200,000 synthetic customers: 50 requests, then check that nothing of the 50 subjects is
left outside the retained invoices and that no other customer's data changed.

Stores: crm.customers (200k), care.call_notes (300k, 5% mention a second customer), billing.invoices (400k,
retained), analytics.customer_snapshot (200k), marketing.contact_list (consenting customers) and a RAG index
of 5,000 tickets. Half of the subjects are chosen among customers who have tickets, so the RAG path is used.
"""
from __future__ import annotations

import json
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sdai.audit import AuditLog  # noqa: E402
from sdai.erasure import _note_match, build_estate, erase, identifiers, scan, shared_identifiers  # noqa: E402
from sdai.synth import customers  # noqa: E402

TABLES = {"crm.customers": "customer_id", "care.call_notes": "note_id", "billing.invoices": "invoice_id",
          "analytics.customer_snapshot": "customer_id", "marketing.contact_list": "customer_id"}


def fingerprint(con, table, exclude_customers, exclude_notes):
    cols = [r[0] for r in con.execute(f"DESCRIBE {table}").fetchall()]
    where = []
    if table != "billing.invoices":  # invoices are retained, so every row must be unchanged
        where.append(f"customer_id NOT IN ({','.join(map(str, exclude_customers))})")
    if table == "care.call_notes" and exclude_notes:
        where.append(f"note_id NOT IN ({','.join(map(str, exclude_notes))})")
    w = (" WHERE " + " AND ".join(where)) if where else ""
    n, h = con.execute(f"SELECT count(*), bit_xor(hash({', '.join(cols)})) FROM {table}{w}").fetchone()
    return n, str(h)


def main():
    rows = customers(200_000)
    t = time.perf_counter(); est = build_estate(rows); build_s = time.perf_counter() - t
    rng = random.Random(42)
    keyed = {est.subject_key(r["customer_id"]): r["customer_id"] for r in rows}
    holders = sorted(keyed[k] for k in est.subject_index)
    with_tickets = rng.sample(holders, 25)
    others = rng.sample([r["customer_id"] for r in rows if r["customer_id"] not in set(holders)], 25)
    subjects = with_tickets + others
    full_ids = {s: identifiers(est, s) for s in subjects}
    shared = {s: shared_identifiers(est, s, full_ids[s]) for s in subjects}
    ids = {s: {k: v for k, v in full_ids[s].items() if k not in shared[s]} for s in subjects}
    redacted_notes = set()
    for s in subjects:
        cond, params = _note_match(ids[s])
        redacted_notes |= {r[0] for r in est.con.execute(
            f"SELECT note_id FROM care.call_notes WHERE customer_id <> ? AND {cond}", [s] + params).fetchall()}
    before_fp = {t_: fingerprint(est.con, t_, subjects, redacted_notes) for t_ in TABLES}
    before_scan = {s: scan(est, s, ids[s]) for s in subjects}
    raw = Path("results/raw"); raw.mkdir(parents=True, exist_ok=True)
    for f in ("erasure_audit.jsonl", "erasure_audit.anchor"):
        (raw / f).unlink(missing_ok=True)
    audit = AuditLog(raw / "erasure_audit.jsonl")
    receipts = [erase(est, s, "dpo-desk", audit) for s in subjects]
    after_fp = {t_: fingerprint(est.con, t_, subjects, redacted_notes) for t_ in TABLES}
    repeat = erase(est, subjects[0], "dpo-desk", audit)
    unknown = erase(est, 999_999, "dpo-desk", audit)
    log_text = audit.path.read_text()
    leaked_into_log = sum(v in log_text for s in subjects for v in full_ids[s].values())
    ms = sorted(r["elapsed_ms"] for r in receipts)
    found = {k: sum(b[k] for b in before_scan.values()) for k in next(iter(before_scan.values()))}
    acts = {k: sum(r["actions"][k] for r in receipts) for k in receipts[0]["actions"]}
    out = {
        "customers": len(rows), "estate_build_s": round(build_s, 1), "requests": len(subjects),
        "subjects_with_rag_tickets": len(with_tickets),
        "found_before_total": found,
        "negative_control_every_subject_found_in_crm": all(b["crm.customers"] >= 1 for b in before_scan.values()),
        "actions_total": acts,
        "subjects_with_shared_identifiers": sum(bool(v) for v in shared.values()),
        "shared_identifier_kinds": {k: sum(k in v for v in shared.values()) for k in ("tckn", "phone", "email", "iban", "card_number")},
        "retained_invoice_rows": sum(r["retained"]["billing.invoices"]["rows"] for r in receipts),
        "status_counts": {s: sum(r["status"] == s for r in receipts) for s in ("erased", "incomplete")},
        "residual_outside_retention_total": sum(sum(r["residual_outside_retention"].values()) for r in receipts),
        "untouched_rows_unchanged": {t_: before_fp[t_] == after_fp[t_] for t_ in TABLES},
        "untouched_rows_counted": {t_: after_fp[t_][0] for t_ in TABLES},
        "repeat_request_status": repeat["status"], "unknown_subject_status": unknown["status"],
        "audit": {"entries": len(audit.entries()), "chain_verified": audit.verify().ok,
                  "raw_identifiers_in_log": leaked_into_log},
        "latency_ms": {"p50": round(statistics.median(ms), 1), "p95": round(ms[int(0.95 * (len(ms) - 1))], 1),
                       "max": ms[-1]},
    }
    Path("results/erasure_eval.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
    ex = next(r for r in receipts if r["actions"]["rag.documents.removed"] and r["actions"]["care.call_notes.redacted"]) \
        if any(r["actions"]["rag.documents.removed"] and r["actions"]["care.call_notes.redacted"] for r in receipts) \
        else next(r for r in receipts if r["actions"]["rag.documents.removed"])
    Path("results/erasure_receipt_example.json").write_text(json.dumps(ex, indent=2, ensure_ascii=False))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
