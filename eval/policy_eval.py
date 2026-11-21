"""Policy engine evaluation: what each role sees, bypass attempts, and the cost of masking views."""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sdai.policy import AccessDenied, PolicyEngine, load_customers, lock_down  # noqa: E402
from sdai.synth import customers  # noqa: E402

BYPASS = {
    "raw table": "SELECT * FROM crm.customers",
    "unqualified name": "SELECT * FROM customers",
    "another role's view": "SELECT * FROM {other}.customers",
    "file read": "SELECT * FROM read_csv('/etc/hosts')",
    "file replacement scan": "SELECT * FROM '/etc/hosts'",
    "catalog / view SQL": "SELECT sql FROM duckdb_views()",
    "subquery on raw": "SELECT count(*) FROM {role}.customers WHERE customer_id IN (SELECT customer_id FROM crm.customers)",
    "stacked statement": "SELECT 1; DROP TABLE crm.customers",
    "config change": "SET lock_configuration = false",
    "DDL": "CREATE TABLE x AS SELECT * FROM crm.customers",
}


def timed(fn, n=7):
    ts = []
    for _ in range(n):
        t = time.perf_counter(); fn(); ts.append(time.perf_counter() - t)
    return statistics.median(ts)


def main():
    n = 200_000
    con = duckdb.connect()
    t = time.perf_counter(); load_customers(con, customers(n)); load_s = time.perf_counter() - t
    audit = Path("results/raw/audit.jsonl"); audit.parent.mkdir(parents=True, exist_ok=True); audit.unlink(missing_ok=True)
    audit.with_suffix(".anchor").unlink(missing_ok=True)
    eng = PolicyEngine(con, "policies/customers.yaml", audit)
    lock_down(con)
    roles = list(eng.policy["roles"])
    total = con.execute("SELECT count(*) FROM crm.customers").fetchone()[0]
    out = {"rows": total, "load_s": round(load_s, 2), "roles": {}, "bypass": {}, "overhead": {}}
    for r in roles:
        cnt = eng.query(r, f"SELECT count(*) FROM {r}.customers")[0][0]
        sample = eng.query(r, f"SELECT * FROM {r}.customers ORDER BY customer_id LIMIT 2")
        out["roles"][r] = {"columns": eng.visible_columns(r), "rows_visible": cnt,
                           "sample": [[str(v) for v in row] for row in sample]}
    for name, sql in BYPASS.items():
        res = {}
        for r in roles:
            try:
                eng.query(r, sql.format(role=r, other='marketing' if r == 'dpo' else 'dpo')); res[r] = "ALLOWED"
            except AccessDenied:
                res[r] = "denied"
            except duckdb.Error as e:
                res[r] = "error: " + type(e).__name__
        out["bypass"][name] = res
    agg = "SELECT city, segment, count(*) FROM {t} GROUP BY ALL"
    full = "SELECT * FROM {t}"
    for r in ("dpo", "data_scientist", "marketing"):
        out["overhead"][r] = {
            "aggregate_raw_ms": round(timed(lambda: con.execute(agg.format(t="crm.customers")).fetchall()) * 1000, 1),
            "aggregate_view_ms": round(timed(lambda: con.execute(agg.format(t=f"{r}.customers")).fetchall()) * 1000, 1),
            "full_scan_raw_ms": round(timed(lambda: con.execute(full.format(t="crm.customers")).fetchall(), 3) * 1000, 1),
            "full_scan_view_ms": round(timed(lambda: con.execute(full.format(t=f"{r}.customers")).fetchall(), 3) * 1000, 1),
        }
    ents = eng.audit.entries()
    rep = eng.audit.verify()
    out["audit"] = {"entries": len(ents), "denied": sum(e["decision"] == "deny" for e in ents),
                    "engine_errors": sum(e["decision"] == "error" for e in ents), "chain_verified": rep.ok}
    Path("results/policy_eval.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(json.dumps({k: v for k, v in out.items() if k != "roles"}, indent=1)[:2500])
    for r, v in out["roles"].items():
        print(r, v["rows_visible"], v["columns"])


if __name__ == "__main__":
    main()
