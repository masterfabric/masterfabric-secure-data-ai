# 0002. Enforce column and row policies with secure views and a query check

- Status: Accepted
- Date: 2026-11-21

## Context

Apache Ranger (Cloudera SDX) enforces column masking and row filtering inside Hive/Impala, and
audits every access. This lab needs the same behaviour on a laptop, without a Hadoop stack.

## Options

1. Materialise a masked copy per role. Simple, but copies multiply and go stale.
2. **Secure views per role plus a pre-execution check.** One copy of the data; masks and filters
   are applied at query time, like Ranger.
3. Rewrite every user query. Powerful, but a custom SQL rewriter is a large attack surface.

## Decision

Option 2 on DuckDB:

- A YAML policy lists, per role, the visible columns with a mask each (default deny) and an optional
  row filter. One view per role is generated from it.
- Before execution, the SQL is parsed by DuckDB (`json_serialize_sql`). Only a single SELECT is
  accepted, with no table functions, and every referenced table must be the role's own view.
- External file access and configuration are locked after loading.
- The pseudonymisation key lives in a Python UDF, so a view definition never contains it.
- Every attempt, allowed or denied, goes to an audit log.

## Consequences

- 10 bypass patterns × 5 roles: 0 allowed (results/policy_eval.json).
- Masks cost nothing on aggregates; HMAC pseudonyms make full scans ~2.7× slower.
- In production, Ranger or Unity Catalog does this inside the engine. This code shows the policy model,
  not a replacement for an in-engine enforcement point.
