# 0005. Audit log: append-only JSON lines with a SHA-256 hash chain and an anchor

- Status: Accepted
- Date: 2026-11-21
- Amends: [0002](0002-policy-enforcement.md) (plain JSON-lines audit file)

## Context

The policy engine wrote one plain JSON line per query, with the raw SQL. Anyone with write access could edit or
delete a line without trace, and SQL with a national ID in a WHERE clause put that ID into the log. The guard,
the retriever and the new erasure service wrote nothing.

## Decision

- One `AuditLog` (`sdai/audit.py`) for all components: policy queries, guard input decisions, RAG searches,
  erasure requests.
- Each entry carries `seq`, `prev` (hash of the previous entry) and `hash` (SHA-256 of its own fields).
  `verify()` reports the first entry where the content, the link or the sequence is wrong.
- The head (`seq`, `hash`) is also written to an anchor file, because cutting entries off the end leaves a valid
  chain. In production the anchor goes somewhere the writer cannot rewrite (object lock, another team's system).
- Free text is PII-masked (`mask_text`) before it is written; erasure entries carry a keyed subject reference only.
- Engine errors are logged as `error` with the exception type, not its message, which can echo literals.

## Evidence

- Simulated day (`results/audit_sim.json`): 2,404 entries from the real components, chain verified.
- Tamper drills on copies: flipping a deny to allow, deleting one entry and cutting the last 50 entries are all
  detected (the last one only through the anchor).
- Append cost 25.8 µs per entry, verify 20,000 entries in 0.094 s. The first version opened the file for each
  entry and took 2.45 ms per append on the test Mac; handles now stay open.

## Consequences

- Tamper-evident, not tamper-proof: whoever can write both files can rebuild the chain. Signing the anchor or
  shipping it off-host is the next step and is not implemented.
- Entries are flushed but not fsync'ed; a power cut can lose the last few.
- Customer ids in SQL text are not masked (they are not PII patterns), so the log still links queries to a
  customer number. The erasure service does not rewrite the audit log; keeping it is a security record.
