# 0006. KVKK erasure: find every copy, delete or redact, keep what the law requires, prove it with a scan

- Status: Accepted
- Date: 2026-11-21

## Context

KVKK (Law No. 6698) article 7 and the Regulation on the Erasure, Destruction or Anonymisation of Personal Data
require deletion when the purpose ends or the person asks (article 11), unless another legal basis applies.
In this repository a customer's data ends up in six places: the CRM table, call-centre notes (including notes
filed under other customers), an analytics snapshot (CREATE TABLE AS), a marketing export, invoices, and the
RAG index, where PII is pseudonymised but still personal data.

## Decision

- `sdai/erasure.py` erases one subject per request in a transaction: delete the CRM row, the subject's own
  notes, the analytics and marketing copies; **redact** the subject's identifiers in other customers' notes
  instead of deleting those notes; remove the subject's RAG documents through a keyed subject index built at
  ingest, then rebuild the BM25 index.
- **Invoices are kept** (legal retention, e.g. Turkish Commercial Code art. 82, 10 years); the receipt lists
  them with the date they become erasable. The period is configuration, not legal advice.
- **Shared identifiers are not used for matching.** If an identifier also belongs to another customer record,
  matching on it would erase someone else's data; it is left out and listed for manual review.
- Each request ends with a residual scan of every store (identifiers as written, digits only, and pseudonyms)
  and a receipt that names the subject by keyed hash; the same summary goes to the audit log.

## Evidence (`results/erasure_eval.json`)

- 50 requests over 200,000 customers, 300,000 notes, 400,000 invoices and 5,000 RAG tickets (25 subjects with
  tickets): 50/50 erased, 0 residual rows outside the 100 retained invoice rows; 86 notes deleted, 5 redacted,
  25 RAG documents removed.
- Fingerprints (row count + XOR of row hashes) of every other customer's rows are unchanged in all five tables.
- p50 108 ms, p95 125 ms per request. Repeating a request or asking for an unknown id returns `not_found`.
- 22 of 50 subjects share their e-mail with another synthetic customer (the generator draws from 479,520
  combinations for 200,000 people), so e-mail was excluded from matching for them and flagged for review.
- The first version scanned free text with a regex per row and took about 8 s per request; a digits-only shadow
  column on the notes brought it to about 0.1 s.

## Consequences

- Out of scope and stated in the README: backups and replicas, the model server's KV cache and prompt logs,
  logs outside this estate, and storage-level residue (a byte search of a DuckDB file finds nothing even before
  deletion because strings are compressed, so it proves nothing either way).
- The audit log keeps entries that mention the subject's customer id in SQL text.
