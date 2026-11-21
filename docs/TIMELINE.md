# Build timeline

Build log of masterfabric-secure-data-ai: KVKK PII masking, Ranger-style policies, secure RAG retrieval and OWASP LLM tests on synthetic data.

Every step below is one commit, in order. Times are Europe/Istanbul (UTC+3).

| # | Commit | Time | Change |
|---|---|---|---|
| 1 | `35ac35b` | 2026-11-21 04:47 | chore: scaffold repository with AGPL-3.0 license and community files |
| 2 | `c915543` | 2026-11-21 04:49 | feat(synth): synthetic Turkish customers with checksum-valid identifiers |
| 3 | `b5f3f12` | 2026-11-21 04:49 | feat(pii): KVKK PII detectors with checksum validation and three masking modes |
| 4 | `e76f6a9` | 2026-11-21 04:49 | feat(eval): PII detector precision and recall on 2,000 labelled notes |
| 5 | `39a74f8` | 2026-11-21 04:52 | feat(policy): Ranger-style column masks and row filters for five roles |
| 6 | `f6fa03f` | 2026-11-21 04:52 | feat(policy): DuckDB secure views, query checks and audit log |
| 7 | `350daf1` | 2026-11-21 04:52 | test: PII checksums, masking, column masks, row filters and bypass attempts |
| 8 | `72d3918` | 2026-11-21 04:52 | feat(eval): policy results on 200,000 synthetic customers |
| 9 | `392b377` | 2026-11-21 04:53 | fix(pii): letter-only pseudonyms so masked text never re-detects as PII |
| 10 | `d4788f6` | 2026-11-21 04:53 | feat(rag): permission-aware BM25 retrieval with PII masked at ingest |
| 11 | `ec35a73` | 2026-11-21 04:53 | feat(eval): RAG leakage with no filter, post-filter and pre-filter |
| 12 | `022353c` | 2026-11-21 04:54 | feat(guard): guardrails mapped to the OWASP Top 10 for LLM Applications 2025 |
| 13 | `bc1af98` | 2026-11-21 04:54 | test: one deterministic test per OWASP LLM risk covered by the guards |
| 14 | `3b106a8` | 2026-11-21 04:55 | feat(eval): OWASP LLM01/02/07 attacks against a real local model |
| 15 | `9d34dfc` | 2026-11-21 04:56 | docs: charts for PII precision, RAG leakage, OWASP attacks and role views |
| 16 | `6aea98e` | 2026-11-21 04:57 | docs: architecture diagram of the data-to-model controls |
| 17 | `89229a0` | 2026-11-21 04:57 | docs: 1600x900 hero from the measured results |
| 18 | `527f1b2` | 2026-11-21 04:58 | fix(pii): partial masks keep four characters, not four positions |
| 19 | `113b9d3` | 2026-11-21 04:58 | docs(adr): 0001 synthetic personal data only |
| 20 | `ab9f724` | 2026-11-21 04:58 | docs(adr): 0002 policy enforcement with secure views and a query check |
| 21 | `2ee2e2f` | 2026-11-21 04:58 | docs(adr): 0003 RAG masking and filtering, deterministic guardrails, and index |
| 22 | `57af958` | 2026-11-21 04:59 | build: pinned Python requirements |
| 23 | `d0fdbd2` | 2026-11-21 04:59 | build: Makefile with evaluation targets and a hash-pinned model server |
| 24 | `d2c0d67` | 2026-11-21 04:59 | docs: CONTRIBUTING with synthetic-data and measured-results rules |
| 25 | `d6d02b7` | 2026-11-21 05:00 | docs: full README with results, figures, OWASP mapping and limitations |

The final commit adds this file and the README; see `git log` for the full messages, which explain
the why of each step (including the fixes found by running the system).
