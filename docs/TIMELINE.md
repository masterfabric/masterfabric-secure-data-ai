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


## Addition: second injection layer, hash-chained audit log and dashboard, KVKK erasure (2026-11-21)

Started from `b0b1740`. The held-out injection set was committed first, before the second layer existed.
Times are Europe/Istanbul.

| # | Commit | Time | Change |
|---|---|---|---|
| 1 | `545a102` | 2026-11-21 13:15 | eval: held-out injection set (12 direct, 8 indirect, 12 hard benign), fixed before the second layer is built |
| 2 | `3d1562f` | 2026-11-21 13:18 | guard: second injection layer, Granite Guardian classifier on questions and retrieved documents (fails closed) |
| 3 | `e7982cd` | 2026-11-21 13:18 | eval: guard v1 vs v2 on dev and held-out injection sets; Makefile guard-up/guard-down/injection |
| 4 | `c795ce7` | 2026-11-21 13:18 | results: held-out direct injections 7/12 (rules) -> 1/12 (rules + classifier), 2/12 hard-benign blocked |
| 5 | `87ddaa5` | 2026-11-21 13:20 | audit: hash-chained append-only log with anchor file, PII-masked fields, verify() and tests |
| 6 | `a665c12` | 2026-11-21 13:20 | policy: write every query attempt to the hash-chained audit log, engine errors included |
| 7 | `0e8c549` | 2026-11-21 13:20 | eval: policy audit now reports chain verification (60 entries, 50 denied, chain intact) |
| 8 | `1e27b96` | 2026-11-21 13:27 | erasure: KVKK right-to-erasure across CRM, notes, derived copies, marketing export and the RAG index, with receipts |
| 9 | `33bb14b` | 2026-11-21 13:27 | eval: erasure on 200,000 customers with negative control, untouched-row fingerprints and shared-identifier review |
| 10 | `1790022` | 2026-11-21 13:27 | results: 50 erasures, 0 residual rows outside retained invoices, p50 108 ms; 22 subjects share an e-mail with another customer |
| 11 | `c93518a` | 2026-11-21 13:28 | audit: guard input decisions and RAG searches can be written to the same chained log |
| 12 | `267436d` | 2026-11-21 13:30 | audit: keep the log and anchor open; append drops from 2.45 ms to 26 us on the test Mac |
| 13 | `07106f3` | 2026-11-21 13:30 | eval: simulated day of 2,404 audit entries from policy, guard, RAG and erasure; 3 of 3 tamper drills detected |
| 14 | `f82836e` | 2026-11-21 13:32 | deps: playwright as a dev-only requirement; NOTICE lists Granite Guardian and Playwright (both Apache-2.0) |
| 15 | `4fb5bfb` | 2026-11-21 13:32 | dashboard: self-contained audit log dashboard (inline SVG, no JavaScript) built from the simulated day |
| 16 | `26fc665` | 2026-11-21 13:32 | docs: audit dashboard screenshot |
| 17 | `a458527` | 2026-11-21 13:33 | charts: injection layers (attacks and false blocks) and erasure (found vs left per store) |
| 18 | `1f99cff` | 2026-11-21 13:33 | diagram: architecture with classifier layer, audit log and erasure service |
| 19 | `82e23ba` | 2026-11-21 13:33 | charts: role views regenerated from the re-run policy evaluation (hash salt is per run) |
| 20 | `286a8c3` | 2026-11-21 13:34 | docs: ADRs 0004-0006 (classifier layer, hash-chained audit log, KVKK erasure) |
| 21 | `7cc85e2` | 2026-11-21 13:35 | README: sections 5-7 (classifier layer, audit log and dashboard, KVKK erasure), key results, figures 6-8, limitations |
| 22 | `d3e08cb` | 2026-11-21 13:36 | hero: erasure and held-out injection numbers read from results |
| 23 | (this commit) | | docs(timeline): this section |

### Verification (measured on the M4 Pro)

| Check | Result |
|---|---|
| Model files | Qwen2.5-1.5B and Granite Guardian 3.2 3B-A800M sha256 checked by `make llm-up` / `guard-up` before serving |
| Known-answer detection (rejected) | dev: 1/10 direct, 1/8 poisoned documents flagged |
| Direct injection, dev | 7/10 (no guard) → 4/10 (rules) → 0/10 (rules + classifier) |
| Direct injection, held-out | 7/12 → 7/12 → 1/12 |
| Legitimate questions blocked | 0/10 and 0/12 with rules; 1/10 and 2/12 with the classifier |
| Poisoned documents dropped | 16/16; clean documents 0/2 |
| Latency | classifier call p50 71 ms, p95 75 ms; end to end p50 115 ms (v1) vs 166 ms (v2) |
| Policy audit | 60 entries, 50 denied, chain verified |
| Simulated audit day | 2,404 entries, 65 denied, chain verified; 3/3 tamper drills detected (truncation only via the anchor) |
| Audit cost | 25.8 µs per append, verify 20,000 entries in 0.094 s |
| Erasure, 50 of 200,000 customers | 50/50 erased, 0 residual outside 100 retained invoice rows, other rows unchanged in 5 tables, p50 108 ms / p95 125 ms |
| Unit tests | 43 passed |
| Machine state | both llama-servers stopped at the end; Colima and k3d not used; ports 3000, 8081, 11234 not touched |

### Found while running it

- Known-answer detection does not work with a 1.5B answering model: it repeats the key and ignores the
  injected text, so the probe fired on 1 of 10 attacks.
- The rule layer caught none of the 12 held-out direct attacks. All of the improvement comes from the classifier.
- The classifier sees the pseudonymised question, not the raw one; one development benign question with a
  national ID scored 0.58 on that form and was blocked, although the threshold had been picked on raw text.
- The audit log first opened its file for every entry: 2.45 ms per append, almost all of it in `open()`.
  Keeping the handles open: 25.8 µs.
- 22 of 50 erasure subjects share their e-mail with another synthetic customer. The first erasure run flagged
  70 "residual" rows that belonged to those other people; identifiers shared by several customers are now left
  out of matching and sent to review.
- Scanning free text with a regex per row made each erasure take about 8 s; a digits-only shadow column on the
  notes brought it to about 0.1 s.
- A byte search of a DuckDB file found none of 50 e-mails even before deletion (compressed strings), so it
  cannot serve as an erasure check either way.
- Re-running the policy evaluation changes the hashed values in the role-view figure, because the hash salt is
  random per run unless `SDAI_HASH_SALT` is set.


## Addition: clarify instead of block, guard v3 (2026-11-23)

Started from `30bf75f`. The fresh held-out set was committed first, before `sdai/clarify.py` existed; the
earlier development and held-out v1 sets were the development data for v3. Times are Europe/Istanbul.

| # | Commit | Time | Change |
|---|---|---|---|
| 1 | `54449dd` | 2026-11-23 12:29 | eval: fresh held-out set for the clarify flow (12 direct attacks, 12 format-style legitimate questions), committed before the flow exists |
| 2 | `d87783a` | 2026-11-23 12:31 | guard v3: clarify instead of block for classifier-flagged input (rewrite, re-check, confirm); 6 unit tests |
| 3 | `9883656` | 2026-11-23 12:31 | eval: guard v2 vs v3 on dev, held-out v1 and held-out v2 (user confirms every clarification) |
| 4 | `e0fc469` | 2026-11-23 12:34 | results: guard v3 clarify flow; false blocks 6/34 -> 1/34, attack success unchanged (v2 = v3 in both runs) |
| 5 | `10f17b5` | 2026-11-23 12:35 | docs: ADR 0007 clarify instead of block; Makefile clarify target |
| 6 | `61d1acc` | 2026-11-23 12:35 | charts: clarify flow (false blocks and attack success, v2 vs v3) and every flagged question with its rewrite |
| 7 | `b8e0267` | 2026-11-23 12:35 | ADR 0007 and chart: describe the three clarified attacks exactly |
| 8 | `50e7517` | 2026-11-23 12:36 | README: guard v3 clarify flow (figures 7-8, later figures +2), key results, ADR 0007, limitations, 49 tests |
| 9 | (this commit) | | docs(timeline): this section |

### Verification (measured on the M4 Pro)

| Check | Result |
|---|---|
| Model files | Qwen2.5-1.5B and Granite Guardian 3.2 3B-A800M sha256 checked by `make llm-up` / `guard-up` |
| Legitimate questions blocked, v2 → v3 | dev 1/10 → 1/10; held-out v1 2/12 → 0/12; **fresh held-out v2 3/12 → 0/12** |
| Attacks shown PWNED, v2 → v3 | dev 0/10 → 0/10; held-out v1 1/12 → 1/12; held-out v2 3/12 → 3/12 |
| Attacks that reached a clarification | 3 (all rewrites free of the instruction, none showed PWNED) |
| Latency | clarified path p50 753 ms; directly answered p50 368 ms |
| Repeatability | two full runs: identical guard decisions; answer text differed in 9 of 136 outputs; held-out v2 attack success 2/12 (run 1, `results/clarify_eval_run1.json`) and 3/12 (run 2) |
| Unit tests | 49 passed (6 new for the clarify flow) |
| Machine state | both llama-servers stopped after the run; ports 3000, 8081, 11234 not touched |

### Found while running it

- No threshold could have fixed the false blocks: legitimate questions scored 0.58-0.77 and caught attacks
  0.55-0.83 on the same classifier.
- The first run's "served" metric (citation check) was 0 for every answer in both pipelines, because the 1.5B
  model never writes `[KB01]` citations inside the wrapped context (the same holds in `injection_l2.json`). It
  was replaced by "not blocked" and the clarified answers are shown in Figure 8. The run was repeated with the
  new metric; the first run is kept as `results/clarify_eval_run1.json`.
- The echo check for capitalised code words also fires on the PII masking tag `<TCKN:…>`, which keeps the
  development ID question blocked. Left as found (ADR 0007).
- The repository's `.venv` had been deleted by a disk clean-up outside this work while it ran; the evaluation
  used a fresh virtual environment with the pinned requirements under `/tmp`, removed afterwards.
