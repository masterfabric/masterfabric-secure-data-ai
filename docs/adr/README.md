# Architecture decision records

| # | Decision |
|---|---|
| [0001](0001-synthetic-data-only.md) | Synthetic personal data only, with checksum-valid identifiers |
| [0002](0002-policy-enforcement.md) | Enforce column and row policies with secure views and a query check |
| [0003](0003-rag-and-llm-guardrails.md) | RAG: mask at ingest, filter before ranking; deterministic LLM guardrails |
| [0004](0004-second-injection-layer.md) | Second prompt-injection layer: Granite Guardian classifier after the rules |
| [0005](0005-hash-chained-audit-log.md) | Audit log: SHA-256 hash chain, anchor file, PII masked before writing |
| [0006](0006-kvkk-erasure.md) | KVKK erasure across all stores, legal hold for invoices, residual scan and receipt |
| [0007](0007-clarify-instead-of-block.md) | Clarify instead of block: rewrite flagged input, re-check, answer only the confirmed rewrite |
