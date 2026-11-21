# 0003. RAG: mask at ingest, filter before ranking; LLM guardrails are deterministic

- Status: Accepted
- Date: 2026-11-21

## Decision

- **Mask PII at ingest**, not at answer time. The index never holds identifiers, so no retrieval bug or
  prompt can expose them. Pseudonyms (HMAC) keep tickets about the same customer linkable.
- **Filter by ACL before ranking.** Post-filtering top-k avoids leaks too, but measured on 300
  queries it left the Istanbul desk with 0.32 of 5 results; pre-filtering returned 4.06 of 5.
- **Guardrails are deterministic and pattern-based**, one control per OWASP LLM Top 10 (2025) risk,
  each with a unit test. They are measured against a real model, including the attacks they miss.

## Evidence

| Risk | Baseline | Guarded |
|---|---|---|
| LLM01 direct injection | 7/10 succeeded | 4/10 (all paraphrases without trigger phrases) |
| LLM01 indirect (poisoned document) | 0/8 | 0/8 |
| LLM02 PII disclosure | 6/8 | 0/8 |
| LLM07 system prompt leak | 2/8 | 0/8 |
| Benign questions blocked | 0/10 | 0/10 |

## Consequences

- Patterns do not stop paraphrased injections. Production needs a trained classifier (for example
  Llama Guard or Prompt Guard) in addition, and should treat these patterns as a first layer.
- The model never followed the `[ID]` citation format, so the LLM09 grounding check would refuse
  every answer. A larger model or constrained output is needed before enabling it.
