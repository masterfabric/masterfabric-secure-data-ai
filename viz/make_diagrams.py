"""Architecture diagram (Pillow)."""
from mfviz import GREEN, GREY, ICE, IMG, ORANGE, PURPLE, RED, WHITE, YELLOW, arrow, box, canvas, font


def architecture():
    im, d = canvas(1600, 1130)
    d.text((60, 40), "MasterFabric Secure Data AI · controls on the path from data to model", font=font(34, 800), fill=WHITE)
    d.text((60, 88), "Synthetic Turkish customer data only. Every control has a test and a measured result.", font=font(20, 450), fill=GREY)
    box(d, (50, 170, 360, 400), "Synthetic data", ["customers: TCKN, IBAN,", "card, phone, e-mail", "call-centre notes", "tickets + help articles"], GREY, line_size=18)
    box(d, (430, 150, 790, 420), "PII detection (KVKK)", ["pattern + checksum", "TCKN · IBAN mod-97 · Luhn", "redact · partial · HMAC", "precision 0.986, recall 1.0"], GREEN, line_size=18)
    box(d, (960, 150, 1550, 420), "Policy engine (Ranger-style)", ["DuckDB secure view per role", "column masks, default deny", "row filters: consent, region", "SQL checked before execution",
                                                                   "every attempt to the audit log"], ORANGE, line_size=18)
    box(d, (430, 500, 790, 790), "Secure RAG retrieval", ["PII pseudonymised at ingest", "ACL: clearance, tenant, region", "filter BEFORE ranking (BM25)", "0 unauthorised chunks"], PURPLE, line_size=18)
    box(d, (960, 500, 1550, 790), "LLM guardrails (OWASP 2025)", ["input: rules, then classifier", "docs: classifier drops poisoned", "output: canary, PII, HTML escape",
                                                                  "tools: role scope, human approval", "model hash pins, rate limit"], RED, line_size=18)
    box(d, (50, 500, 360, 790), "Local models", ["Qwen2.5-1.5B (answers)", "  127.0.0.1:61080", "Granite Guardian 3.2", "  3B-A800M (classifier)", "  127.0.0.1:61081"], ICE, line_size=18)
    box(d, (430, 900, 790, 1090), "KVKK erasure service", ["CRM, notes, copies, RAG index", "residual scan + receipt", "invoices kept: legal hold"], GREEN, line_size=18)
    box(d, (960, 900, 1550, 1090), "Audit log (SHA-256 hash chain)", ["policy, guard, RAG, erasure entries", "PII-masked before writing",
                                                                      "anchor file catches tail cuts"], YELLOW, line_size=18)
    arrow(d, (790, 995), (960, 995), GREEN, "receipt")
    arrow(d, (360, 285), (430, 285), GREY)
    arrow(d, (790, 285), (960, 285), GREEN, "mask rules")
    arrow(d, (610, 420), (610, 500), GREEN, "masked text")
    arrow(d, (790, 645), (960, 645), PURPLE, "allowed chunks")
    d.line([(1100, 790), (1100, 840), (205, 840)], fill=RED, width=3)
    arrow(d, (205, 840), (205, 790), RED)
    d.text((560, 812), "guarded prompt and answer", font=font(16, 600), fill=RED)
    arrow(d, (1400, 790), (1400, 900), YELLOW, "decisions")
    d.text((60, 1100), "Analysts query DuckDB views; assistants go through retrieval and guardrails; the DPO runs erasure.", font=font(18, 500), fill=YELLOW)
    im.save(IMG / "architecture.png", optimize=True)


if __name__ == "__main__":
    architecture()
    print("diagram written")
