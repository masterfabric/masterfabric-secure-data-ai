"""Architecture diagram (Pillow)."""
from mfviz import GREEN, GREY, ICE, IMG, ORANGE, PURPLE, RED, WHITE, YELLOW, arrow, box, canvas, font


def architecture():
    im, d = canvas(1600, 900)
    d.text((60, 40), "MasterFabric Secure Data AI · controls on the path from data to model", font=font(34, 800), fill=WHITE)
    d.text((60, 88), "Synthetic Turkish customer data only. Every control has a test and a measured result.", font=font(20, 450), fill=GREY)
    box(d, (50, 170, 360, 400), "Synthetic data", ["customers: TCKN, IBAN,", "card, phone, e-mail", "call-centre notes", "tickets + help articles"], GREY, line_size=18)
    box(d, (430, 150, 790, 420), "PII detection (KVKK)", ["pattern + checksum", "TCKN · IBAN mod-97 · Luhn", "redact · partial · HMAC", "precision 0.986, recall 1.0"], GREEN, line_size=18)
    box(d, (960, 150, 1550, 420), "Policy engine (Ranger-style)", ["DuckDB secure view per role", "column masks, default deny", "row filters: consent, region", "SQL checked before execution",
                                                                   "audit log of every attempt"], ORANGE, line_size=18)
    box(d, (430, 500, 790, 790), "Secure RAG retrieval", ["PII pseudonymised at ingest", "ACL: clearance, tenant, region", "filter BEFORE ranking (BM25)", "0 unauthorised chunks"], PURPLE, line_size=18)
    box(d, (960, 500, 1550, 790), "LLM guardrails (OWASP 2025)", ["input: injection, length, PII", "context: sanitise + fence docs", "output: canary, PII, HTML escape",
                                                                  "tools: role scope, human approval", "model hash pin, rate limit"], RED, line_size=18)
    box(d, (50, 520, 360, 720), "Local model", ["Qwen2.5-1.5B Q4_K_M", "llama.cpp, Metal", "127.0.0.1:61080"], ICE, line_size=18)
    arrow(d, (360, 285), (430, 285), GREY)
    arrow(d, (790, 285), (960, 285), GREEN, "mask rules")
    arrow(d, (610, 420), (610, 500), GREEN, "masked text")
    arrow(d, (790, 645), (960, 645), PURPLE, "allowed chunks")
    d.line([(1255, 790), (1255, 840), (205, 840)], fill=RED, width=3)
    arrow(d, (205, 840), (205, 720), RED)
    d.text((560, 812), "guarded prompt and answer", font=font(16, 600), fill=RED)
    d.text((800, 862), "Analysts query DuckDB views; assistants go through retrieval and guardrails.", font=font(18, 500), fill=YELLOW)
    im.save(IMG / "architecture.png", optimize=True)


if __name__ == "__main__":
    architecture()
    print("diagram written")
