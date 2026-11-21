"""Compose docs/hero.png (1600x900) from real screenshots and measured numbers.

Every number on the hero is read from results/*.json at render time.
"""

from __future__ import annotations

import json

from PIL import Image, ImageDraw, ImageFilter

from mfviz import BG, BG2, DOCS, GREEN, GREY, ICE, IMG, ORANGE, PURPLE, RED, RESULTS, WHITE, YELLOW, font

W, H = 1600, 900


def load(n):
    return json.loads((RESULTS / f"{n}.json").read_text())


def background():
    im = Image.new("RGB", (W, H), BG)
    px = im.load()
    for y in range(H):
        for x in range(W):
            t = min(1.0, (x / W) * 0.75 + (y / H) * 0.35)
            px[x, y] = tuple(int(BG[i] * (1 - t) + BG2[i] * t) for i in range(3))
    return im


def card(base, path, box, label, color, crop=None):
    x0, y0, x1, y1 = box
    shot = Image.open(path).convert("RGB")
    if crop:
        shot = shot.crop(crop)
    shot = shot.resize((x1 - x0, round(shot.height * (x1 - x0) / shot.width)), Image.LANCZOS)
    shot = shot.crop((0, 0, x1 - x0, min(shot.height, y1 - y0)))
    shadow = Image.new("RGBA", (shot.width + 40, shot.height + 40), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle((20, 20, shot.width + 20, shot.height + 20), radius=16, fill=(0, 0, 0, 170))
    shadow = shadow.filter(ImageFilter.GaussianBlur(12))
    base.paste(shadow, (x0 - 20, y0 - 12), shadow)
    mask = Image.new("L", shot.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, shot.width, shot.height), radius=14, fill=255)
    base.paste(shot, (x0, y0), mask)
    d = ImageDraw.Draw(base)
    f = font(20, 800)
    w = d.textlength(label, font=f)
    d.rounded_rectangle((x0 - 10, y0 - 22, x0 + w + 18, y0 + 14), radius=18, fill=color)
    d.text((x0 + 4, y0 - 18), label, font=f, fill=(255, 255, 255))


def main():
    p, pol, rag, ow = load("pii_eval"), load("policy_eval"), load("rag_eval")["modes"], load("owasp_llm")["summary"]
    leak_none = max(v["unauthorized_rate"] for v in rag["none_masked"].values())
    leak_pre = sum(v["unauthorized"] for v in rag["pre_masked"].values())
    allowed = sum(v == "ALLOWED" for b in pol["bypass"].values() for v in b.values())
    tried = sum(len(b) for b in pol["bypass"].values())
    im = background()
    card(im, IMG / "role_views.png", (960, 70, 1570, 330), "same table, five roles", ORANGE)
    card(im, IMG / "rag_leakage.png", (960, 390, 1570, 590), "RAG leakage", PURPLE, crop=(0, 0, 1140, 720))
    card(im, IMG / "owasp_attacks.png", (990, 650, 1550, 870), "OWASP LLM attacks", RED)
    d = ImageDraw.Draw(im)
    d.text((80, 70), "MASTERFABRIC", font=font(36, 800), fill=WHITE)
    d.text((76, 120), "Secure Data AI", font=font(84, 800), fill=WHITE)
    x, y = 80, 238
    for word, col in (("KVKK PII", GREEN), (" · ", GREY), ("column policies", ORANGE), (" · ", GREY), ("secure RAG", PURPLE),
                      (" · ", GREY), ("OWASP LLM", RED)):
        f = font(36, 800)
        d.text((x, y), word, font=f, fill=col)
        x += d.textlength(word, font=f)
    d.text((80, 318), "Data security controls for AI on synthetic Turkish customer data,", font=font(26, 500), fill=GREY)
    d.text((80, 352), "each with tests and a measured result. No real personal data.", font=font(26, 500), fill=GREY)
    a = p["with_checksum"]["ALL"]
    o = {k: ow[k] for k in ("LLM01 direct", "LLM02 disclosure", "LLM07 prompt leak")}
    facts = [
        (f"PII precision {p['pattern_only']['ALL']['precision']:.2f} → {a['precision']:.3f}, recall {a['recall']:.1f}",
         f"checksums on TCKN, IBAN and cards · {p['notes']:,} labelled notes with decoys", GREEN),
        (f"{allowed}/{tried} bypass queries allowed",
         f"{pol['rows']:,} customers · 5 roles · column masks, row filters, audit log", ORANGE),
        (f"RAG: {leak_none * 100:.1f}% → {leak_pre} unauthorised chunks",
         "ACL filter before ranking · PII pseudonymised at ingest", PURPLE),
        (f"PII leak {o['LLM02 disclosure']['baseline']['succeeded']}/8 → {o['LLM02 disclosure']['guarded']['succeeded']}/8 · "
         f"injection {o['LLM01 direct']['baseline']['succeeded']}/10 → {o['LLM01 direct']['guarded']['succeeded']}/10",
         "real local model (Qwen2.5-1.5B) · paraphrased injections still get through", RED),
    ]
    y = 430
    for title, sub, col in facts:
        d.rounded_rectangle((80, y + 6, 88, y + 62), radius=4, fill=col)
        d.text((106, y), title, font=font(29, 750), fill=WHITE)
        d.text((106, y + 38), sub, font=font(20, 450), fill=GREY)
        y += 92
    d.text((80, 820), "github.com/masterfabric/masterfabric-secure-data-ai", font=font(30, 700), fill=WHITE)
    im.save(DOCS / "hero.png", optimize=True)
    print("docs/hero.png written")


if __name__ == "__main__":
    main()
