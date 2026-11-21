"""Labelled synthetic call-centre notes for the PII detector evaluation.

Each note embeds real-format PII from the synthetic customers plus decoys that look like PII but are
not: 11-digit order numbers, 16-digit shipment tracking numbers, IBAN-shaped strings with a wrong
check digit, and short reference codes.
"""
from __future__ import annotations

import random
import re

from .synth import customers

TEMPLATES = [
    "Customer called about bill. ID {TCKN}, callback on {PHONE}. Order no {DECOY_ORDER} delayed.",
    "Refund requested to {IBAN}. Confirmation sent to {EMAIL}. Ticket {DECOY_REF}.",
    "Card {CARD} blocked after 3 failed attempts; shipment tracking {DECOY_TRACK} for new card.",
    "Line transfer: national id {TCKN}, new number {PHONE}, e-mail {EMAIL}.",
    "Customer disputes charge on card {CARD}; wants credit to {IBAN}. Old order {DECOY_ORDER}.",
    "Address change only. Contract {DECOY_ORDER}, tracking {DECOY_TRACK}, ref {DECOY_REF}.",
    "Payment from {DECOY_IBAN} bounced (wrong IBAN given). Asked for correct account, reach at {PHONE}.",
    "Roaming package for {EMAIL}. Verified identity with TCKN {TCKN}.",
]


def notes(n: int = 1000, seed: int = 11) -> list[dict]:
    rng = random.Random(seed)
    people = customers(max(200, n // 4), seed=seed)
    out = []
    for i in range(n):
        c = rng.choice(people)
        t = rng.choice(TEMPLATES)
        values = {
            "TCKN": c["tckn"], "PHONE": c["phone"] if rng.random() < 0.5 else "0" + c["phone"][4:].replace(" ", ""),
            "IBAN": c["iban"] if rng.random() < 0.5 else " ".join([c["iban"][i:i + 4] for i in range(0, 26, 4)]),
            "EMAIL": c["email"],
            "CARD": c["card_number"] if rng.random() < 0.5 else " ".join(c["card_number"][i:i + 4] for i in range(0, 16, 4)),
            "DECOY_ORDER": str(rng.randint(10**10, 10**11 - 1)), "DECOY_TRACK": str(rng.randint(10**15, 10**16 - 1)),
            "DECOY_REF": f"REF-{rng.randint(1000, 9999)}",
            "DECOY_IBAN": "TR" + "".join(str(rng.randint(0, 9)) for _ in range(24)),
        }
        text, labels, pos = "", [], 0
        for m in re.finditer(r"\{(\w+)\}", t):
            text += t[pos:m.start()]
            v = values[m.group(1)]
            if not m.group(1).startswith("DECOY"):
                labels.append({"start": len(text), "end": len(text) + len(v), "kind": m.group(1)})
            text += v
            pos = m.end()
        text += t[pos:]
        out.append({"id": i, "text": text, "labels": labels})
    return out
