"""PII detection and masking for Turkish personal data (KVKK).

Detectors combine a pattern with a checksum where one exists (TCKN, IBAN mod-97, Luhn), which is
what separates a national ID from an 11-digit order number. `validate=False` gives the
pattern-only baseline used in the evaluation.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass

PATTERNS = {
    "TCKN": re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)"),
    "IBAN": re.compile(r"\bTR\d{2}(?: ?\d{4}){5}(?: ?\d{2})\b"),
    "CARD": re.compile(r"(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)"),
    "PHONE": re.compile(r"(?<!\d)(?:\+90[ -]?|0)?5\d{2}[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}(?!\d)"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"),
}


def valid_tckn(s: str) -> bool:
    d = [int(c) for c in s]
    if len(d) != 11 or d[0] == 0:
        return False
    return d[9] == ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10 and d[10] == sum(d[:10]) % 10


def valid_iban(s: str) -> bool:
    s = s.replace(" ", "")
    return len(s) == 26 and int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def valid_luhn(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    total = 0
    for i, n in enumerate(reversed(digits)):
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return len(digits) == 16 and total % 10 == 0


VALIDATORS = {"TCKN": valid_tckn, "IBAN": valid_iban, "CARD": valid_luhn}


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    text: str


def detect(text: str, validate: bool = True) -> list[Span]:
    spans: list[Span] = []
    for kind in ("IBAN", "EMAIL", "CARD", "TCKN", "PHONE"):  # longer formats first; overlaps are dropped
        for m in PATTERNS[kind].finditer(text):
            if any(m.start() < s.end and s.start < m.end() for s in spans):
                continue
            if validate and kind in VALIDATORS and not VALIDATORS[kind](m.group()):
                continue
            spans.append(Span(m.start(), m.end(), kind, m.group()))
    return sorted(spans, key=lambda s: s.start)


def _key() -> bytes:
    k = os.environ.get("SDAI_PSEUDO_KEY")
    return k.encode() if k else _RUN_KEY


_RUN_KEY = os.urandom(32)  # per-process key when none is configured: tokens are stable within one run only


def pseudonym(value: str, kind: str) -> str:
    # Letters only, so a pseudonym can never look like a phone number or an ID to a later scan.
    token = hmac.new(_key(), value.encode(), hashlib.sha256).hexdigest()[:10].translate(_DIGITS_TO_LETTERS)
    return f"<{kind}:{token}>"


_DIGITS_TO_LETTERS = str.maketrans("0123456789", "ghijklmnop")


def mask_value(value: str, kind: str, mode: str = "redact") -> str:
    if mode == "redact":
        return f"<{kind}>"
    if mode == "pseudonymize":
        return pseudonym(value, kind)
    if mode == "partial":
        keep = 2 if kind == "EMAIL" else 4
        if kind == "EMAIL":
            user, dom = value.split("@", 1)
            return user[:keep] + "*" * max(1, len(user) - keep) + "@" + dom
        cut, seen = len(value), 0  # keep the last 4 letters/digits, however the value is spaced
        while cut > 0 and seen < keep:
            cut -= 1
            seen += value[cut].isalnum()
        return re.sub(r"[0-9A-Za-z]", "*", value[:cut]) + value[cut:]
    raise ValueError(mode)


def mask_text(text: str, mode: str = "redact") -> str:
    out, pos = [], 0
    for s in detect(text):
        out += [text[pos:s.start], mask_value(s.text, s.kind, mode)]
        pos = s.end
    return "".join(out) + text[pos:]
