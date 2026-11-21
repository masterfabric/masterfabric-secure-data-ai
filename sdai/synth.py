"""Synthetic Turkish customer data. Nothing here belongs to a real person.

Names are random combinations of common Turkish first names and surnames. National ID numbers
(TCKN) and IBANs are random digits with valid checksums, so detectors can be tested on them; they
are not issued to anyone. Card numbers use the 9-prefixed range, which no card network issues.
"""
from __future__ import annotations

import random
from dataclasses import asdict, dataclass

FIRST = ["Ahmet", "Mehmet", "Mustafa", "Ali", "Hüseyin", "Hasan", "İbrahim", "Murat", "Emre", "Burak", "Can", "Deniz",
         "Ayşe", "Fatma", "Emine", "Hatice", "Zeynep", "Elif", "Merve", "Esra", "Selin", "Ebru", "Gül", "Özlem"]
LAST = ["Yılmaz", "Kaya", "Demir", "Şahin", "Çelik", "Yıldız", "Yıldırım", "Öztürk", "Aydın", "Özdemir", "Arslan",
        "Doğan", "Kılıç", "Aslan", "Çetin", "Kara", "Koç", "Kurt", "Özkan", "Şimşek"]
CITIES = ["İstanbul", "Ankara", "İzmir", "Bursa", "Antalya", "Adana", "Konya", "Gaziantep", "Kayseri", "Trabzon"]
SEGMENTS = ["consumer", "consumer", "consumer", "business"]
BANKS = ["00010", "00012", "00015", "00046", "00062", "00064", "00067", "00111"]


def tckn(rng: random.Random) -> str:
    d = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
    d.append(((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10)
    d.append(sum(d) % 10)
    return "".join(map(str, d))


def iban_tr(rng: random.Random) -> str:
    bban = rng.choice(BANKS) + "0" + "".join(str(rng.randint(0, 9)) for _ in range(16))
    num = int("".join(str(int(c, 36)) for c in bban + "TR00"))
    return f"TR{98 - num % 97:02d}{bban}"


def luhn_complete(prefix: str) -> str:
    total = 0
    for i, c in enumerate(reversed(prefix)):
        n = int(c)
        if i % 2 == 0:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return prefix + str((10 - total % 10) % 10)


def card(rng: random.Random) -> str:
    return luhn_complete("9" + "".join(str(rng.randint(0, 9)) for _ in range(14)))


def phone(rng: random.Random) -> str:
    return f"+90 5{rng.randint(30, 59)} {rng.randint(100, 999)} {rng.randint(10, 99)} {rng.randint(10, 99)}"


def ascii_tr(s: str) -> str:
    return s.translate(str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosuCGIOSU")).lower()


@dataclass
class Customer:
    customer_id: int
    full_name: str
    tckn: str
    phone: str
    email: str
    iban: str
    card_number: str
    city: str
    birth_date: str
    segment: str
    consent_marketing: bool
    monthly_spend_try: float


def customers(n: int, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    out = []
    for i in range(1, n + 1):
        f, l_ = rng.choice(FIRST), rng.choice(LAST)
        out.append(asdict(Customer(
            customer_id=100000 + i, full_name=f"{f} {l_}", tckn=tckn(rng), phone=phone(rng),
            email=f"{ascii_tr(f)}.{ascii_tr(l_)}{rng.randint(1, 999)}@example.com", iban=iban_tr(rng), card_number=card(rng),
            city=rng.choice(CITIES), birth_date=f"{rng.randint(1950, 2005)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
            segment=rng.choice(SEGMENTS), consent_marketing=rng.random() < 0.55,
            monthly_spend_try=round(rng.lognormvariate(6.2, 0.6), 2))))
    return out
