import random

from sdai.pii import detect, mask_text, mask_value, pseudonym, valid_iban, valid_luhn, valid_tckn
from sdai.synth import card, iban_tr, tckn


def test_generated_identifiers_pass_their_checksums():
    rng = random.Random(1)
    for _ in range(500):
        assert valid_tckn(tckn(rng)) and valid_iban(iban_tr(rng)) and valid_luhn(card(rng))


def test_checksum_rejects_order_numbers_and_wrong_ibans():
    assert not valid_tckn("12345678901")
    assert not valid_tckn("01234567890")
    assert not valid_iban("TR000001200000000000000000")


def test_detect_and_redact_all_kinds():
    rng = random.Random(2)
    t, i, c = tckn(rng), iban_tr(rng), card(rng)
    text = f"id {t} iban {i} card {c} phone +90 532 111 22 33 mail ali.kaya1@example.com order 12345678901"
    kinds = [s.kind for s in detect(text)]
    assert kinds == ["TCKN", "IBAN", "CARD", "PHONE", "EMAIL"]
    masked = mask_text(text)
    assert t not in masked and i not in masked and c not in masked and "example.com" not in masked
    assert "12345678901" in masked  # an invalid TCKN is an order number, not PII


def test_partial_and_pseudonym():
    assert mask_value("TR590001203186091390996030", "IBAN", "partial").endswith("6030")
    assert mask_value("TR42 0001 5018 0967 9290 8100 33", "IBAN", "partial").endswith("00 33")
    assert mask_value("ali.kaya@example.com", "EMAIL", "partial") == "al******@example.com"
    assert pseudonym("70181590898", "TCKN") == pseudonym("70181590898", "TCKN")
    assert pseudonym("70181590898", "TCKN") != pseudonym("70181590899", "TCKN")
