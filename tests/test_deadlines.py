from datetime import date

import pytest

from sdai import deadlines as dl
from sdai.deadlines import Law, RequestType as T

G, C, K = Law.GDPR, Law.CCPA, Law.KVKK


@pytest.mark.parametrize("d,n,want", [
    (date(2027, 1, 31), 1, date(2027, 2, 28)),
    (date(2028, 1, 31), 1, date(2028, 2, 29)),
    (date(2028, 2, 29), 1, date(2028, 3, 29)),
    (date(2026, 3, 31), 1, date(2026, 4, 30)),
    (date(2026, 11, 30), 1, date(2026, 12, 30)),
    (date(2026, 12, 31), 1, date(2027, 1, 31)),
    (date(2026, 8, 31), 3, date(2026, 11, 30)),
    (date(2026, 11, 30), 3, date(2027, 2, 28)),
    (date(2026, 5, 15), 12, date(2027, 5, 15)),
    (date(2028, 2, 29), 12, date(2029, 2, 28)),
])
def test_add_months(d, n, want):
    assert dl.add_months(d, n) == want


@pytest.mark.parametrize("t", list(T))
def test_gdpr_one_month_and_extension(t):
    assert dl.due_date(G, t, date(2027, 1, 31)) == date(2027, 2, 28)
    assert dl.due_date(G, t, date(2028, 1, 31)) == date(2028, 2, 29)
    assert dl.due_date(G, t, date(2026, 8, 31), extended=True) == date(2026, 11, 30)
    assert dl.due_date(G, t, date(2026, 11, 30)) == date(2026, 12, 30)
    assert dl.can_extend(G, t)


def test_ccpa_45_days_across_year_end_and_leap_february():
    assert dl.due_date(C, T.ACCESS, date(2026, 11, 20)) == date(2027, 1, 4)
    assert dl.due_date(C, T.ERASURE, date(2028, 1, 20)) == date(2028, 3, 5)  # leap year
    assert dl.due_date(C, T.ERASURE, date(2027, 1, 20)) == date(2027, 3, 6)


def test_ccpa_extension_is_90_days_total():
    r = date(2026, 11, 20)
    assert dl.due_date(C, T.ACCESS, r, extended=True) == date(2027, 2, 18)
    assert (dl.due_date(C, T.ACCESS, r, extended=True) - r).days == 90


def test_ccpa_opt_out_is_15_business_days():
    assert dl.rule(C, T.CONSENT_WITHDRAWAL).unit == "business_days"
    assert dl.due_date(C, T.CONSENT_WITHDRAWAL, date(2027, 1, 1)) == date(2027, 1, 22)  # Friday -> three weeks
    assert dl.due_date(C, T.CONSENT_WITHDRAWAL, date(2027, 1, 4)) == date(2027, 1, 25)  # Monday
    assert dl.due_date(C, T.CONSENT_WITHDRAWAL, date(2027, 1, 2)) == date(2027, 1, 22)  # Saturday counts from Monday
    assert not dl.can_extend(C, T.CONSENT_WITHDRAWAL)


def test_kvkk_30_days_across_february():
    assert dl.due_date(K, T.ACCESS, date(2027, 2, 1)) == date(2027, 3, 3)
    assert dl.due_date(K, T.ERASURE, date(2028, 2, 1)) == date(2028, 3, 2)


@pytest.mark.parametrize("t", list(T))
def test_kvkk_cannot_extend(t):
    assert not dl.can_extend(K, t)
    assert dl.extension_notice_deadline(K, t, date(2027, 1, 1)) is None
    with pytest.raises(ValueError):
        dl.due_date(K, t, date(2027, 1, 1), extended=True)


def test_extension_notice_deadline_is_original_due_date():
    r = date(2027, 1, 31)
    assert dl.extension_notice_deadline(G, T.ACCESS, r) == date(2027, 2, 28)
    assert dl.notice_in_time(G, T.ACCESS, r, date(2027, 2, 28))
    assert not dl.notice_in_time(G, T.ACCESS, r, date(2027, 3, 1))
    assert not dl.notice_in_time(K, T.ACCESS, r, date(2027, 2, 1))


def test_status_boundaries():
    due = date(2027, 3, 10)
    assert dl.status(due, date(2027, 3, 2)) == "ok"          # 8 days left
    assert dl.status(due, date(2027, 3, 3)) == "due_soon"    # 7 days left
    assert dl.status(due, due) == "due_soon"                 # due today is not overdue
    assert dl.status(due, date(2027, 3, 11)) == "overdue"
    assert dl.status(due, date(2027, 3, 8), warn_days=1) == "ok"
    assert dl.days_remaining(due, date(2027, 3, 11)) == -1


def test_every_rule_is_cited_and_hedged():
    assert len(dl.RULES) == 9
    assert all(r.citation and r.note for r in dl.RULES.values())


def test_unknown_combination_rejected():
    with pytest.raises(ValueError):
        dl.rule("eu", T.ACCESS)
