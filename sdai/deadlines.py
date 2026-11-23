"""Response deadlines for data-subject requests under GDPR, CCPA/CPRA and KVKK, as pure functions of dates.

Every rule lives in one table (RULES) with the provision it comes from and a note on how it is modelled.
Nothing here reads the clock; callers pass `today`.

Counting convention (one common interpretation, not legal advice): the day of receipt is day 0 and is not
counted, so a period of n days ends n days after the receipt date, and a period of one month ends on the same
day number one calendar month later. If that month has no such day, the deadline clamps to the month's last day
(31 Jan -> 28/29 Feb, 31 Mar -> 30 Apr). EU Regulation 1182/71 (periods ending on a non-working day roll to the
next working day, receipt-day rules for requests that arrive on a weekend) is not modelled; neither are public
holidays. A deadline that falls on a weekend is returned as is.

An extension notice is treated as in time when it is given on or before the original due date.
"""
from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum


class Law(str, Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    KVKK = "kvkk"


class RequestType(str, Enum):
    ACCESS = "access"
    ERASURE = "erasure"
    CONSENT_WITHDRAWAL = "consent_withdrawal"  # under CCPA this is the opt-out of sale/sharing


@dataclass(frozen=True)
class Rule:
    unit: str        # "months", "days" or "business_days"
    base: int        # length of the first period
    extension: int   # further length allowed once, 0 if the law gives none
    citation: str
    note: str


_GDPR = Rule("months", 1, 2, "GDPR Art. 12(3)",
             "One month from receipt, extendable by two further months where necessary (complexity, number of "
             "requests); the data subject must be told of the extension and the reasons within the first month. "
             "Calendar-month arithmetic with clamping; Reg. 1182/71 not modelled.")
_CCPA = Rule("days", 45, 45, "Cal. Civ. Code 1798.130(a)(2); CCR tit. 11 s. 7021",
             "45 calendar days to know/delete/correct, extendable once by up to 45 more when reasonably "
             "necessary (90 in total), with notice to the consumer within the first 45 days.")
_CCPA_OPT_OUT = Rule("business_days", 15, 0, "CCR tit. 11 s. 7026(f)",
                     "Opt-out of sale/sharing must be acted on as soon as feasibly possible and no later than 15 "
                     "business days. Modelled as Monday to Friday with no holiday calendar; check the regulation text "
                     "for the current wording. No extension modelled.")
_KVKK = Rule("days", 30, 0, "Law 6698 Art. 13(2)",
             "Applications are concluded free of charge as soon as possible and at the latest within 30 days. "
             "The law gives no extension, so none is modelled.")
_KVKK_CONSENT = Rule("days", 30, 0, "Law 6698 Art. 13(2)",
                     "Art. 11 does not list withdrawal of consent as a separate right; it is handled as an "
                     "application under Art. 13 with the same 30 days. Treat as a conservative assumption.")

RULES: dict[tuple[Law, RequestType], Rule] = {
    **{(Law.GDPR, t): _GDPR for t in RequestType},
    (Law.CCPA, RequestType.ACCESS): _CCPA,
    (Law.CCPA, RequestType.ERASURE): _CCPA,
    (Law.CCPA, RequestType.CONSENT_WITHDRAWAL): _CCPA_OPT_OUT,
    (Law.KVKK, RequestType.ACCESS): _KVKK,
    (Law.KVKK, RequestType.ERASURE): _KVKK,
    (Law.KVKK, RequestType.CONSENT_WITHDRAWAL): _KVKK_CONSENT,
}


def rule(law: Law, rtype: RequestType) -> Rule:
    try:
        return RULES[(Law(law), RequestType(rtype))]
    except (KeyError, ValueError):
        raise ValueError(f"no deadline rule for {law!r} / {rtype!r}") from None


def add_months(d: date, n: int) -> date:
    """Same day number n calendar months later, clamped to the last day of the target month."""
    year, month = divmod(d.year * 12 + d.month - 1 + n, 12)
    month += 1
    return date(year, month, min(d.day, calendar.monthrange(year, month)[1]))


def add_business_days(d: date, n: int) -> date:
    """n Monday-to-Friday days after d. A start on a weekend counts from the next Monday."""
    while n > 0:
        d += timedelta(days=1)
        if d.weekday() < 5:
            n -= 1
    return d


def _add(d: date, unit: str, n: int) -> date:
    if unit == "months":
        return add_months(d, n)
    if unit == "days":
        return d + timedelta(days=n)
    return add_business_days(d, n)


def can_extend(law: Law, rtype: RequestType) -> bool:
    return rule(law, rtype).extension > 0


def due_date(law: Law, rtype: RequestType, received: date, extended: bool = False) -> date:
    r = rule(law, rtype)
    if not extended:
        return _add(received, r.unit, r.base)
    if not r.extension:
        raise ValueError(f"{Law(law).value} {RequestType(rtype).value} requests cannot be extended")
    # Months add up exactly (1 + 2 = 3, one clamp); days add up the same way.
    return _add(received, r.unit, r.base + r.extension)


def extension_notice_deadline(law: Law, rtype: RequestType, received: date) -> date | None:
    """Last day the requester can be told about an extension: the original due date. None if not extendable."""
    return due_date(law, rtype, received) if can_extend(law, rtype) else None


def notice_in_time(law: Law, rtype: RequestType, received: date, notice_on: date) -> bool:
    deadline = extension_notice_deadline(law, rtype, received)
    return deadline is not None and notice_on <= deadline


def days_remaining(due: date, today: date) -> int:
    return (due - today).days


def status(due: date, today: date, warn_days: int = 7) -> str:
    """'overdue' after the due date, 'due_soon' from warn_days before it up to and including the due date."""
    left = days_remaining(due, today)
    return "overdue" if left < 0 else "due_soon" if left <= warn_days else "ok"
