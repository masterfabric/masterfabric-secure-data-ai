# 0008. Data-subject request deadlines as one rule table and pure date functions

- Status: Accepted
- Date: 2026-11-23
- Builds on: [0005](0005-hash-chained-audit-log.md) (every transition is audited) and
  [0006](0006-kvkk-erasure.md) (erasure is one of the request types)

## Context

GDPR, CCPA/CPRA and KVKK all give a person the right to ask for their data, its erasure, or the end of marketing
use, and each has its own clock: one calendar month plus a possible two (GDPR Art. 12(3)), 45 days plus a possible
45 and 15 business days for an opt-out (Cal. Civ. Code 1798.130(a)(2), CCR tit. 11 ss. 7021, 7026), and 30 days
with no extension (KVKK Art. 13). The erasure service of ADR 0006 answers "can we delete everything"; nothing
answered "by when must we reply, and who is late". See [the comparison](../dsr-gdpr-ccpa-kvkk.md) for the
provisions; none of this is legal advice.

## Decision

[`sdai/deadlines.py`](../../sdai/deadlines.py) and [`sdai/dsr.py`](../../sdai/dsr.py):

1. **One rule table per law and request type** (`RULES`): unit (months, days or business days), base period,
   extension, citation and a note on how it is modelled. Adding a law is adding rows.
2. **Pure date functions.** `due_date`, `extension_notice_deadline`, `days_remaining` and `status` take dates and
   return dates or strings. Nothing reads the clock; the caller passes `today`.
3. **Calendar-month arithmetic with clamping** (31 Jan + 1 month = 28 or 29 Feb), written with `calendar`
   from the standard library. Day 0 is the receipt day. Weekends, holidays and Regulation 1182/71 are not modelled;
   CCPA opt-out business days are Monday to Friday.
4. **Status `ok` / `due_soon` / `overdue`**, with `due_soon` from 7 days before the due date up to and including
   it, and `overdue` only after it. `tracker()` lists open requests earliest due date first.
5. **Every transition is audited**: the request keeps a history and each step is appended to the hash-chained
   log with the subject as a keyed pseudonym; claims are dropped once checked.
6. **Incomplete processing stays open.** A request only becomes `completed` if the post-checks pass (erasure
   receipt `erased`, zero marketing rows left and the consent flag false); otherwise it stays in `processing`,
   with an `incomplete` entry, and keeps showing in the tracker.
7. **An extension is a recorded event**, accepted only if the law allows one, none was given before, and the
   notice is on or before the original due date. It moves `due`; the state does not change.

## Alternatives considered

- **A fixed 30 days for GDPR.** Simple, but it is wrong in both directions: the
  calendar-month deadline is 28 to 31 days after receipt, and a flat 30 would show a request as overdue one day
  early (31-day cases) or hide a late one for up to two days (28- and 29-day cases). In the sweep of 731
  receipt dates, 29 land at 28 days, 31 at 29 days and 421 at 31; only 250 are exactly 30.
- **`dateutil.relativedelta`.** Does the same clamping. Rejected to avoid a dependency for one 4-line function
  (`add_months`), and because the rules are in a table with citations anyway.
- **A workflow engine or cron job.** Would add a service and a clock to a problem that is a function of two
  dates, and would make the 2028-01-31 cases hard to test. Pure functions with an explicit `today` are tested in
  milliseconds and can be replayed for any date. A scheduler can still call `tracker()` in production.

## Result (`results/dsr_bench.json`, `.venv/bin/python eval/dsr_bench.py`, Apple M4 Pro, 24 GB)

| Check | Result |
|---|---|
| Requests (3 laws × 3 types × 60) over 200,000 customers | 540 of 540 completed, 540 on time, 0 failed or open |
| Latency per request, p50 / p95 | access 2.1 / 2.7 ms; consent withdrawal 1.5 / 2.1 ms; erasure 117 / 141 ms |
| Where the time goes (all 540) | verify p50 0.28 ms, respond p50 0.01 ms; erasure `process` p50 117 ms |
| Residual rows after the 180 erasures | 0 outside 360 retained invoice rows; other customers' row counts unchanged in 5 stores |
| Consent withdrawal, 180 subjects | 0 marketing rows left, 0 consent flags still true |
| Deadline function cost | 425 ns (days), 717 ns (months), 3,649 ns (15 business days) per call, including the loop |
| Deadline sweep, 731 receipt dates | GDPR one month lands 28 to 31 days out (13 month-end clamps); extended 89 to 92 |
| Tracker over 500 synthetic requests | 0.42 ms, sorted by due date; 110 ok, 32 due soon, 358 overdue |
| Audit | 2,340 entries, chain verified, 0 raw identifiers (TCKN, e-mail, phone, IBAN, card) in the log |

The 358 overdue are a property of the demo, not of the code: its receipt dates are spread over 120 days before
`today` (2027-06-15), so most 30- and 45-day periods have ended. The unit tests, 98 in all, include the
leap-year and month-end cases.

## Consequences

- Counting rules are visible in one table and one docstring, and a different reading (for example Regulation
  1182/71 for GDPR) means changing one row or one function, with tests that show what moved.
- The date arithmetic is a convention, not a ruling. A due date that falls on a weekend is shown as is, and the
  tracker will say `overdue` a day before a reading that rolls to Monday would.
- `due_soon` at 7 days is a default (`warn_days`), not a legal concept.
- The tracker lives in memory over the objects of one process. Persisting requests, reminders and a holiday
  calendar are outside this decision.
- The CCPA opt-out is the one request that accepts a single matching identifier, on one reading of s. 7026(d).
  If that reading is wrong for an organisation, `MIN_FACTORS_IDENTIFY` is one constant.
- Identity checking uses attempts constructed to the rules (820 attempts: 0 false accepts, 0 false rejects). That
  confirms the code does what the rules say, not that two factors are enough against real impostors.
