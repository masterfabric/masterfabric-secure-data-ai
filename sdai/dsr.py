"""Data-subject request (DSR) workflow for GDPR, CCPA/CPRA and KVKK over the estate in sdai.erasure.

A request moves through a small state machine and every step is written twice: to an in-memory history on the
request and to the hash-chained audit log, where the subject appears only as a keyed pseudonym.

  received -> identity_verified -> processing -> completed
          \\-> identity_rejected -> needs_info -> (verify again) | rejected
  any open state -> rejected;  extend() records the notice and moves the due date, the state does not change

Identity is checked against crm.customers: the requester supplies a customer id plus claims (e-mail, phone,
last four digits of the TCKN) and at least two of them must match. Each comparison is constant-time and all
factors are always compared, so neither timing nor an early exit tells the requester which factor was wrong. The
claims are dropped from the request once checked.

One exception, modelled on a reading of CCR tit. 11 s. 7026(d) (check the current regulation text; not legal
advice): a CCPA opt-out of sale/sharing (CONSENT_WITHDRAWAL) is not a request that needs verification, and the
business may ask only for what it needs to identify whose data to stop selling or sharing. For that one law and
type a single matching factor is therefore enough (MIN_FACTORS_IDENTIFY); every other law and type still needs two.

Processing per type:
  ACCESS              a report for the subject (their own data, per store). The report is returned to the
                      requester and kept on the request, never written to the audit log or the response document.
  ERASURE             sdai.erasure.erase(); its receipt is attached. Not "erased" -> stays in processing.
  CONSENT_WITHDRAWAL  consent_marketing = false and removal from marketing.contact_list, verified to be zero
                      afterwards. Under CCPA this is the opt-out of sale/sharing.

Dates are always passed in; nothing here reads the clock. Deadlines come from sdai.deadlines (see its docstring
for the counting convention and what is not modelled).
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from datetime import date

from . import deadlines as dl
from .audit import AuditLog
from .deadlines import Law, RequestType
from .erasure import Estate, digits, erase
from .pii import pseudonym

RECEIVED, VERIFIED, REJECTED_ID = "received", "identity_verified", "identity_rejected"
PROCESSING, COMPLETED, REJECTED, NEEDS_INFO = "processing", "completed", "rejected", "needs_info"
OPEN = {RECEIVED, VERIFIED, REJECTED_ID, PROCESSING, NEEDS_INFO}
TRANSITIONS = {RECEIVED: {VERIFIED, REJECTED_ID, REJECTED}, NEEDS_INFO: {VERIFIED, REJECTED_ID, REJECTED},
               REJECTED_ID: {NEEDS_INFO, REJECTED}, VERIFIED: {PROCESSING, REJECTED},
               PROCESSING: {COMPLETED, REJECTED}, COMPLETED: set(), REJECTED: set()}
MIN_FACTORS = 2
MIN_FACTORS_IDENTIFY = 1  # CCPA opt-out: identification of the record, not verification (see module docstring)
FACTORS = ("email", "phone", "tckn_last4")


@dataclass
class DSRequest:
    id: str
    law: Law
    type: RequestType
    received: date
    due: date
    claims: dict = field(default_factory=dict, repr=False)  # raw identifiers from the requester; cleared after the check
    customer_id: int | None = None
    subject_ref: str = ""
    state: str = RECEIVED
    extended: bool = False
    extension_notice_on: date | None = None
    completed_on: date | None = None
    outcome: dict = field(default_factory=dict)  # counts and statuses only, safe to log
    deliverable: dict | None = field(default=None, repr=False)  # access report or erasure receipt, for the subject
    history: list[dict] = field(default_factory=list)

    @property
    def original_due(self) -> date:
        return dl.due_date(self.law, self.type, self.received)


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _norm(factor: str, v) -> str:
    v = str(v or "")
    if factor == "email":
        return v.strip().lower()
    if factor == "phone":
        return digits(v)[-10:]
    return digits(v)[-4:]


def required_factors(law: Law, rtype: RequestType) -> int:
    return MIN_FACTORS_IDENTIFY if (law, rtype) == (Law.CCPA, RequestType.CONSENT_WITHDRAWAL) else MIN_FACTORS


class DSRService:
    def __init__(self, est: Estate, audit: AuditLog | None = None, actor: str = "dpo"):
        self.est, self.audit, self.actor = est, audit, actor
        self.requests: dict[str, DSRequest] = {}

    # -- bookkeeping --------------------------------------------------------------------------------------------
    def _log(self, req: DSRequest, event: str, today: date, decision: str = "allow", reason: str = "", **detail) -> None:
        req.history.append({"event": event, "on": str(today), "state": req.state, **detail})
        if self.audit:
            self.audit.append(self.actor, "dpo", f"dsr.{event}", decision, reason,
                              {"request": req.id, "law": req.law.value, "type": req.type.value,
                               "subject_ref": req.subject_ref, "state": req.state, "due": str(req.due), **detail})

    def _move(self, req: DSRequest, to: str) -> None:
        if to not in TRANSITIONS[req.state]:
            raise ValueError(f"request {req.id}: cannot go from {req.state} to {to}")
        req.state = to

    # -- workflow -----------------------------------------------------------------------------------------------
    def intake(self, law: Law, rtype: RequestType, received: date, claims: dict, request_id: str | None = None) -> DSRequest:
        if not isinstance(law, Law) or not isinstance(rtype, RequestType):
            raise ValueError("law and type must be Law and RequestType members")
        due = dl.due_date(law, rtype, received)  # raises if the law has no rule for this type
        rid = request_id or f"DSR-{len(self.requests) + 1:04d}"
        if rid in self.requests:
            raise ValueError(f"duplicate request id {rid}")
        cid = claims.get("customer_id")
        req = DSRequest(rid, law, rtype, received, due, {k: v for k, v in claims.items() if k != "customer_id"},
                        subject_ref=pseudonym(str(cid), "SUBJECT"))
        req.customer_id = int(cid) if isinstance(cid, int) or str(cid).isdigit() else None
        self.requests[rid] = req
        self._log(req, "intake", received, original_due=str(req.original_due))
        return req

    def verify_identity(self, req: DSRequest, today: date) -> bool:
        row = None
        if req.customer_id is not None:
            row = self.est.con.execute("SELECT email, phone, tckn FROM crm.customers WHERE customer_id = ?",
                                       [req.customer_id]).fetchone()
        held = {"email": row[0], "phone": row[1], "tckn_last4": row[2]} if row else {f: "" for f in FACTORS}
        # Every factor is compared (no short-circuit) and an empty or missing claim never matches.
        hits = [bool(_norm(f, req.claims.get(f))) & _eq(_norm(f, req.claims.get(f)), _norm(f, held[f])) for f in FACTORS]
        matched = sum(hits) if row else 0
        req.claims = {}
        need = required_factors(req.law, req.type)
        ok = matched >= need
        self._move(req, VERIFIED if ok else REJECTED_ID)
        self._log(req, "identity_verified" if ok else "identity_rejected", today, "allow" if ok else "deny",
                  "" if ok else f"fewer than {need} matching factors", factors_matched=matched)
        return ok

    def request_info(self, req: DSRequest, today: date, claims: dict | None = None) -> None:
        """Ask the requester for more proof; a fresh set of claims replaces the old one for the next check."""
        self._move(req, NEEDS_INFO)
        req.claims = dict(claims or {})
        self._log(req, "needs_info", today)

    def extend(self, req: DSRequest, notice_on: date, reason: str = "") -> None:
        if req.state not in OPEN:
            raise ValueError(f"request {req.id} is closed")
        if not dl.can_extend(req.law, req.type):
            raise ValueError(f"{req.law.value} {req.type.value} requests cannot be extended")
        if req.extended:
            raise ValueError(f"request {req.id} is already extended")
        if not dl.notice_in_time(req.law, req.type, req.received, notice_on):
            raise ValueError(f"extension notice on {notice_on} is after the original due date {req.original_due}")
        req.extended, req.extension_notice_on = True, notice_on
        req.due = dl.due_date(req.law, req.type, req.received, extended=True)
        self._log(req, "extended", notice_on, reason=reason, original_due=str(req.original_due), new_due=str(req.due))

    def reject(self, req: DSRequest, today: date, reason: str) -> None:
        self._move(req, REJECTED)
        req.completed_on = today
        self._log(req, "rejected", today, "deny", reason)

    def process(self, req: DSRequest, today: date) -> dict:
        if req.state != VERIFIED:
            raise ValueError(f"request {req.id} is {req.state}; identity must be verified before processing")
        self._move(req, PROCESSING)
        self._log(req, "processing", today)
        handler = {RequestType.ACCESS: self._access, RequestType.ERASURE: self._erasure,
                   RequestType.CONSENT_WITHDRAWAL: self._withdraw}[req.type]
        req.deliverable, req.outcome = handler(req, today)
        if req.outcome["status"] in ("access_report_ready", "erased", "consent_withdrawn"):
            self._move(req, COMPLETED)
            req.completed_on = today
            self._log(req, "completed", today, outcome=req.outcome)
        else:  # work did not verify as done: it stays open and visible in the tracker
            self._log(req, "incomplete", today, "error", "post-checks failed", outcome=req.outcome)
        return req.deliverable

    # -- handlers: each returns (deliverable for the subject, outcome safe for logs) --------------------------------
    def _access(self, req: DSRequest, today: date):
        con, cid = self.est.con, req.customer_id
        cols = [d[0] for d in con.execute("DESCRIBE crm.customers").fetchall()]
        row = con.execute("SELECT * FROM crm.customers WHERE customer_id = ?", [cid]).fetchone()
        inv_cols = ["invoice_id", "amount_try", "issued_on"]
        invoices = con.execute(f"SELECT {', '.join(inv_cols)} FROM billing.invoices WHERE customer_id = ? ORDER BY invoice_id",
                               [cid]).fetchall()
        n = lambda t: con.execute(f"SELECT count(*) FROM {t} WHERE customer_id = ?", [cid]).fetchone()[0]  # noqa: E731
        docs = len(self.est.subject_index.get(self.est.subject_key(cid), set()))
        report = {"generated_on": str(today), "law": req.law.value,
                  "categories": {"identity and contact": "crm.customers", "customer-care notes": "care.call_notes",
                                 "billing": "billing.invoices", "analytics profile": "analytics.customer_snapshot",
                                 "marketing list": "marketing.contact_list", "support tickets (search index)": "rag.index"},
                  "crm.customers": dict(zip(cols, row)),
                  "care.call_notes": {"count": n("care.call_notes")},
                  "billing.invoices": {"count": len(invoices), "rows": [dict(zip(inv_cols, i)) for i in invoices]},
                  "analytics.customer_snapshot": {"present": bool(n("analytics.customer_snapshot"))},
                  "marketing.contact_list": {"present": bool(n("marketing.contact_list"))},
                  "rag.index": {"documents": docs}}
        counts = {"call_notes": report["care.call_notes"]["count"], "invoices": len(invoices), "rag_documents": docs}
        return report, {"status": "access_report_ready", **counts}

    def _erasure(self, req: DSRequest, today: date):
        receipt = erase(self.est, req.customer_id, self.actor, self.audit, today)
        return receipt, {"status": receipt["status"], "actions": receipt.get("actions", {}),
                         "retained_rows": receipt.get("retained", {}).get("billing.invoices", {}).get("rows", 0)}

    def _withdraw(self, req: DSRequest, today: date):
        con, cid = self.est.con, req.customer_id
        con.execute("UPDATE crm.customers SET consent_marketing = false WHERE customer_id = ?", [cid])
        removed = con.execute("DELETE FROM marketing.contact_list WHERE customer_id = ?", [cid]).fetchone()[0]
        left = con.execute("SELECT count(*) FROM marketing.contact_list WHERE customer_id = ?", [cid]).fetchone()[0]
        consent = con.execute("SELECT count(*) FROM crm.customers WHERE customer_id = ? AND consent_marketing", [cid]).fetchone()[0]
        ok = left == 0 and consent == 0
        out = {"status": "consent_withdrawn" if ok else "incomplete", "contact_list_rows_removed": removed,
               "contact_list_rows_left": left}
        return {"consent_marketing": False, "removed_from_marketing_list": removed > 0}, out

    # -- output -------------------------------------------------------------------------------------------------
    def respond(self, req: DSRequest) -> dict:
        if req.state not in (COMPLETED, REJECTED):
            raise ValueError(f"request {req.id} is still {req.state}")
        return {"request": req.id, "law": req.law.value, "type": req.type.value, "outcome_state": req.state,
                "received": str(req.received), "original_due": str(req.original_due), "due": str(req.due),
                "completed_on": str(req.completed_on), "on_time": req.completed_on <= req.due,
                "extension": {"extended": req.extended, "notice_on": str(req.extension_notice_on) if req.extended else None},
                "subject_ref": req.subject_ref, "outcome": req.outcome,
                "citation": dl.rule(req.law, req.type).citation}

    def queue(self, today: date, warn_days: int = 7) -> list[dict]:
        return tracker(self.requests.values(), today, warn_days)


def tracker(requests, today: date, warn_days: int = 7) -> list[dict]:
    """Open requests with days left and ok / due_soon / overdue, earliest due date first."""
    rows = [{"request": r.id, "law": r.law.value, "type": r.type.value, "state": r.state, "due": str(r.due),
             "days_remaining": dl.days_remaining(r.due, today), "status": dl.status(r.due, today, warn_days)}
            for r in requests if r.state in OPEN]
    return sorted(rows, key=lambda x: (x["due"], x["request"]))
