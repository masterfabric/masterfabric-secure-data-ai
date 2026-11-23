from datetime import date

import pytest

from sdai import deadlines as dl
from sdai.audit import AuditLog
from sdai.deadlines import Law, RequestType as T
from sdai.dsr import DSRService, tracker
from sdai.erasure import build_estate, identifiers, scan
from sdai.synth import customers

TODAY = date(2026, 11, 23)


@pytest.fixture()
def estate():
    return build_estate(customers(120, seed=21), n_notes=600, n_tickets=150, seed=4)


@pytest.fixture()
def svc(estate, tmp_path):
    return DSRService(estate, AuditLog(tmp_path / "a.jsonl"))


def _cid(est, consent=True):
    rows = est.con.execute("SELECT customer_id FROM crm.customers WHERE consent_marketing = ? ORDER BY customer_id", [consent]).fetchall()
    for (c,) in rows:
        if est.subject_key(c) in est.subject_index:
            return c


def _claims(est, cid, *factors):
    ids = identifiers(est, cid)
    full = {"email": ids["email"], "phone": ids["phone"], "tckn_last4": ids["tckn"][-4:]}
    return {"customer_id": cid, **{f: full[f] for f in factors}}


def _verified(svc, law=Law.KVKK, rtype=T.ACCESS, cid=None, consent=True):
    cid = cid or _cid(svc.est, consent)
    req = svc.intake(law, rtype, TODAY, _claims(svc.est, cid, "email", "phone"))
    assert svc.verify_identity(req, TODAY)
    return req, cid


def _count(est, cid, table, where=""):
    return est.con.execute(f"SELECT count(*) FROM {table} WHERE customer_id = ? {where}", [cid]).fetchone()[0]


def test_intake_computes_due_and_validates_type(svc, estate):
    req = svc.intake(Law.GDPR, T.ACCESS, date(2027, 1, 31), _claims(estate, _cid(estate), "email"))
    assert req.due == date(2027, 2, 28) and req.state == "received"
    with pytest.raises(ValueError):
        svc.intake(Law.GDPR, "access", TODAY, {"customer_id": 1})
    with pytest.raises(ValueError):
        svc.intake("gdpr", T.ACCESS, TODAY, {"customer_id": 1})


def test_intake_rejects_type_without_rule(svc, monkeypatch):
    monkeypatch.delitem(dl.RULES, (Law.KVKK, T.CONSENT_WITHDRAWAL))
    with pytest.raises(ValueError):
        svc.intake(Law.KVKK, T.CONSENT_WITHDRAWAL, TODAY, {"customer_id": 1})


def test_duplicate_id_rejected(svc):
    svc.intake(Law.KVKK, T.ACCESS, TODAY, {"customer_id": 1}, "X")
    with pytest.raises(ValueError):
        svc.intake(Law.KVKK, T.ACCESS, TODAY, {"customer_id": 1}, "X")


@pytest.mark.parametrize("factors", [("email", "phone"), ("email", "tckn_last4"), ("phone", "tckn_last4"),
                                     ("email", "phone", "tckn_last4")])
def test_verification_succeeds_with_two_or_more_factors(svc, estate, factors):
    req = svc.intake(Law.KVKK, T.ACCESS, TODAY, _claims(estate, _cid(estate), *factors))
    assert svc.verify_identity(req, TODAY) and req.state == "identity_verified" and req.claims == {}


def test_one_factor_fails(svc, estate):
    req = svc.intake(Law.KVKK, T.ACCESS, TODAY, _claims(estate, _cid(estate), "email"))
    assert not svc.verify_identity(req, TODAY) and req.state == "identity_rejected"
    assert req.history[-1]["factors_matched"] == 1


def test_wrong_factor_fails_and_formatting_is_normalised(svc, estate):
    c = _claims(estate, _cid(estate), "email", "phone")
    bad = svc.intake(Law.KVKK, T.ACCESS, TODAY, {**c, "email": "other@example.com", "tckn_last4": "0000"})
    assert not svc.verify_identity(bad, TODAY)  # only the phone matches
    ok = svc.intake(Law.KVKK, T.ACCESS, TODAY, {**c, "email": c["email"].upper(), "phone": c["phone"].replace(" ", "")})
    assert svc.verify_identity(ok, TODAY)


def test_unknown_subject_and_empty_claims_rejected(svc, estate):
    req = svc.intake(Law.KVKK, T.ACCESS, TODAY, {"customer_id": 1, "email": "", "phone": "", "tckn_last4": ""})
    assert not svc.verify_identity(req, TODAY)
    ghost = svc.intake(Law.KVKK, T.ACCESS, TODAY, {"customer_id": 999999, "email": "a@b.co", "phone": "5", "tckn_last4": "1"})
    assert not svc.verify_identity(ghost, TODAY)
    blank = svc.intake(Law.KVKK, T.ACCESS, TODAY, {"customer_id": _cid(estate)})
    assert not svc.verify_identity(blank, TODAY)


def test_cannot_process_before_verification(svc, estate):
    req = svc.intake(Law.KVKK, T.ACCESS, TODAY, _claims(estate, _cid(estate), "email", "phone"))
    with pytest.raises(ValueError):
        svc.process(req, TODAY)


def test_rejected_identity_can_be_retried_via_needs_info(svc, estate):
    cid = _cid(estate)
    req = svc.intake(Law.KVKK, T.ACCESS, TODAY, _claims(estate, cid, "email"))
    svc.verify_identity(req, TODAY)
    svc.request_info(req, TODAY, _claims(estate, cid, "email", "phone"))
    assert req.state == "needs_info" and svc.verify_identity(req, TODAY)
    with pytest.raises(ValueError):
        svc.request_info(req, TODAY)  # verified -> needs_info is not a transition


def test_access_report_contents(svc, estate):
    req, cid = _verified(svc, Law.GDPR, T.ACCESS)
    report = svc.process(req, TODAY)
    ids = identifiers(estate, cid)
    assert req.state == "completed" and report["crm.customers"]["email"] == ids["email"]
    assert report["care.call_notes"]["count"] == _count(estate, cid, "care.call_notes")
    assert report["billing.invoices"]["count"] == len(report["billing.invoices"]["rows"]) == 2
    assert report["analytics.customer_snapshot"]["present"] and report["marketing.contact_list"]["present"]
    assert report["rag.index"]["documents"] == len(estate.subject_index[estate.subject_key(cid)]) >= 1
    assert ids["email"] not in str(svc.respond(req))  # the response document carries no subject data


def test_erasure_leaves_only_retained_invoices(svc, estate):
    req, cid = _verified(svc, Law.KVKK, T.ERASURE)
    ids = identifiers(estate, cid)
    assert sum(scan(estate, cid, ids).values()) > 0
    receipt = svc.process(req, TODAY)
    assert req.state == "completed" and receipt["status"] == "erased"
    after = scan(estate, cid, {k: v for k, v in ids.items() if k not in receipt["shared_identifiers_needing_review"]})
    assert {k: v for k, v in after.items() if v} == {"billing.invoices": receipt["retained"]["billing.invoices"]["rows"]}
    assert svc.respond(req)["outcome"]["retained_rows"] == 2


def test_consent_withdrawal_removes_from_marketing_list(svc, estate):
    req, cid = _verified(svc, Law.CCPA, T.CONSENT_WITHDRAWAL, consent=True)
    assert _count(estate, cid, "marketing.contact_list") == 1
    svc.process(req, TODAY)
    assert req.state == "completed" and _count(estate, cid, "marketing.contact_list") == 0
    assert _count(estate, cid, "crm.customers", "AND consent_marketing") == 0
    assert _count(estate, cid, "crm.customers") == 1  # record kept, flag cleared
    assert req.outcome["contact_list_rows_removed"] == 1
    assert dl.due_date(Law.CCPA, T.CONSENT_WITHDRAWAL, TODAY) == req.due  # 15 business days


def test_consent_withdrawal_when_already_withdrawn(svc):
    req, _ = _verified(svc, Law.GDPR, T.CONSENT_WITHDRAWAL, consent=False)
    svc.process(req, TODAY)
    assert req.state == "completed" and req.outcome["contact_list_rows_removed"] == 0


def test_extension_gdpr_and_notice_rules(svc, estate):
    req = svc.intake(Law.GDPR, T.ERASURE, date(2026, 8, 31), _claims(estate, _cid(estate), "email"))
    svc.extend(req, date(2026, 9, 30), "complex request")
    assert req.extended and req.due == date(2026, 11, 30) and req.original_due == date(2026, 9, 30)
    with pytest.raises(ValueError):
        svc.extend(req, date(2026, 9, 30))  # only once
    late = svc.intake(Law.GDPR, T.ERASURE, date(2026, 8, 31), _claims(estate, _cid(estate), "email"))
    with pytest.raises(ValueError):
        svc.extend(late, date(2026, 10, 1))  # after the original due date
    assert not late.extended and late.due == date(2026, 9, 30)


def test_kvkk_extension_refused_and_ccpa_extension_90_days(svc):
    k = svc.intake(Law.KVKK, T.ACCESS, TODAY, {"customer_id": 1})
    with pytest.raises(ValueError):
        svc.extend(k, TODAY)
    c = svc.intake(Law.CCPA, T.ACCESS, TODAY, {"customer_id": 1})
    svc.extend(c, date(2026, 12, 1))
    assert (c.due - c.received).days == 90


def test_respond_on_time_and_late(svc):
    req, _ = _verified(svc, Law.KVKK, T.ACCESS)
    with pytest.raises(ValueError):
        svc.respond(req)  # not finished
    svc.process(req, date(2026, 12, 23))  # day 30
    r = svc.respond(req)
    assert r["on_time"] and r["due"] == "2026-12-23" and r["completed_on"] == "2026-12-23" and r["law"] == "kvkk"
    late, _ = _verified(svc, Law.KVKK, T.ACCESS)
    svc.process(late, date(2026, 12, 24))
    assert not svc.respond(late)["on_time"]


def test_extended_response_is_on_time_after_original_due(svc):
    req, _ = _verified(svc, Law.CCPA, T.ACCESS)
    svc.extend(req, date(2026, 12, 1), "volume")
    svc.process(req, date(2027, 1, 20))  # past day 45, within day 90
    r = svc.respond(req)
    assert r["on_time"] and r["extension"] == {"extended": True, "notice_on": "2026-12-01"}


def test_reject_and_closed_states_are_final(svc):
    req, _ = _verified(svc)
    svc.reject(req, TODAY, "manifestly unfounded")
    assert svc.respond(req)["outcome_state"] == "rejected"
    with pytest.raises(ValueError):
        svc.process(req, TODAY)
    with pytest.raises(ValueError):
        svc.extend(req, TODAY)


def test_audit_log_verifies_and_has_no_raw_identifiers(svc, estate):
    cid = _cid(estate)
    ids = identifiers(estate, cid)
    req, _ = _verified(svc, Law.KVKK, T.ERASURE, cid)
    svc.process(req, TODAY)
    bad = svc.intake(Law.KVKK, T.ACCESS, TODAY, {"customer_id": cid, "email": ids["email"], "tckn_last4": ids["tckn"][-4:] + "x"})
    svc.verify_identity(bad, TODAY)
    log = svc.audit
    assert log.verify().ok
    text = log.path.read_text()
    assert not any(v in text for v in (ids["tckn"], ids["email"], ids["phone"], ids["iban"]))
    actions = [e["action"] for e in log.entries()]
    assert {"dsr.intake", "dsr.identity_verified", "dsr.processing", "dsr.completed", "dsr.identity_rejected",
            "kvkk.erasure"} <= set(actions)
    dsr_entries = [e for e in log.entries() if e["action"].startswith("dsr.")]
    assert all(e["detail"]["subject_ref"].startswith("<SUBJECT:") for e in dsr_entries)
    assert [h["event"] for h in req.history] == ["intake", "identity_verified", "processing", "completed"]


def test_tracker_orders_by_due_and_flags_status(svc):
    a = svc.intake(Law.KVKK, T.ACCESS, date(2026, 11, 1), {"customer_id": 1})   # due Dec 1
    b = svc.intake(Law.KVKK, T.ACCESS, date(2026, 10, 1), {"customer_id": 2})   # due Oct 31 -> overdue
    c = svc.intake(Law.KVKK, T.ACCESS, date(2026, 11, 10), {"customer_id": 3})  # due Dec 10
    d = svc.intake(Law.GDPR, T.ACCESS, date(2026, 10, 30), {"customer_id": 4})  # due Nov 30
    done = svc.intake(Law.KVKK, T.ACCESS, date(2026, 10, 1), {"customer_id": 5})
    svc.reject(done, TODAY, "no")
    q = svc.queue(TODAY)
    assert [r["request"] for r in q] == [b.id, d.id, a.id, c.id]
    assert [r["status"] for r in q] == ["overdue", "due_soon", "ok", "ok"]
    assert q[0]["days_remaining"] < 0 and q[1]["days_remaining"] == 7
    assert [r["status"] for r in tracker(svc.requests.values(), TODAY, warn_days=14)][2:] == ["due_soon", "ok"]
    due_today = tracker([a], date(2026, 12, 1))
    assert due_today[0]["status"] == "due_soon" and due_today[0]["days_remaining"] == 0
