import pytest

from sdai.audit import AuditLog
from sdai.erasure import build_estate, erase, identifiers, scan
from sdai.synth import customers


@pytest.fixture()
def estate():
    return build_estate(customers(400, seed=21), n_notes=1500, n_tickets=300, seed=4)


def _subject_with_ticket(est):
    for r in est.con.execute("SELECT customer_id FROM crm.customers").fetchall():
        if est.subject_key(r[0]) in est.subject_index:
            return r[0]


def test_erasure_leaves_nothing_but_retained_invoices(estate, tmp_path):
    cid = _subject_with_ticket(estate)
    ids = identifiers(estate, cid)
    assert sum(scan(estate, cid, ids).values()) > 0  # negative control: the subject is there before
    log = AuditLog(tmp_path / "a.jsonl")
    rec = erase(estate, cid, "dpo", log)
    assert rec["status"] == "erased"
    assert rec["actions"]["crm.customers.deleted"] == 1 and rec["actions"]["rag.documents.removed"] >= 1
    after = scan(estate, cid, {k: v for k, v in ids.items() if k not in rec["shared_identifiers_needing_review"]})
    assert {k: v for k, v in after.items() if v} == {"billing.invoices": rec["retained"]["billing.invoices"]["rows"]}
    assert log.verify().ok and ids["tckn"] not in log.path.read_text()


def test_other_customers_untouched(estate):
    before = estate.con.execute("SELECT count(*) FROM crm.customers").fetchone()[0]
    erase(estate, _subject_with_ticket(estate), "dpo")
    assert estate.con.execute("SELECT count(*) FROM crm.customers").fetchone()[0] == before - 1


def test_receipt_has_no_raw_identifiers(estate):
    cid = _subject_with_ticket(estate)
    ids = identifiers(estate, cid)
    rec = str(erase(estate, cid, "dpo"))
    assert not any(v in rec for v in ids.values()) and str(cid) not in rec


def test_unknown_and_repeat_requests(estate):
    cid = _subject_with_ticket(estate)
    assert erase(estate, cid, "dpo")["status"] == "erased"
    assert erase(estate, cid, "dpo")["status"] == "not_found"
    assert erase(estate, 1, "dpo")["status"] == "not_found"


def test_shared_identifier_is_not_used_for_matching(estate):
    a, b = [r[0] for r in estate.con.execute("SELECT customer_id FROM crm.customers ORDER BY customer_id LIMIT 2").fetchall()]
    estate.con.execute("UPDATE crm.customers SET email = (SELECT email FROM crm.customers WHERE customer_id = ?) "
                       "WHERE customer_id = ?", [a, b])
    rec = erase(estate, a, "dpo")
    assert rec["shared_identifiers_needing_review"] == {"email": 1}
    assert estate.con.execute("SELECT count(*) FROM crm.customers WHERE customer_id = ?", [b]).fetchone()[0] == 1
