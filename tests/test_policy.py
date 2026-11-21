import duckdb
import pytest

from sdai.policy import AccessDenied, PolicyEngine, load_customers, lock_down
from sdai.synth import customers


@pytest.fixture(scope="module")
def eng(tmp_path_factory):
    con = duckdb.connect()
    load_customers(con, customers(500))
    e = PolicyEngine(con, "policies/customers.yaml", tmp_path_factory.mktemp("a") / "audit.jsonl")
    lock_down(con)
    return e


def test_default_deny_columns(eng):
    assert "tckn" not in eng.visible_columns("marketing")
    assert "full_name" not in eng.visible_columns("data_scientist")


def test_masks(eng):
    iban, card = eng.query("fraud_analyst", "SELECT iban, card_number FROM fraud_analyst.customers LIMIT 1")[0]
    assert set(iban[:-4]) == {"*"} and set(card[:-4]) == {"*"}
    name = eng.query("marketing", "SELECT full_name FROM marketing.customers LIMIT 1")[0][0]
    assert name.count(".") == 2 and len(name) == 5
    tk = eng.query("data_scientist", "SELECT tckn FROM data_scientist.customers LIMIT 1")[0][0]
    assert len(tk) == 16 and not tk.isdigit()


def test_row_filters(eng):
    cities = eng.query("support_istanbul", "SELECT DISTINCT city FROM support_istanbul.customers")
    assert cities == [("İstanbul",)]
    n_m = eng.query("marketing", "SELECT count(*) FROM marketing.customers")[0][0]
    n_c = eng.query("dpo", "SELECT count(*) FROM dpo.customers WHERE consent_marketing")[0][0]
    assert n_m == n_c


@pytest.mark.parametrize("sql", [
    "SELECT * FROM crm.customers", "SELECT * FROM customers", "SELECT * FROM dpo.customers",
    "SELECT * FROM read_csv('/etc/hosts')", "SELECT sql FROM duckdb_views()", "SELECT 1; DROP TABLE crm.customers",
    "SELECT count(*) FROM marketing.customers WHERE customer_id IN (SELECT customer_id FROM crm.customers)",
    "SET lock_configuration = false",
])
def test_bypass_attempts_denied(eng, sql):
    with pytest.raises(AccessDenied):
        eng.query("marketing", sql)
