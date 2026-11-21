"""Ranger-style column masking and row filtering on DuckDB.

Each role gets a secure view over the raw table: listed columns with their mask applied, a row
filter, and nothing else (default deny). Queries are checked before execution: every table they
reference must be the role's own view, so a role cannot read crm.customers directly. Every
attempt, allowed or denied, is appended to an audit log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path

import duckdb
import yaml

MASKS = {
    "NONE": "{c}",
    "MASK_SHOW_LAST_4": "regexp_replace(left(replace({c}, ' ', ''), length(replace({c}, ' ', '')) - 4), '[0-9A-Za-z]', '*', 'g')"
                        " || right(replace({c}, ' ', ''), 4)",
    "MASK_EMAIL": "left({c}, 2) || '***@' || split_part({c}, '@', 2)",
    "HASH": "sdai_hash(CAST({c} AS VARCHAR))",
    "INITIALS": "list_aggregate(list_transform(string_split({c}, ' '), lambda x: left(x, 1) || '.'), 'string_agg', ' ')",
    "YEAR_ONLY": "left(CAST({c} AS VARCHAR), 4)",
    "NULLIFY": "NULL",
}


class AccessDenied(Exception):
    pass


class PolicyEngine:
    def __init__(self, con: duckdb.DuckDBPyConnection, policy_file: str | Path, audit_file: str | Path | None = None):
        self.con = con
        self.policy = yaml.safe_load(Path(policy_file).read_text())
        self.schema, self.table = self.policy["table"].split(".")
        self.audit_file = Path(audit_file) if audit_file else None
        # The hash salt comes from the environment or is random per process; it is never stored.
        # It lives in a Python UDF, so it never appears in a view definition that a role could read.
        key = (os.environ.get("SDAI_HASH_SALT") or os.urandom(16).hex()).encode()
        con.create_function("sdai_hash", lambda v: hmac.new(key, v.encode(), hashlib.sha256).hexdigest()[:16],
                            ["VARCHAR"], "VARCHAR", side_effects=False)
        self.all_columns = [r[0] for r in con.execute(f"DESCRIBE {self.schema}.{self.table}").fetchall()]
        for role in self.policy["roles"]:
            con.execute(f"CREATE SCHEMA IF NOT EXISTS {role}")
            con.execute(f"CREATE OR REPLACE VIEW {role}.{self.table} AS {self.view_sql(role)}")

    def view_sql(self, role: str) -> str:
        rule = self.policy["roles"][role]
        cols = rule["columns"]
        exprs = []
        for c in self.all_columns:
            mask = cols.get(c, cols.get("*"))
            if mask is None:
                continue  # default deny: the column does not exist for this role
            exprs.append(MASKS[mask].format(c=c) + f" AS {c}")
        where = f" WHERE {rule['row_filter']}" if rule.get("row_filter") else ""
        return f"SELECT {', '.join(exprs)} FROM {self.schema}.{self.table}{where}"

    def visible_columns(self, role: str) -> list[str]:
        return [r[0] for r in self.con.execute(f"DESCRIBE {role}.{self.table}").fetchall()]

    def query(self, role: str, sql: str):
        entry = {"ts": time.time(), "role": role, "sql": sql}
        try:
            if role not in self.policy["roles"]:
                raise AccessDenied(f"unknown role {role}")
            check_statement(sql)
            tables = duckdb.get_table_names(sql, qualified=True)
            allowed = {f"{role}.{self.table}"}
            bad = {t for t in tables if t not in allowed}
            if bad:
                raise AccessDenied(f"{role} may only query {role}.{self.table}; referenced {sorted(bad)}")
            rows = self.con.execute(sql).fetchall()
            entry |= {"decision": "allow", "rows": len(rows)}
            return rows
        except AccessDenied as e:
            entry |= {"decision": "deny", "reason": str(e)}
            raise
        finally:
            if self.audit_file:
                with self.audit_file.open("a") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def check_statement(sql: str) -> None:
    """Only a single plain SELECT; no table functions (read_csv, duckdb_views, ...)."""
    tree = json.loads(duckdb.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0])
    if tree.get("error"):
        raise AccessDenied(f"only single SELECT statements are allowed ({tree.get('error_message', '')[:80]})")
    if len(tree["statements"]) != 1:
        raise AccessDenied("only one statement per query")
    for n in _walk(tree):
        if n.get("type") == "TABLE_FUNCTION":
            raise AccessDenied("table functions are not allowed")


def load_customers(con: duckdb.DuckDBPyConnection, rows: list[dict]) -> None:
    """Load synthetic customers into crm.customers, then switch off file and network access."""
    con.execute("CREATE SCHEMA IF NOT EXISTS crm")
    con.execute("""CREATE OR REPLACE TABLE crm.customers (customer_id INTEGER, full_name VARCHAR, tckn VARCHAR,
        phone VARCHAR, email VARCHAR, iban VARCHAR, card_number VARCHAR, city VARCHAR, birth_date DATE,
        segment VARCHAR, consent_marketing BOOLEAN, monthly_spend_try DOUBLE)""")
    import csv
    import tempfile
    cols = list(rows[0])
    with tempfile.NamedTemporaryFile("w", suffix=".csv", newline="", delete=False) as f:
        csv.DictWriter(f, cols).writerows(rows)
    con.execute(f"INSERT INTO crm.customers SELECT * FROM read_csv(?, header=false, columns={_types(con)})", [f.name])
    os.unlink(f.name)


def _types(con) -> dict:
    return {r[0]: r[1] for r in con.execute("DESCRIBE crm.customers").fetchall()}


def lock_down(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("SET enable_external_access = false")
    con.execute("SET lock_configuration = true")
