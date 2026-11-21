"""KVKK right to erasure (Law No. 6698, articles 7 and 11; Regulation on the Erasure, Destruction or
Anonymisation of Personal Data) for one data subject, across every store this repository writes to.

The hard part of erasure is not the DELETE, it is knowing every copy. This module models a small estate:

  crm.customers                 master record                         -> deleted
  care.call_notes               free-text notes filed under the       -> deleted; notes filed under someone
                                customer, sometimes mentioning others    else that mention the subject are redacted
  analytics.customer_snapshot   derived copy (CREATE TABLE AS)        -> deleted
  marketing.contact_list        exported copy for campaigns           -> deleted
  billing.invoices              records with a legal retention period -> kept, listed in the receipt with the
                                                                         date they become erasable
  RAG index                     ticket documents, PII pseudonymised   -> documents removed, index rebuilt
                                at ingest; a keyed subject index maps
                                customers to documents

Every request ends with a residual scan of all stores for the subject's identifiers (raw, digits-only and
pseudonymised forms) and a receipt that names the subject only by a keyed hash. The receipt and an entry in
the hash-chained audit log are the evidence that the request was handled.

What it does not cover is listed in the README: backups, replicas, the model's KV cache, logs outside this
estate, and storage-level residue. The retention periods here are examples, not legal advice.
"""
from __future__ import annotations

import hashlib
import hmac
import random
import re
import time
from dataclasses import dataclass, field
from datetime import date

import duckdb

from .audit import AuditLog
from .pii import pseudonym
from .policy import load_customers
from .rag import Doc, SecureRetriever

RETENTION_YEARS = {"billing.invoices": 10}  # e.g. Turkish Commercial Code art. 82; configure per legal advice
ERASED = "<ERASED>"
IDENTIFIERS = ("tckn", "phone", "email", "iban", "card_number")
NOTE_TEMPLATES = [
    "Customer called about the bill. ID {tckn}, callback on {phone}.",
    "Refund requested to {iban}. Confirmation sent to {email}.",
    "Line transfer: national id {tckn}, new number {phone_compact}, e-mail {email}.",
    "Roaming package for {email}. Verified identity with TCKN {tckn}.",
    "Card {card_number} reported lost; replacement posted.",
]


def digits(s: str) -> str:
    return re.sub(r"\D", "", s)


@dataclass
class Estate:
    con: duckdb.DuckDBPyConnection
    retriever: SecureRetriever
    subject_index: dict[str, set[str]] = field(default_factory=dict)
    key: bytes = b""

    def subject_key(self, customer_id: int) -> str:
        return hmac.new(self.key, str(customer_id).encode(), hashlib.sha256).hexdigest()[:16]


def build_estate(rows: list[dict], n_notes: int = 300_000, n_tickets: int = 5_000, seed: int = 3,
                 key: bytes = b"demo-subject-index-key") -> Estate:
    rng = random.Random(seed)
    con = duckdb.connect()
    load_customers(con, rows)
    con.execute("CREATE SCHEMA care; CREATE SCHEMA billing; CREATE SCHEMA analytics; CREATE SCHEMA marketing")
    notes = []
    for i in range(n_notes):
        c = rng.choice(rows)
        text = rng.choice(NOTE_TEMPLATES).format(**c, phone_compact=c["phone"].replace(" ", ""))
        if rng.random() < 0.05:  # a note about one customer that also names another (family line, payer)
            o = rng.choice(rows)
            text += f" Line is paid by another customer, phone {o['phone']}."
        notes.append((i + 1, c["customer_id"], text))
    con.execute("CREATE TABLE care.call_notes (note_id INTEGER, customer_id INTEGER, text VARCHAR)")
    _bulk(con, "care.call_notes", notes)
    con.execute("ALTER TABLE care.call_notes ADD COLUMN text_digits VARCHAR")
    con.execute("UPDATE care.call_notes SET text_digits = regexp_replace(text, '[^0-9]', '', 'g')")
    con.execute("""CREATE TABLE billing.invoices AS SELECT row_number() OVER () AS invoice_id, customer_id, full_name, tckn,
        round(monthly_spend_try * (0.9 + 0.2 * random()), 2) AS amount_try,
        DATE '2026-01-20' + INTERVAL (k * 30) DAY AS issued_on FROM crm.customers, range(2) t(k)""")
    con.execute("""CREATE TABLE analytics.customer_snapshot AS
        SELECT customer_id, email, city, segment, monthly_spend_try FROM crm.customers""")
    con.execute("""CREATE TABLE marketing.contact_list AS
        SELECT customer_id, full_name, email, phone FROM crm.customers WHERE consent_marketing""")
    docs, index = [], {}
    est = Estate(con, None, index, key)  # type: ignore[arg-type]
    for i in range(n_tickets):
        c = rng.choice(rows)
        docs.append(Doc(f"T{i:05d}", f"Ticket: customer {c['full_name']} from {c['city']}, TCKN {c['tckn']}, phone {c['phone']}, "
                                     f"IBAN {c['iban']}, asks about a refund.", "internal", c["segment"], c["city"], "billing"))
        index.setdefault(est.subject_key(c["customer_id"]), set()).add(docs[-1].doc_id)
    est.retriever = SecureRetriever(docs)
    return est


def _bulk(con, table, rows):
    import csv
    import os
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".csv", newline="", delete=False) as f:
        csv.writer(f).writerows(rows)
    types = {r[0]: r[1] for r in con.execute(f"DESCRIBE {table}").fetchall()}
    con.execute(f"INSERT INTO {table} SELECT * FROM read_csv(?, header=false, columns={types})", [f.name])
    os.unlink(f.name)


def identifiers(est: Estate, customer_id: int) -> dict | None:
    r = est.con.execute(f"SELECT {', '.join(IDENTIFIERS)} FROM crm.customers WHERE customer_id = ?", [customer_id]).fetchone()
    return dict(zip(IDENTIFIERS, r)) if r else None


def _note_match(ids: dict) -> tuple[str, list]:
    """Free text matches if it holds any identifier as written or, for numbers, as digits only (so
    '+90 532 111 22 33' and '05321112233' are the same phone). text_digits is a digits-only shadow column kept
    next to the note, so the scan is a substring search rather than a regex over every row."""
    conds, params = [], []
    for k, v in ids.items():
        conds.append("contains(text, ?)"); params.append(v)
        if k in ("tckn", "phone", "iban", "card_number"):
            conds.append("contains(text_digits, ?)"); params.append(digits(v)[-10:] if k == "phone" else digits(v))
    return ("(" + " OR ".join(conds) + ")") if conds else "FALSE", params


# Structured copies: identifier columns are compared for equality, plus the customer id.
STRUCTURED = {"crm.customers": ["tckn", "phone", "email", "iban", "card_number"], "billing.invoices": ["tckn"],
              "analytics.customer_snapshot": ["email"], "marketing.contact_list": ["email", "phone"]}


def scan(est: Estate, customer_id: int, ids: dict) -> dict:
    """Rows or documents in each store that still hold the subject's identifiers or customer id."""
    hits = {}
    for table, cols in STRUCTURED.items():
        cols = [c for c in cols if c in ids]
        cond = "".join(f" OR {c} = ?" for c in cols)
        hits[table] = est.con.execute(f"SELECT count(*) FROM {table} WHERE customer_id = ?{cond}",
                                      [customer_id] + [ids[c] for c in cols]).fetchone()[0]
    cond, params = _note_match(ids)
    hits["care.call_notes"] = est.con.execute(f"SELECT count(*) FROM care.call_notes WHERE customer_id = ? OR {cond}",
                                              [customer_id] + params).fetchone()[0]
    tokens = [pseudonym(ids[k], k.upper()) for k in ("tckn", "phone", "iban", "email") if k in ids]
    mine = est.subject_index.get(est.subject_key(customer_id), set())
    hits["rag.index"] = sum(any(t in d.text for t in tokens) or d.doc_id in mine for d in est.retriever.docs)
    return hits


def shared_identifiers(est: Estate, customer_id: int, ids: dict) -> dict:
    """Identifiers that also belong to another customer record (a family e-mail, a reused phone). Matching on
    them would erase someone else's data, so they are left out of matching and flagged for manual review."""
    out = {}
    for k, v in ids.items():
        n = est.con.execute(f"SELECT count(*) FROM crm.customers WHERE {k} = ? AND customer_id <> ?", [v, customer_id]).fetchone()[0]
        if n:
            out[k] = n
    return out


def erase(est: Estate, customer_id: int, requested_by: str, audit: AuditLog | None = None,
          today: date = date(2026, 11, 21)) -> dict:
    t0 = time.perf_counter()
    ids = identifiers(est, customer_id)
    subject_ref = pseudonym(str(customer_id), "SUBJECT")
    if ids is None:
        receipt = {"subject_ref": subject_ref, "status": "not_found"}
        if audit:
            audit.append(requested_by, "dpo", "kvkk.erasure", "deny", "subject not found", {"subject_ref": subject_ref})
        return receipt
    shared = shared_identifiers(est, customer_id, ids)
    own = {k: v for k, v in ids.items() if k not in shared}
    before = scan(est, customer_id, own)
    c = est.con
    actions = {}
    c.execute("BEGIN")
    actions["care.call_notes.deleted"] = c.execute("DELETE FROM care.call_notes WHERE customer_id = ?", [customer_id]).fetchone()[0]
    cond, params = _note_match(own)
    other = c.execute(f"SELECT note_id, text FROM care.call_notes WHERE {cond}", params).fetchall()
    for note_id, text in other:
        for k, v in own.items():
            text = text.replace(v, ERASED)
            if k == "phone":
                text = text.replace(v.replace(" ", ""), ERASED)
        c.execute("UPDATE care.call_notes SET text = ?, text_digits = regexp_replace(?, '[^0-9]', '', 'g') WHERE note_id = ?",
                  [text, text, note_id])
    actions["care.call_notes.redacted"] = len(other)
    for t in ("analytics.customer_snapshot", "marketing.contact_list", "crm.customers"):
        actions[t + ".deleted"] = c.execute(f"DELETE FROM {t} WHERE customer_id = ?", [customer_id]).fetchone()[0]
    held = c.execute("SELECT count(*), max(issued_on) FROM billing.invoices WHERE customer_id = ?", [customer_id]).fetchone()
    c.execute("COMMIT")
    sk = est.subject_key(customer_id)
    gone = est.subject_index.pop(sk, set())
    if gone:
        est.retriever.docs = [d for d in est.retriever.docs if d.doc_id not in gone]
        est.retriever.index = type(est.retriever.index)(est.retriever.docs)
    actions["rag.documents.removed"] = len(gone)
    after = scan(est, customer_id, own)
    retained = {"billing.invoices": {"rows": held[0], "basis": "legal retention obligation (KVKK art. 5(2)(ç))",
                                     "erasable_from": str(date(held[1].year + RETENTION_YEARS["billing.invoices"],
                                                               held[1].month, held[1].day)) if held[0] else None}}
    residual = {k: v for k, v in after.items() if v and k not in retained}
    receipt = {"subject_ref": subject_ref, "status": "erased" if not residual else "incomplete",
               "shared_identifiers_needing_review": shared,
               "requested_by": requested_by, "completed_on": str(today), "found_before": before, "actions": actions,
               "retained": retained, "residual_after": after, "residual_outside_retention": residual,
               "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1)}
    if audit:
        audit.append(requested_by, "dpo", "kvkk.erasure", "allow" if not residual else "error",
                     "" if not residual else "residual data found",
                     {"subject_ref": subject_ref, "actions": actions, "retained_rows": held[0],
                      "review": sorted(shared)})
    return receipt
