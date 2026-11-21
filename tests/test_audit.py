import json

from sdai.audit import AuditLog, verify


def _log(tmp_path, n=5):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(n):
        log.append("u1", "support_istanbul", "sql.query", "allow", detail={"rows": i})
    return log


def test_clean_chain_verifies(tmp_path):
    log = _log(tmp_path)
    r = log.verify()
    assert r.ok and r.entries == 5


def test_reopen_continues_chain(tmp_path):
    _log(tmp_path, 3)
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("u2", "dpo", "erasure", "allow")
    assert log.verify().ok and log.verify().entries == 4


def test_edit_is_detected(tmp_path):
    log = _log(tmp_path)
    lines = log.path.read_text().splitlines()
    e = json.loads(lines[2]); e["decision"] = "deny"; lines[2] = json.dumps(e)
    log.path.write_text("\n".join(lines) + "\n")
    r = log.verify()
    assert not r.ok and r.first_bad_seq == 3


def test_deletion_is_detected(tmp_path):
    log = _log(tmp_path)
    lines = log.path.read_text().splitlines()
    del lines[1]
    log.path.write_text("\n".join(lines) + "\n")
    assert verify(log.path).first_bad_seq == 2


def test_truncation_needs_the_anchor(tmp_path):
    log = _log(tmp_path)
    lines = log.path.read_text().splitlines()[:3]
    log.path.write_text("\n".join(lines) + "\n")
    assert verify(log.path).ok  # the chain alone cannot see a cut tail
    assert not verify(log.path, log.anchor).ok


def test_pii_is_masked_before_writing(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("u", "dpo", "sql.query", "allow", detail={"sql": "SELECT * FROM x WHERE tckn = '10000000146'"})
    assert "10000000146" not in log.path.read_text()
