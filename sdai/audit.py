"""Tamper-evident audit log: append-only JSON lines, each entry chained to the previous one by SHA-256.

Every entry stores the hash of the entry before it, and its own hash covers all of its fields. Editing or
deleting a line breaks the chain at that point; verify() reports where. Cutting lines off the end leaves a
valid chain, so the head (sequence number and last hash) is also written to a separate anchor file, which
in production would live somewhere the writer cannot rewrite (WORM bucket, another team's system). Free
text is PII-masked before it is written, so the log itself does not become a second copy of personal data.

This is evidence of tampering, not prevention: someone with write access to both files can rebuild the
whole chain. Signing the anchor or shipping it off-host closes that gap; neither is done here.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .pii import mask_text

GENESIS = "0" * 64
FIELDS = ("seq", "ts", "actor", "role", "action", "decision", "reason", "detail", "prev")


def _digest(entry: dict) -> str:
    body = json.dumps({k: entry.get(k) for k in FIELDS}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


@dataclass
class Report:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    problem: str = ""


class AuditLog:
    def __init__(self, path: str | Path, anchor: str | Path | None = None, clock=time.time):
        self.path = Path(path)
        self.anchor = Path(anchor) if anchor else self.path.with_suffix(".anchor")
        self.clock = clock
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq, self.prev = 0, GENESIS
        if self.path.exists() and self.path.stat().st_size:
            last = json.loads(self.path.read_text().splitlines()[-1])
            self.seq, self.prev = last["seq"], last["hash"]
        # Handles stay open: opening a file costs about 1 ms on the test Mac, ten times the rest of an append.
        # Each append is flushed to the OS but not fsync'ed; a power cut can lose the last entries (README).
        self._log = self.path.open("a", buffering=1)
        self._anchor = self.anchor.open("a+")

    def append(self, actor: str, role: str, action: str, decision: str, reason: str = "", detail: dict | None = None,
               ts: float | None = None) -> dict:
        detail = {k: mask_text(v) if isinstance(v, str) else v for k, v in (detail or {}).items()}
        with self._lock:
            e = {"seq": self.seq + 1, "ts": round(self.clock() if ts is None else ts, 3), "actor": actor, "role": role,
                 "action": action, "decision": decision, "reason": mask_text(reason), "detail": detail,
                 "prev": self.prev}
            e["hash"] = _digest(e)
            self._log.write(json.dumps(e, ensure_ascii=False) + "\n")
            self._anchor.seek(0); self._anchor.truncate()
            self._anchor.write(json.dumps({"seq": e["seq"], "hash": e["hash"]})); self._anchor.flush()
            self.seq, self.prev = e["seq"], e["hash"]
        return e

    def close(self) -> None:
        self._log.close(); self._anchor.close()

    def entries(self) -> list[dict]:
        return [json.loads(line) for line in self.path.read_text().splitlines()] if self.path.exists() else []

    def verify(self) -> Report:
        return verify(self.path, self.anchor)


def verify(path: str | Path, anchor: str | Path | None = None) -> Report:
    path = Path(path)
    lines = path.read_text().splitlines() if path.exists() else []
    prev, n = GENESIS, 0
    for n, line in enumerate(lines, 1):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            return Report(False, n - 1, n, "line is not JSON")
        if e.get("seq") != n:
            return Report(False, n - 1, n, f"sequence gap: expected {n}, found {e.get('seq')}")
        if e.get("prev") != prev:
            return Report(False, n - 1, n, "previous-hash link broken")
        if _digest(e) != e.get("hash"):
            return Report(False, n - 1, n, "entry content does not match its hash")
        prev = e["hash"]
    if anchor and Path(anchor).exists():
        a = json.loads(Path(anchor).read_text())
        if a["seq"] != len(lines) or a["hash"] != prev:
            return Report(False, len(lines), len(lines) + 1 if a["seq"] > len(lines) else a["seq"],
                          f"anchor says {a['seq']} entries, log has {len(lines)} (truncated or rewritten)")
    return Report(True, len(lines))
