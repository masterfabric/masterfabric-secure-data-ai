"""Precision and recall of the PII detector on labelled synthetic notes, with and without checksums."""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sdai.notes import notes  # noqa: E402
from sdai.pii import detect, mask_text  # noqa: E402

KINDS = ["TCKN", "IBAN", "CARD", "PHONE", "EMAIL"]


def score(docs, validate):
    tp, fp, fn = Counter(), Counter(), Counter()
    for d in docs:
        gold = {(l["start"], l["end"], l["kind"]) for l in d["labels"]}
        pred = {(s.start, s.end, s.kind) for s in detect(d["text"], validate=validate)}
        for k in KINDS:
            g, p = {x for x in gold if x[2] == k}, {x for x in pred if x[2] == k}
            tp[k] += len(g & p); fp[k] += len(p - g); fn[k] += len(g - p)
    rows = {}
    for k in KINDS + ["ALL"]:
        t = sum(tp.values()) if k == "ALL" else tp[k]
        f_p = sum(fp.values()) if k == "ALL" else fp[k]
        f_n = sum(fn.values()) if k == "ALL" else fn[k]
        rows[k] = {"tp": t, "fp": f_p, "fn": f_n, "precision": round(t / (t + f_p), 4) if t + f_p else None,
                   "recall": round(t / (t + f_n), 4) if t + f_n else None}
    return rows


def main():
    docs = notes(2000)
    t0 = time.perf_counter()
    masked = [mask_text(d["text"]) for d in docs]
    dt = time.perf_counter() - t0
    leaks = sum(1 for d, m in zip(docs, masked) for l in d["labels"] if d["text"][l["start"]:l["end"]] in m)
    out = {"notes": len(docs), "entities": sum(len(d["labels"]) for d in docs),
           "with_checksum": score(docs, True), "pattern_only": score(docs, False),
           "mask_notes_per_s": round(len(docs) / dt), "entities_left_unmasked": leaks,
           "example": {"original": docs[3]["text"], "redact": masked[3], "partial": mask_text(docs[3]["text"], "partial")}}
    Path("results").mkdir(exist_ok=True)
    Path("results/pii_eval.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
    for mode in ("with_checksum", "pattern_only"):
        print(mode, {k: (v["precision"], v["recall"]) for k, v in out[mode].items()})
    print("masked notes/s", out["mask_notes_per_s"], "left unmasked", leaks)


if __name__ == "__main__":
    main()
