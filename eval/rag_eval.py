"""Leakage and recall of RAG retrieval with no filter, post-filter and pre-filter, on raw vs masked text."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sdai.pii import detect  # noqa: E402
from sdai.rag import PRINCIPALS, TOPICS, SecureRetriever, corpus  # noqa: E402


def main(n_queries: int = 300, k: int = 5):
    docs = corpus()
    rng = random.Random(3)
    targets = rng.sample([d for d in docs if d.doc_id.startswith("T")], n_queries)
    raw, masked = SecureRetriever(docs, mask=False), SecureRetriever(docs, mask=True)
    out = {"docs": len(docs), "queries_per_principal": n_queries, "k": k, "modes": {}}
    for mode in ("none", "post", "pre"):
        for idx_name, idx in (("raw", raw), ("masked", masked)):
            per = {}
            for who in PRINCIPALS:
                unauthorized = pii = returned = hit = eligible = 0
                for t in targets:
                    name = t.text.split("customer ")[1].split(" from")[0]
                    q = f"{t.topic} {' '.join(TOPICS[t.topic].split()[:2])} {name} {t.region}"
                    res = idx.search(who, q, k, mode)
                    returned += len(res)
                    unauthorized += sum(not who.can_read(d) for d in res)
                    pii += sum(len(detect(d.text)) for d in res if who.can_read(d) or mode == "none")
                    if who.can_read(t):
                        eligible += 1
                        hit += any(d.doc_id == t.doc_id for d in res)
                per[who.name] = {"results": returned, "unauthorized": unauthorized,
                                 "unauthorized_rate": round(unauthorized / max(returned, 1), 4),
                                 "pii_entities_in_context": pii, "avg_results": round(returned / n_queries, 2),
                                 "eligible_targets": eligible, "recall_at_k": round(hit / eligible, 4) if eligible else None}
            out["modes"][f"{mode}_{idx_name}"] = per
    Path("results/rag_eval.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
    for m, per in out["modes"].items():
        print(m, {p: (v["unauthorized"], v["pii_entities_in_context"], v["avg_results"], v["recall_at_k"]) for p, v in per.items()})


if __name__ == "__main__":
    main()
