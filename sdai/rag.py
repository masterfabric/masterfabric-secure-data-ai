"""Permission-aware retrieval for RAG.

Documents carry ACL metadata (classification, tenant, region). PII is masked at ingest, before
anything is indexed, so even an authorised reader gets pseudonyms rather than identifiers. Retrieval
filters by the caller's attributes *before* ranking (pre-filter); the alternatives measured in
eval/rag_eval.py are no filter and post-filtering the top-k.
"""
from __future__ import annotations

import math
import random
import re
from collections import Counter
from dataclasses import dataclass, field

from .pii import mask_text
from .synth import customers

LEVELS = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
TOPICS = {
    "billing": "invoice overcharge bill payment late fee refund",
    "roaming": "roaming package abroad data charges travel",
    "fiber": "fiber installation modem outage speed technician",
    "porting": "number porting operator transfer line",
    "fraud": "fraud suspicious transaction card blocked chargeback",
    "contract": "contract renewal discount commitment cancellation",
}


@dataclass
class Doc:
    doc_id: str
    text: str
    classification: str
    tenant: str
    region: str
    topic: str


@dataclass
class Principal:
    name: str
    clearance: str
    tenants: set = field(default_factory=lambda: {"*"})
    regions: set = field(default_factory=lambda: {"*"})

    def can_read(self, d: Doc) -> bool:
        return (LEVELS[d.classification] <= LEVELS[self.clearance]
                and ("*" in self.tenants or d.tenant in self.tenants)
                and ("*" in self.regions or d.region in self.regions or d.classification == "public"))


PRINCIPALS = [
    Principal("public_chatbot", "public"),
    Principal("support_istanbul", "internal", {"consumer"}, {"İstanbul"}),
    Principal("business_desk", "confidential", {"business"}),
    Principal("fraud_team", "restricted"),
]


def corpus(n_tickets: int = 400, seed: int = 5) -> list[Doc]:
    rng = random.Random(seed)
    people = customers(n_tickets, seed=seed)
    docs = []
    for i, c in enumerate(people):
        topic = rng.choice(list(TOPICS))
        words = TOPICS[topic].split()
        cls = "restricted" if topic == "fraud" else rng.choice(["internal", "internal", "confidential"])
        text = (f"Ticket about {topic}: customer {c['full_name']} from {c['city']} reports {' '.join(rng.sample(words, 3))}. "
                f"TCKN {c['tckn']}, phone {c['phone']}, IBAN {c['iban']}. Agent noted {' '.join(rng.sample(words, 2))}.")
        docs.append(Doc(f"T{i:04d}", text, cls, c["segment"], c["city"], topic))
    for j, (topic, words) in enumerate(TOPICS.items()):
        docs.append(Doc(f"KB{j:02d}", f"Help article on {topic}: how to handle {words}.", "public", "*", "*", topic))
    return docs


TOKEN = re.compile(r"\w+", re.UNICODE)


class BM25:
    def __init__(self, docs: list[Doc], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.toks = [Counter(TOKEN.findall(d.text.lower())) for d in docs]
        self.len = [sum(t.values()) for t in self.toks]
        self.avg = sum(self.len) / len(self.len)
        df = Counter(w for t in self.toks for w in t)
        n = len(docs)
        self.idf = {w: math.log(1 + (n - f + 0.5) / (f + 0.5)) for w, f in df.items()}
        self.k1, self.b = k1, b

    def scores(self, query: str, allowed=None) -> list[tuple[float, int]]:
        q = TOKEN.findall(query.lower())
        out = []
        for i, t in enumerate(self.toks):
            if allowed is not None and not allowed(self.docs[i]):
                continue
            s = sum(self.idf.get(w, 0) * t[w] * (self.k1 + 1) / (t[w] + self.k1 * (1 - self.b + self.b * self.len[i] / self.avg))
                    for w in q if w in t)
            if s > 0:
                out.append((s, i))
        return sorted(out, reverse=True)


class SecureRetriever:
    def __init__(self, docs: list[Doc], mask: bool = True, audit=None):
        self.audit = audit  # optional sdai.audit.AuditLog: every search is recorded with the query PII-masked
        self.docs = [Doc(d.doc_id, mask_text(d.text, "pseudonymize") if mask else d.text, d.classification, d.tenant,
                         d.region, d.topic) for d in docs]
        self.index = BM25(self.docs)

    def search(self, who: Principal, query: str, k: int = 5, mode: str = "pre") -> list[Doc]:
        if mode == "none":
            hits = self.index.scores(query)[:k]
        elif mode == "post":
            hits = [h for h in self.index.scores(query)[:k] if who.can_read(self.docs[h[1]])]
        else:
            hits = self.index.scores(query, allowed=who.can_read)[:k]
        if self.audit is not None:
            self.audit.append(who.name, who.clearance, "rag.search", "allow", "",
                              {"query": query[:200], "mode": mode, "returned": len(hits)})
        return [self.docs[i] for _, i in hits]
