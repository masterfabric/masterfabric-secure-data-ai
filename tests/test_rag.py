from sdai.pii import detect
from sdai.rag import PRINCIPALS, SecureRetriever, corpus

DOCS = corpus(120)
R = SecureRetriever(DOCS)


def test_no_pii_survives_ingest():
    assert all(not detect(d.text) for d in R.docs)


def test_prefilter_never_returns_unreadable_docs():
    for who in PRINCIPALS:
        for q in ("fraud card blocked", "roaming abroad İstanbul", "invoice refund Ankara", "fiber outage"):
            assert all(who.can_read(d) for d in R.search(who, q, 10))


def test_public_bot_sees_only_help_articles():
    res = R.search(PRINCIPALS[0], "invoice refund fraud card", 10)
    assert res and all(d.doc_id.startswith("KB") for d in res)


def test_unfiltered_search_would_leak():
    assert any(not PRINCIPALS[0].can_read(d) for d in R.search(PRINCIPALS[0], "fraud card blocked", 5, mode="none"))
