from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from migrations import _migration_2
from models.database import Base
from rag.indexing import service
from rag.indexing.sources import content_hash
from rag.retrieval.postgres import _where
from rag.retrieval.sqlite_fallback import retrieve as sqlite_retrieve


def _db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        _migration_2(connection)
    return sessionmaker(bind=engine)()


def test_content_hash_is_deterministic_and_metadata_sensitive():
    document = {"id": "cve:X", "title": "Title", "text": "same text", "metadata": {"severity": "high"}}
    assert content_hash(document) == content_hash(dict(document))
    changed = {**document, "metadata": {"severity": "critical"}}
    assert content_hash(document) != content_hash(changed)


def test_incremental_index_reuses_and_tombstones(monkeypatch):
    db = _db()
    documents = [{"id": "cve:X", "source": "CVE", "title": "X", "text": "alpha", "metadata": {}}]
    monkeypatch.setattr(service, "build_corpus", lambda db: documents)
    monkeypatch.setattr(service, "embed_texts", lambda texts, batch_size=64: [[1.0, 0.0] for _ in texts])
    monkeypatch.setattr(
        service, "active_embedding_metadata",
        lambda: {"provider": "test", "model": "test", "revision": "1", "dimension": 2, "implementation": "test"},
    )
    first = service.index_incremental(db, full=True)
    second = service.index_incremental(db, full=True)
    assert first["added"] == 1
    assert second["unchanged"] == 1
    documents.clear()
    deleted = service.index_incremental(db, full=True)
    assert deleted["deleted"] == 1


def test_postgres_filter_is_parameterized():
    clause, params = _where({"severity": "critical", "port": 443, "vm": "10.0.0.1"})
    assert ":severity" in clause and ":port" in clause and ":vm" in clause
    assert params == {"severity": "critical", "port": "443", "vm": "10.0.0.1"}


def test_sqlite_fallback_returns_persisted_evidence(monkeypatch):
    db = _db()
    monkeypatch.setattr(service, "build_corpus", lambda db: [{
        "id": "cve:X", "source": "CVE", "title": "SQL injection", "text": "SQL injection remediation",
        "metadata": {"document_type": "CVE"},
    }])
    monkeypatch.setattr(service, "embed_texts", lambda texts, batch_size=64: [[1.0, 0.0] for _ in texts])
    monkeypatch.setattr(
        service, "active_embedding_metadata",
        lambda: {"provider": "test", "model": "test", "revision": "1", "dimension": 2, "implementation": "test"},
    )
    service.index_incremental(db)
    results = sqlite_retrieve(db, "SQL injection", [1.0, 0.0], k=1)
    assert results and results[0][0]["id"] == "cve:X"
