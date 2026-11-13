"""Opt-in PostgreSQL/pgvector checks.

Run with ``RAG_POSTGRES_TEST_URL`` pointing at an isolated test database.
These tests never use the application's configured database implicitly.
"""
from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from migrations import _migration_1, _migration_2, _migration_3, _migration_4
from rag.retrieval.postgres import retrieve

pytestmark = pytest.mark.skipif(
    not os.environ.get("RAG_POSTGRES_TEST_URL"),
    reason="set RAG_POSTGRES_TEST_URL to run PostgreSQL/pgvector integration tests",
)


def test_pgvector_extension_fts_and_indexes():
    engine = create_engine(os.environ["RAG_POSTGRES_TEST_URL"])
    with engine.begin() as connection:
        _migration_1(connection)
        _migration_2(connection)
        _migration_3(connection)
        _migration_4(connection)
    with engine.connect() as connection:
        assert connection.execute(text(
            "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')"
        )).scalar()
        assert connection.execute(text(
            "SELECT to_tsvector('simple', 'CVE remediation') @@ plainto_tsquery('simple', 'remediation')"
        )).scalar()
        indexes = {
            row[0] for row in connection.execute(text(
                "SELECT indexname FROM pg_indexes WHERE tablename='rag_index_records'"
            ))
        }
        assert "ix_rag_records_vector_hnsw" in indexes
        assert "ix_rag_records_fts" in indexes


def test_persistent_dense_fts_and_sql_filter_retrieval():
    engine = create_engine(os.environ["RAG_POSTGRES_TEST_URL"])
    source_id = "integration-source"
    vector = "[" + ",".join(["1"] + ["0"] * 767) + "]"
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM rag_index_records WHERE source_id=:source_id"), {"source_id": source_id})
        connection.execute(text("""
            INSERT INTO rag_index_records
              (source_type, source_id, chunk_index, content_hash, title, content, metadata,
               embedding, embedding_model, embedding_dimension, embedding_implementation, indexed_at)
            VALUES ('integration', :source_id, 0, 'integration-hash', 'SQL injection remediation',
                    'SQL injection remediation guidance', CAST(:metadata AS jsonb),
                    CAST(:embedding AS vector), 'integration', 768, 'test', now())
        """), {"source_id": source_id, "metadata": '{"severity":"critical","source_id_original":"integration:source"}', "embedding": vector})
    session = sessionmaker(bind=engine)()
    try:
        results = retrieve(session, "SQL injection remediation", [1.0] + [0.0] * 767, {"severity": "critical"}, k=5)
        assert results and results[0][0]["id"] == "integration:source"
    finally:
        session.close()
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM rag_index_records WHERE source_id=:source_id"), {"source_id": source_id})


def test_prior_schema_migration_and_worker_heartbeat_table():
    engine = create_engine(os.environ["RAG_POSTGRES_TEST_URL"])
    with engine.connect() as connection:
        assert connection.execute(text(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='worker_heartbeats')"
        )).scalar()
        assert connection.execute(text(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='assistant_conversations')"
        )).scalar()
