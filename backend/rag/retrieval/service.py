from __future__ import annotations

from sqlalchemy.orm import Session

from rag.embeddings import embed_texts
from rag.settings import RAG_RETRIEVAL_BACKEND
from observability import observe, rag_stage_duration, span
import time


def backend_name(db: Session) -> str:
    configured = RAG_RETRIEVAL_BACKEND
    if configured == "sqlite":
        return "sqlite"
    if configured == "postgres":
        return "postgres" if db.bind.dialect.name == "postgresql" else "unavailable"
    return "postgres" if db.bind.dialect.name == "postgresql" else "sqlite"


def retrieve(db: Session, query: str, criteria: dict | None = None, k: int = 20):
    started = time.monotonic()
    with span("rag.query_embedding", stage="embedding", model="local-bge"):
        embedding = embed_texts([query])[0]
    observe(rag_stage_duration, time.monotonic() - started, "embedding")
    backend = backend_name(db)
    if backend == "postgres":
        from rag.retrieval.postgres import retrieve as postgres_retrieve
        return postgres_retrieve(db, query, embedding, criteria, k)
    if backend == "sqlite":
        from rag.retrieval.sqlite_fallback import retrieve as sqlite_retrieve
        return sqlite_retrieve(db, query, embedding, criteria, k)
    raise RuntimeError("Configured PostgreSQL retrieval backend is unavailable")


def capability(db: Session) -> dict:
    if db.bind.dialect.name == "postgresql":
        from rag.retrieval.postgres import capability as postgres_capability
        return postgres_capability(db)
    from rag.retrieval.sqlite_fallback import capability as sqlite_capability
    return sqlite_capability(db)
