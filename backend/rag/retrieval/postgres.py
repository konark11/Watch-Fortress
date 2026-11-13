from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from rag.indexing.repository import _row_to_doc
from rag.settings import (
    FUSION_K, LEXICAL_CANDIDATE_K, RRF_K, VECTOR_CANDIDATE_K,
)
from observability import observe, rag_stage_duration, retrieval_candidates, span
import time


def _where(criteria: dict | None) -> tuple[str, dict]:
    clauses = ["deleted_at IS NULL", "embedding IS NOT NULL"]
    params: dict = {}
    if not criteria:
        return " AND ".join(clauses), params
    if criteria.get("document_type"):
        clauses.append("(metadata ->> 'document_type' = :document_type OR source_type = :document_type_key)")
        params["document_type"] = criteria["document_type"]
        params["document_type_key"] = str(criteria["document_type"]).lower()
    if criteria.get("severity"):
        clauses.append("metadata ->> 'severity' = :severity")
        params["severity"] = criteria["severity"]
    if criteria.get("port") is not None:
        clauses.append("metadata ->> 'port' = :port")
        params["port"] = str(criteria["port"])
    if criteria.get("vm"):
        clauses.append("metadata ->> 'vm' = :vm")
        params["vm"] = criteria["vm"]
    if criteria.get("cve"):
        clauses.append("(title ILIKE :cve OR content ILIKE :cve)")
        params["cve"] = f"%{criteria['cve']}%"
    return " AND ".join(clauses), params


def retrieve(db: Session, query: str, embedding: list[float], criteria: dict | None = None, k: int = FUSION_K):
    where, params = _where(criteria)
    vector_params = dict(params, query_embedding="[" + ",".join(str(float(v)) for v in embedding) + "]", query=query)
    dense_started = time.monotonic()
    with span("rag.postgres_vector_retrieval", backend="postgres", stage="vector"):
        dense = db.execute(text(f"""
        SELECT * FROM rag_index_records
        WHERE {where}
        ORDER BY embedding <=> CAST(:query_embedding AS vector)
        LIMIT {int(VECTOR_CANDIDATE_K)}
    """), vector_params).fetchall()
    observe(rag_stage_duration, time.monotonic() - dense_started, "vector_retrieval")
    observe(retrieval_candidates, len(dense), "vector", "postgres")
    lexical_started = time.monotonic()
    with span("rag.postgres_full_text_retrieval", backend="postgres", stage="full_text"):
        lexical = db.execute(text(f"""
        SELECT *, ts_rank_cd(
          to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(content, '')),
          plainto_tsquery('simple', :query)
        ) AS lexical_score
        FROM rag_index_records
        WHERE {where} AND to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(content, ''))
          @@ plainto_tsquery('simple', :query)
        ORDER BY lexical_score DESC, source_type, source_id, chunk_index
        LIMIT {int(LEXICAL_CANDIDATE_K)}
    """), vector_params).fetchall()
    observe(rag_stage_duration, time.monotonic() - lexical_started, "full_text_retrieval")
    observe(retrieval_candidates, len(lexical), "full_text", "postgres")
    by_id: dict[str, tuple[dict, float]] = {}
    for rank, row in enumerate(dense, 1):
        doc = _row_to_doc(row, True)
        by_id[doc["id"]] = (doc, 1 / (RRF_K + rank))
    for rank, row in enumerate(lexical, 1):
        doc = _row_to_doc(row, True)
        current = by_id.get(doc["id"])
        by_id[doc["id"]] = (doc, (current[1] if current else 0) + 1 / (RRF_K + rank))
    with span("rag.fusion", stage="fusion", backend="postgres"):
        fused = sorted(by_id.values(), key=lambda item: (-item[1], item[0]["id"]))[:k]
    observe(retrieval_candidates, len(fused), "fusion", "postgres")
    return fused


def capability(db: Session) -> dict:
    try:
        extension = db.execute(text(
            "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')"
        )).scalar()
        return {"database": "postgresql", "vector_extension": bool(extension), "available": bool(extension)}
    except Exception:
        return {"database": "postgresql", "vector_extension": False, "available": False}
