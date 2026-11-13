from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session


def _postgres(db: Session) -> bool:
    return db.bind.dialect.name == "postgresql"


def _row_to_doc(row: Any, postgres: bool) -> dict:
    metadata = row.metadata
    if isinstance(metadata, str):
        metadata = json.loads(metadata or "{}")
    vector = row.embedding if postgres else json.loads(row.embedding_json or "null")
    return {
        "id": metadata.get("source_id_original") or (
            f"{row.source_type}:{row.source_id}" if row.chunk_index == 0
            else f"{row.source_type}:{row.source_id}:{row.chunk_index}"
        ),
        "source": metadata.get("source", row.source_type),
        "title": row.title,
        "text": row.content,
        "metadata": metadata,
        "embedding": vector,
        "index_score": 0.0,
    }


def get_record(db: Session, source_type: str, source_id: str, chunk_index: int):
    return db.execute(text(
        "SELECT * FROM rag_index_records "
        "WHERE source_type=:source_type AND source_id=:source_id AND chunk_index=:chunk_index"
    ), {"source_type": source_type, "source_id": source_id, "chunk_index": chunk_index}).mappings().first()


def save_record(db: Session, document: dict, vector: list[float], provenance: dict, digest: str) -> None:
    from rag.indexing.sources import source_parts
    source_type, source_id, chunk_index = source_parts(document)
    metadata = dict(document.get("metadata") or {})
    metadata["source"] = document.get("source", source_type)
    metadata["source_id_original"] = document["id"]
    values = {
        "source_type": source_type, "source_id": source_id, "chunk_index": chunk_index,
        "content_hash": digest, "title": str(document.get("title", ""))[:500],
        "content": str(document.get("text", "")), "metadata": json.dumps(metadata, sort_keys=True),
        "model": provenance["model"], "revision": provenance.get("revision"),
        "dimension": provenance["dimension"], "implementation": provenance["implementation"],
        "indexed_at": datetime.now(timezone.utc), "embedding": json.dumps(vector),
    }
    if _postgres(db):
        db.execute(text("""
            INSERT INTO rag_index_records
              (source_type, source_id, chunk_index, content_hash, title, content, metadata,
               embedding, embedding_model, embedding_revision, embedding_dimension,
               embedding_implementation, indexed_at, deleted_at)
            VALUES
              (:source_type, :source_id, :chunk_index, :content_hash, :title, :content,
               CAST(:metadata AS jsonb), CAST(:embedding AS vector), :model, :revision,
               :dimension, :implementation, :indexed_at, NULL)
            ON CONFLICT (source_type, source_id, chunk_index) DO UPDATE SET
              content_hash=EXCLUDED.content_hash, title=EXCLUDED.title, content=EXCLUDED.content,
              metadata=EXCLUDED.metadata, embedding=EXCLUDED.embedding,
              embedding_model=EXCLUDED.embedding_model, embedding_revision=EXCLUDED.embedding_revision,
              embedding_dimension=EXCLUDED.embedding_dimension,
              embedding_implementation=EXCLUDED.embedding_implementation,
              indexed_at=EXCLUDED.indexed_at, deleted_at=NULL
        """), values)
    else:
        db.execute(text("""
            INSERT INTO rag_index_records
              (source_type, source_id, chunk_index, content_hash, title, content, metadata,
               embedding_json, embedding_model, embedding_revision, embedding_dimension,
               embedding_implementation, indexed_at, deleted_at)
            VALUES (:source_type, :source_id, :chunk_index, :content_hash, :title, :content,
                    :metadata, :embedding, :model, :revision, :dimension, :implementation,
                    :indexed_at, NULL)
            ON CONFLICT (source_type, source_id, chunk_index) DO UPDATE SET
              content_hash=excluded.content_hash, title=excluded.title, content=excluded.content,
              metadata=excluded.metadata, embedding_json=excluded.embedding_json,
              embedding_model=excluded.embedding_model, embedding_revision=excluded.embedding_revision,
              embedding_dimension=excluded.embedding_dimension,
              embedding_implementation=excluded.embedding_implementation,
              indexed_at=excluded.indexed_at, deleted_at=NULL
        """), values)


def active_records(db: Session, filters: list[str] | None = None, params: dict | None = None) -> list[dict]:
    where = ["deleted_at IS NULL"]
    where.extend(filters or [])
    result = db.execute(text(
        "SELECT * FROM rag_index_records WHERE " + " AND ".join(where)
    ), params or {})
    postgres = _postgres(db)
    return [_row_to_doc(row, postgres) for row in result]


def mark_deleted(db: Session, source_keys: set[tuple[str, str, int]]) -> int:
    if not source_keys:
        return 0
    count = 0
    for source_type, source_id, chunk_index in source_keys:
        result = db.execute(text(
            "UPDATE rag_index_records SET deleted_at=:now "
            "WHERE source_type=:source_type AND source_id=:source_id "
            "AND chunk_index=:chunk_index AND deleted_at IS NULL"
        ), {
            "now": datetime.now(timezone.utc), "source_type": source_type,
            "source_id": source_id, "chunk_index": chunk_index,
        })
        count += result.rowcount or 0
    return count


def create_run(db: Session, provenance: dict) -> str:
    public_id = str(uuid4())
    db.execute(text("""
        INSERT INTO rag_index_runs
          (public_id, state, embedding_model, embedding_revision, embedding_dimension,
           started_at)
        VALUES (:public_id, 'running', :model, :revision, :dimension, :started_at)
    """), {
        "public_id": public_id, "model": provenance["model"],
        "revision": provenance.get("revision"), "dimension": provenance["dimension"],
        "started_at": datetime.now(timezone.utc),
    })
    return public_id


def finish_run(db: Session, public_id: str, summary: dict, state: str = "ready", error: str | None = None) -> None:
    db.execute(text("""
        UPDATE rag_index_runs SET state=:state, records_scanned=:scanned, added=:added,
          updated=:updated, unchanged=:unchanged, deleted=:deleted, failed=:failed,
          error_message=:error, completed_at=:completed_at
        WHERE public_id=:public_id
    """), {
        "state": state, "scanned": summary.get("records_scanned", 0),
        "added": summary.get("added", 0), "updated": summary.get("updated", 0),
        "unchanged": summary.get("unchanged", 0), "deleted": summary.get("deleted", 0),
        "failed": summary.get("failed", 0), "error": error,
        "completed_at": datetime.now(timezone.utc), "public_id": public_id,
    })


def latest_run(db: Session):
    return db.execute(text(
        "SELECT * FROM rag_index_runs ORDER BY started_at DESC LIMIT 1"
    )).mappings().first()
