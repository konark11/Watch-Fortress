from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from rag.corpus import build_corpus
from rag.embeddings import active_embedding_metadata, embed_texts
from rag.indexing import repository
from rag.indexing.sources import content_hash, scope_matches, source_parts
from rag.settings import INDEXING_BATCH_SIZE


def _check_provenance(provenance: dict, postgres: bool) -> None:
    if provenance["dimension"] <= 0:
        raise ValueError("embedding_dimension_invalid")
    if postgres and provenance["provider"] == "hashing-fallback" and provenance["dimension"] != 768:
        # PostgreSQL's production column is vector(768); a fallback vector must
        # never be mixed into it.
        raise ValueError(
            "embedding_incompatible: active fallback embedding is not compatible "
            "with the PostgreSQL BGE vector index; install the configured BGE model "
            "and run a full reindex"
        )


def index_incremental(db: Session, scope: dict[str, Any] | None = None, full: bool = False) -> dict:
    provenance = active_embedding_metadata()
    _check_provenance(provenance, db.bind.dialect.name == "postgresql")
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext('watch_fortress_rag_index'))"))
    run_id = repository.create_run(db, provenance)
    documents = [doc for doc in build_corpus(db) if scope_matches(doc, scope)]
    seen: set[tuple[str, str, int]] = set()
    summary = {"records_scanned": len(documents), "added": 0, "updated": 0,
               "unchanged": 0, "deleted": 0, "failed": 0, "model": provenance["model"],
               "revision": provenance.get("revision"), "dimension": provenance["dimension"],
               "run_public_id": run_id}
    try:
        for offset in range(0, len(documents), INDEXING_BATCH_SIZE):
            batch = documents[offset:offset + INDEXING_BATCH_SIZE]
            to_embed: list[dict] = []
            for document in batch:
                key = source_parts(document)
                seen.add(key)
                digest = content_hash(document)
                existing = repository.get_record(db, *key)
                if existing and existing["content_hash"] == digest and existing["embedding_dimension"] == provenance["dimension"] and existing["embedding_model"] == provenance["model"] and existing["embedding_implementation"] == provenance["implementation"] and existing["embedding_revision"] == provenance.get("revision") and existing["deleted_at"] is None:
                    summary["unchanged"] += 1
                else:
                    to_embed.append(document)
                    summary["updated" if existing else "added"] += 1
            vectors = embed_texts([doc["text"] for doc in to_embed], batch_size=INDEXING_BATCH_SIZE)
            for document, vector in zip(to_embed, vectors):
                if len(vector) != provenance["dimension"]:
                    raise ValueError("embedding_dimension_changed_during_index")
                repository.save_record(db, document, vector, provenance, content_hash(document))
        if full:
            # Full runs are the only operation allowed to remove records that
            # are absent from the complete source snapshot.
            rows = db.execute(text(
                "SELECT source_type, source_id, chunk_index FROM rag_index_records WHERE deleted_at IS NULL"
            )).all()
            stale_keys = {
                (row[0], row[1], row[2]) for row in rows
                if (row[0], row[1], row[2]) not in seen
            }
            summary["deleted"] = repository.mark_deleted(db, stale_keys)
        else:
            # A scoped run can safely tombstone only the selected source family.
            if scope:
                rows = db.execute(text(
                    "SELECT source_type, source_id, chunk_index, metadata FROM rag_index_records WHERE deleted_at IS NULL"
                )).all()
                selected = {
                    (row[0], row[1], row[2]) for row in rows
                    if (
                        (scope.get("document_id") and str(
                            json.loads(row[3] or "{}").get("document_id")
                        ) == str(scope["document_id"]))
                        or (scope.get("source_id") and row[1] == str(scope["source_id"]))
                        or (scope.get("scan_id") and (
                            row[1] == str(scope["scan_id"])
                            or str(json.loads(row[3] or "{}").get("scan_id")) == str(scope["scan_id"])
                        ))
                    )
                }
                summary["deleted"] = repository.mark_deleted(db, selected - seen)
        repository.finish_run(db, run_id, summary)
        db.commit()
        return summary
    except Exception as exc:
        db.rollback()
        # The failed run is intentionally not exposed as ready state.
        raise RuntimeError(f"rag_index_failed: {type(exc).__name__}") from exc
