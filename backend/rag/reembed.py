"""Validate or atomically rebuild persisted knowledge embeddings.

Run from the backend directory:
    python -m rag.reembed --dry-run
    python -m rag.reembed --apply
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone

from sqlalchemy.exc import SQLAlchemyError

from models.database import KnowledgeChunk, SessionLocal
from rag.embeddings import active_embedding_metadata, embed_texts


def reembed_persisted_chunks(db=None, *, dry_run: bool = False) -> dict:
    close_db = db is None
    db = db or SessionLocal()
    try:
        chunks = db.query(KnowledgeChunk).order_by(KnowledgeChunk.id).all()
        metadata = active_embedding_metadata()
        if chunks and not dry_run:
            vectors = embed_texts([chunk.content for chunk in chunks])
            metadata = active_embedding_metadata()
            if any(len(vector) != metadata["dimension"] for vector in vectors):
                raise ValueError("Embedding provider returned an inconsistent dimension")
            timestamp = datetime.now(timezone.utc).isoformat()
            for chunk, vector in zip(chunks, vectors):
                chunk.embedding = vector
                chunk.metadata_json = {
                    **(chunk.metadata_json or {}),
                    "embedding": {**metadata, "created_at": timestamp},
                }
            db.commit()
        return {
            "dry_run": dry_run,
            "knowledge_chunks": len(chunks),
            "updated_chunks": 0 if dry_run else len(chunks),
            "generated_corpus_records": "regenerated on next index build",
            "failures": 0,
            "embedding": metadata,
        }
    except (SQLAlchemyError, RuntimeError, ValueError, OSError):
        if not dry_run:
            db.rollback()
        raise
    finally:
        if close_db:
            db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate or rebuild RAG embeddings")
    parser.add_argument("--dry-run", action="store_true", help="Report counts without changing the database")
    parser.add_argument("--apply", action="store_true", help="Atomically rebuild persisted knowledge chunk embeddings")
    args = parser.parse_args()
    if args.dry_run == args.apply:
        parser.error("choose exactly one of --dry-run or --apply")
    result = reembed_persisted_chunks(dry_run=args.dry_run)
    print(result)


if __name__ == "__main__":
    main()
