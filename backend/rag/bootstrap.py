"""Explicit initial/rebuild indexing command.

Examples (from ``backend``)::

    python -m rag.bootstrap
    RAG_FULL_REINDEX_ENABLED=1 python -m rag.bootstrap --full
"""
from __future__ import annotations

import argparse

from models.database import SessionLocal
from rag.indexing.service import index_incremental


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the persistent RAG index")
    parser.add_argument("--full", action="store_true", help="reconcile and tombstone the complete corpus")
    args = parser.parse_args()
    db = SessionLocal()
    try:
        if args.full:
            import os
            if os.environ.get("RAG_FULL_REINDEX_ENABLED", "0").lower() not in {"1", "true", "yes"}:
                raise SystemExit("Full rebuild is disabled; set RAG_FULL_REINDEX_ENABLED=1 explicitly.")
        summary = index_incremental(db, full=args.full)
        print({
            key: summary[key] for key in (
                "run_public_id", "records_scanned", "added", "updated",
                "unchanged", "deleted", "failed", "model", "dimension",
            )
        })
    finally:
        db.close()


if __name__ == "__main__":
    main()
