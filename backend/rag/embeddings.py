"""Small, deterministic, offline embeddings for persisted ingestion output."""
from __future__ import annotations

import hashlib
import json
import math
import os
import sys
from typing import Any


EMBEDDING_DIMENSIONS = 256


def embed_text(text: str) -> list[float]:
    """Create a normalized hashing-vector embedding without downloading a model."""
    vector = [0.0] * EMBEDDING_DIMENSIONS
    for token in text.lower().split():
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        index = int.from_bytes(digest[:4], "big") % EMBEDDING_DIMENSIONS
        sign = 1.0 if digest[4] & 1 else -1.0
        vector[index] += sign
    norm = math.sqrt(sum(value * value for value in vector))
    return [round(value / norm, 8) for value in vector] if norm else vector


def embed_texts(texts: list[str], batch_size: int = 64) -> list[list[float]]:
    """Embed text with the configured provider, falling back to offline vectors."""
    from rag.openrouter_services import EMBEDDING_MODEL, KEY, embed

    if not texts:
        return []
    if not (KEY and EMBEDDING_MODEL):
        return [embed_text(text) for text in texts]

    vectors: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        vectors.extend(embed(texts[start:start + batch_size]))
    return vectors


def embed_corpus(db: Any = None, save_path: str | None = None) -> dict[str, dict[str, Any]]:
    """Generate normalized vector embeddings for all documents in the knowledge corpus."""
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    from models.database import SessionLocal
    from rag.corpus import build_corpus
    from rag.query_engine import ensure_indexed

    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        ensure_indexed(db, force=True)
        docs = build_corpus(db)
        embeddings_index: dict[str, dict[str, Any]] = {}
        for d in docs:
            doc_id = d["id"]
            vector = embed_texts([d["text"]])[0]
            embeddings_index[doc_id] = {
                "id": doc_id,
                "source": d["source"],
                "title": d["title"],
                "embedding": vector,
            }

        if save_path:
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(embeddings_index, f, indent=2, ensure_ascii=False)

        return embeddings_index
    finally:
        if close_db:
            db.close()


if __name__ == "__main__":
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    output_path = os.path.join(data_dir, "vector_embeddings.json")
    print("Generating vector embeddings for the entire knowledge base corpus...")
    results = embed_corpus(save_path=output_path)
    print(f"Successfully generated {len(results)} vector embeddings ({EMBEDDING_DIMENSIONS} dimensions each).")
    print(f"Vector embeddings saved to: {output_path}")
