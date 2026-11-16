"""Small, deterministic, offline embeddings for persisted ingestion output."""
from __future__ import annotations

import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone
from typing import Any
import warnings
import time

from rag.settings import DEVICE, EMBEDDING_MODEL


FALLBACK_EMBEDDING_DIMENSIONS = 256
EXPECTED_BGE_DIMENSIONS = 768
EMBEDDING_DIMENSIONS = FALLBACK_EMBEDDING_DIMENSIONS
_sentence_transformer = None
_last_embedding_metadata: dict[str, Any] | None = None


def embed_text(text: str) -> list[float]:
    """Create a normalized hashing-vector embedding without downloading a model."""
    vector = [0.0] * FALLBACK_EMBEDDING_DIMENSIONS
    for token in text.lower().split():
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        index = int.from_bytes(digest[:4], "big") % FALLBACK_EMBEDDING_DIMENSIONS
        sign = 1.0 if digest[4] & 1 else -1.0
        vector[index] += sign
    norm = math.sqrt(sum(value * value for value in vector))
    return [round(value / norm, 8) for value in vector] if norm else vector


def embed_texts(texts: list[str], batch_size: int = 64) -> list[list[float]]:
    """Embed locally with BGE on CPU, with an offline test fallback."""
    if not texts:
        return []
    global _sentence_transformer, _last_embedding_metadata
    if _sentence_transformer is None:
        try:
            local_only = os.environ.get("RAG_ALLOW_MODEL_DOWNLOAD", "").lower() not in {"1", "true", "yes"}
            if local_only:
                os.environ.setdefault("HF_HUB_OFFLINE", "1")
                os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
            from sentence_transformers import SentenceTransformer
            _sentence_transformer = SentenceTransformer(
                EMBEDDING_MODEL,
                device=DEVICE,
                model_kwargs={
                    "local_files_only": local_only,
                },
            )
        except (ImportError, OSError, ValueError) as exc:
            warnings.warn(
                f"Local embedding model unavailable ({exc}); using deterministic embeddings.",
                RuntimeWarning,
                stacklevel=2,
            )
            _sentence_transformer = False
    if _sentence_transformer is False:
        vectors = [embed_text(text) for text in texts]
        _last_embedding_metadata = embedding_metadata(len(vectors[0]) if vectors else FALLBACK_EMBEDDING_DIMENSIONS)
        return vectors
    vectors = _sentence_transformer.encode(
        texts, batch_size=batch_size, normalize_embeddings=True, show_progress_bar=False
    )
    result = [vector.tolist() for vector in vectors]
    dimensions = len(result[0]) if result else EXPECTED_BGE_DIMENSIONS
    if any(len(vector) != dimensions for vector in result):
        raise ValueError("Embedding provider returned vectors with inconsistent dimensions")
    _last_embedding_metadata = embedding_metadata(dimensions)
    return result


def warmup_embeddings() -> dict[str, Any]:
    """Load the configured local encoder and run one tiny embedding.

    The normal ``embed_texts`` fallback remains authoritative: model import or
    loading failures are converted there into deterministic embeddings.
    """
    started = time.monotonic()
    embed_texts(["warmup"])
    return {
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "embedding": active_embedding_metadata(),
    }


def embedding_metadata(dimension: int | None = None) -> dict[str, Any]:
    """Return safe provenance for the currently selected embedding implementation."""
    fallback = _sentence_transformer is False
    return {
        "provider": "hashing-fallback" if fallback else "sentence-transformers",
        "model": "watch-fortress-hashing-v1" if fallback else EMBEDDING_MODEL,
        "revision": None if fallback else os.environ.get("RAG_EMBEDDING_REVISION"),
        "dimension": dimension or (FALLBACK_EMBEDDING_DIMENSIONS if fallback else EXPECTED_BGE_DIMENSIONS),
        "device": DEVICE,
        "implementation": "deterministic-token-hash" if fallback else "sentence-transformers",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def active_embedding_metadata() -> dict[str, Any]:
    """Describe the active encoder without requiring a model download."""
    if _last_embedding_metadata:
        return dict(_last_embedding_metadata)
    return embedding_metadata()


def validate_embedding(vector: list[float], metadata: dict[str, Any] | None = None) -> None:
    """Fail closed for malformed or incompatible persisted vectors."""
    if not isinstance(vector, list) or not vector or not all(isinstance(value, (int, float)) for value in vector):
        raise ValueError("Embedding must be a non-empty numeric vector")
    expected = active_embedding_metadata()
    if len(vector) != expected["dimension"]:
        raise ValueError(
            f"Embedding dimension {len(vector)} does not match active dimension {expected['dimension']}"
        )
    if metadata:
        for key in ("model", "dimension", "implementation"):
            if metadata.get(key) != expected.get(key):
                raise ValueError(
                    f"Embedding metadata mismatch for {key}: "
                    f"{metadata.get(key)!r} != {expected.get(key)!r}"
                )


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
