"""Small, deterministic, offline embeddings for persisted ingestion output."""
from __future__ import annotations

import hashlib
import math


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
