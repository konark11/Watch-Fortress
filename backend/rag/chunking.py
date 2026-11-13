"""Deterministic document chunking for future semantic indexes and ingestion."""
from __future__ import annotations
import re
from rag.settings import CHUNK_OVERLAP, CHUNK_SIZE


def chunk_text(
    text: str,
    strategy: str = "paragraph",
    size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[str]:
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError("size must be positive and overlap must be smaller than size")
    text = text.strip()
    if not text:
        return []
    if strategy == "paragraph":
        return [p.strip() for p in re.split(r"\n\s*\n+", text) if p.strip()]
    words = text.split()
    if strategy == "token":
        return [" ".join(words[i:i + size]) for i in range(0, len(words), size)]
    if strategy == "sliding":
        step = size - overlap
        return [
            " ".join(words[i:i + size])
            for i in range(0, len(words), step)
            if words[i:i + size]
        ]
    raise ValueError("strategy must be paragraph, token, or sliding")
