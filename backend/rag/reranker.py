"""OpenRouter-backed reranking for retrieved evidence."""
from __future__ import annotations

from rag.openrouter_services import RERANK_MODEL, rerank as openrouter_rerank
from rag.settings import RERANKER_MODEL


def status() -> dict:
    return {
        "provider": "openrouter",
        "model": RERANKER_MODEL,
        "configured": bool(RERANK_MODEL),
        "available": bool(RERANK_MODEL),
        "loaded": False,
    }


def rerank(query: str, documents: list[str]) -> list[float]:
    if not documents:
        return []
    return openrouter_rerank(query, documents)
