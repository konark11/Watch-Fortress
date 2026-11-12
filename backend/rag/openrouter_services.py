"""OpenRouter adapters for embedding, reranking, and generation support."""
from __future__ import annotations
import json
import os
import urllib.request

BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
KEY = os.environ.get("OPENROUTER_API_KEY", "").strip()
EMBEDDING_MODEL = os.environ.get("OPENROUTER_EMBEDDING_MODEL", "").strip()
RERANK_MODEL = os.environ.get("OPENROUTER_RERANK_MODEL", "").strip()


def _post(path: str, payload: dict) -> dict:
    if not KEY:
        raise RuntimeError("OPENROUTER_API_KEY is required")
    if not payload.get("model", "").endswith(":free"):
        raise ValueError("Only OpenRouter :free models are permitted")
    req = urllib.request.Request(
        f"{BASE_URL}{path}", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {KEY}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read())


def embed(texts: list[str]) -> list[list[float]]:
    if not EMBEDDING_MODEL:
        raise RuntimeError("Set OPENROUTER_EMBEDDING_MODEL to enable API embeddings")
    data = _post("/embeddings", {"model": EMBEDDING_MODEL, "input": texts})
    embeddings = [item["embedding"] for item in data["data"]]
    if len(embeddings) != len(texts) or not all(isinstance(item, list) for item in embeddings):
        raise ValueError("OpenRouter embedding response did not match the input batch")
    return embeddings


def rerank(query: str, documents: list[str]) -> list[float]:
    if not RERANK_MODEL:
        raise RuntimeError("Set OPENROUTER_RERANK_MODEL to enable API reranking")
    data = _post("/chat/completions", {
        "model": RERANK_MODEL,
        "messages": [{"role": "user", "content": f"Return only a JSON array of 0..1 relevance scores for these documents.\nQuery: {query}\nDocuments:\n" + "\n".join(f"{i}: {d}" for i, d in enumerate(documents))}],
        "temperature": 0,
        "max_tokens": 200,
    })
    scores = json.loads(data["choices"][0]["message"]["content"])
    if (
        not isinstance(scores, list)
        or len(scores) != len(documents)
        or not all(isinstance(score, (int, float)) for score in scores)
    ):
        raise ValueError("OpenRouter reranker returned an invalid score array")
    return [max(0.0, min(1.0, float(score))) for score in scores]
