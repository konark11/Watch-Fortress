"""OpenRouter adapters for embedding, reranking, and generation support."""
from __future__ import annotations
import json
import os
import urllib.request

BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
KEY = os.environ.get("OPENROUTER_API_KEY", "").strip()
EMBEDDING_MODEL = os.environ.get("OPENROUTER_EMBEDDING_MODEL", "").strip()
RERANK_MODEL = os.environ.get("OPENROUTER_RERANK_MODEL", "").strip()
try:
    REQUEST_TIMEOUT = max(1, min(int(os.environ.get("RAG_LLM_TIMEOUT_SECONDS", "30")), 120))
except ValueError:
    REQUEST_TIMEOUT = 30


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
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read())


def embed(texts: list[str]) -> list[list[float]]:
    if not EMBEDDING_MODEL:
        raise RuntimeError("Set OPENROUTER_EMBEDDING_MODEL to enable API embeddings")
    data = _post("/embeddings", {"model": EMBEDDING_MODEL, "input": texts})
    embeddings = [item["embedding"] for item in data["data"]]
    if len(embeddings) != len(texts) or not all(isinstance(item, list) for item in embeddings):
        raise ValueError("OpenRouter embedding response did not match the input batch")
    return embeddings


def rerank(query: str, documents: list[str], model: str | None = None) -> list[float]:
    if not RERANK_MODEL:
        raise RuntimeError("Set OPENROUTER_RERANK_MODEL to enable API reranking")
    selected_model = (model or RERANK_MODEL).strip()
    data = _post("/rerank", {
        "model": selected_model,
        "query": query,
        "documents": documents,
        "top_n": len(documents),
    })
    results = data.get("results")
    if not isinstance(results, list) or len(results) != len(documents):
        raise ValueError("OpenRouter reranker returned an invalid score array")
    scores = [None] * len(documents)
    for result in results:
        index = result.get("index")
        score = result.get("relevance_score")
        if not isinstance(index, int) or not 0 <= index < len(documents) or not isinstance(score, (int, float)):
            raise ValueError("OpenRouter reranker returned invalid result metadata")
        scores[index] = max(0.0, min(1.0, float(score)))
    if any(score is None for score in scores):
        raise ValueError("OpenRouter reranker omitted a document score")
    return [float(score) for score in scores]
