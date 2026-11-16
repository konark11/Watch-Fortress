"""Health-aware reranker pool with explicit hybrid-retrieval fallback."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request

from rag.openrouter_services import RERANK_MODEL, rerank as openrouter_rerank
from rag.settings import RERANKER_MODEL

try:
    REQUEST_TIMEOUT = max(1, min(int(os.environ.get("RAG_RERANK_TIMEOUT_SECONDS", "8")), 30))
except ValueError:
    REQUEST_TIMEOUT = 8
try:
    MAX_RETRIES = max(0, min(int(os.environ.get("RAG_RERANK_MAX_RETRIES", "1")), 2))
except ValueError:
    MAX_RETRIES = 1
try:
    CIRCUIT_FAILURE_THRESHOLD = max(1, min(int(os.environ.get("RAG_RERANK_CIRCUIT_FAILURE_THRESHOLD", "2")), 10))
except ValueError:
    CIRCUIT_FAILURE_THRESHOLD = 2
try:
    CIRCUIT_COOLDOWN_SECONDS = max(1, min(int(os.environ.get("RAG_RERANK_CIRCUIT_COOLDOWN_SECONDS", "60")), 3600))
except ValueError:
    CIRCUIT_COOLDOWN_SECONDS = 60

JINA_API_KEY = os.environ.get("JINA_API_KEY", "").strip()
JINA_MODEL = os.environ.get("JINA_RERANKER_MODEL", "").strip()
JINA_URL = os.environ.get("JINA_BASE_URL", "https://api.jina.ai/v1/rerank").strip()
_lock = threading.Lock()
_cursor = 0
_states: dict[str, dict[str, float | int]] = {}
_stats = {"attempts": 0, "successes": 0, "failures": 0, "fallbacks": 0}


def _configured_providers() -> list[str]:
    providers = []
    if RERANK_MODEL:
        providers.append("openrouter")
    if JINA_API_KEY and JINA_MODEL and JINA_URL:
        providers.append("jina")
    return providers


def _state(provider: str) -> dict[str, float | int]:
    return _states.setdefault(provider, {"failures": 0, "open_until": 0.0})


def _is_retryable(exc: Exception) -> bool:
    return isinstance(exc, (TimeoutError, urllib.error.URLError)) or (
        isinstance(exc, urllib.error.HTTPError) and (exc.code == 429 or exc.code >= 500)
    )


def _jina_rerank(query: str, documents: list[str]) -> list[float]:
    request = urllib.request.Request(
        JINA_URL,
        data=json.dumps({
            "model": JINA_MODEL,
            "query": query,
            "documents": documents,
            "top_n": len(documents),
        }).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {JINA_API_KEY}",
            "User-Agent": "Watch-Fortress/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        payload = json.loads(response.read())
    results = payload.get("data")
    if not isinstance(results, list) or len(results) != len(documents):
        raise ValueError("Jina reranker returned an invalid score array")
    scores = [None] * len(documents)
    for result in results:
        index = result.get("index")
        score = result.get("relevance_score")
        if not isinstance(index, int) or not 0 <= index < len(documents) or not isinstance(score, (int, float)):
            raise ValueError("Jina reranker returned invalid result metadata")
        scores[index] = max(0.0, min(1.0, float(score)))
    if any(score is None for score in scores):
        raise ValueError("Jina reranker omitted a document score")
    return [float(score) for score in scores]


def _call(provider: str, query: str, documents: list[str]) -> list[float]:
    if provider == "openrouter":
        return openrouter_rerank(query, documents)
    if provider == "jina":
        return _jina_rerank(query, documents)
    raise RuntimeError(f"Unknown reranker provider: {provider}")


def status() -> dict:
    providers = _configured_providers()
    now = time.monotonic()
    provider_status = {}
    for provider in providers:
        state = _state(provider)
        provider_status[provider] = {
            "configured": True,
            "circuit": "open" if float(state["open_until"]) > now else "closed",
            "failures": int(state["failures"]),
        }
    return {
        "provider": providers[0] if providers else "none",
        "pool": providers,
        "model": RERANKER_MODEL or JINA_MODEL,
        "configured": bool(providers),
        "available": any(item["circuit"] == "closed" for item in provider_status.values()),
        "loaded": False,
        "providers": provider_status,
        "stats": dict(_stats),
    }


def rerank(query: str, documents: list[str]) -> list[float]:
    if not documents:
        return []
    providers = _configured_providers()
    if not providers:
        raise RuntimeError("No reranker provider is configured")

    global _cursor
    with _lock:
        start = _cursor % len(providers)
        _cursor += 1
    ordered = providers[start:] + providers[:start]
    last_error: Exception | None = None
    for provider in ordered:
        state = _state(provider)
        if float(state["open_until"]) > time.monotonic():
            continue
        for attempt in range(MAX_RETRIES + 1):
            _stats["attempts"] += 1
            try:
                scores = _call(provider, query, documents)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                if not _is_retryable(exc) or attempt >= MAX_RETRIES:
                    last_error = exc
                    state["failures"] = int(state["failures"]) + 1
                    _stats["failures"] += 1
                    if int(state["failures"]) >= CIRCUIT_FAILURE_THRESHOLD:
                        state["open_until"] = time.monotonic() + CIRCUIT_COOLDOWN_SECONDS
                    break
                time.sleep(min(2 ** attempt, 4))
                continue
            state["failures"] = 0
            state["open_until"] = 0.0
            _stats["successes"] += 1
            if provider != ordered[0]:
                _stats["fallbacks"] += 1
            return scores
    if last_error:
        raise last_error
    raise RuntimeError("All configured reranker circuits are open")
