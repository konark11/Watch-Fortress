from __future__ import annotations

import importlib
import json
import time
import urllib.error
import pytest


def load_provider(monkeypatch, **values):
    for key in (
        "RAG_GENERATION_PROVIDER", "VULN_RAG_MODE", "RAG_GENERATION_BASE_URL",
        "RAG_GENERATION_API_KEY", "RAG_GENERATION_MODEL", "GROQ_BASE_URL",
        "GROQ_MODEL", "GROQ_API_KEYS", "GROQ_API_KEY_1", "GROQ_API_KEY_2",
        "GROQ_API_KEY_3",
        "ANSWER_MODEL", "RAG_LLM_TIMEOUT_SECONDS", "RAG_LLM_MAX_RETRIES",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    import rag.llm_providers as providers
    return importlib.reload(providers)


def test_explicit_groq_selection(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="groq",
        GROQ_API_KEYS="groq-a,groq-b", GROQ_MODEL="gpt-oss",
    )
    assert providers.get_provider().__class__.__name__ == "GroqProvider"
    assert providers.provider_status()["credential_count"] == 2


def test_legacy_local_env_groq_keys_select_groq_and_model(monkeypatch):
    providers = load_provider(
        monkeypatch, GROQ_API_KEY_1="groq-key", ANSWER_MODEL="llama-3.3-70b-versatile",
    )
    assert providers.RAG_MODE == "groq"
    assert providers.GROQ_MODEL == "llama-3.3-70b-versatile"
    assert providers.provider_status()["warning"] == "provider_inferred_from_groq_credentials"


def test_missing_selected_provider_configuration_fails_fast(monkeypatch):
    providers = load_provider(monkeypatch, RAG_GENERATION_PROVIDER="groq")
    with pytest.raises(providers.ProviderConfigurationError, match="groq_not_configured"):
        providers.validate_provider_configuration()


def test_openrouter_reranker_uses_configured_model(monkeypatch):
    monkeypatch.setenv("OPENROUTER_RERANK_MODEL", "reranker:free")
    import rag.reranker as reranker
    monkeypatch.setattr(reranker, "RERANK_MODEL", "reranker:free")
    monkeypatch.setattr(reranker, "openrouter_rerank", lambda query, documents: [0.8] * len(documents))
    assert reranker.rerank("q", ["evidence"]) == [0.8]
    assert reranker.status()["provider"] == "openrouter"


def test_openrouter_reranker_uses_rerank_endpoint(monkeypatch):
    import rag.openrouter_services as services
    monkeypatch.setattr(services, "RERANK_MODEL", "reranker:free")
    monkeypatch.setattr(services, "KEY", "test-key")
    calls = []

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self):
            return json.dumps({
                "results": [
                    {"index": 1, "relevance_score": 0.2},
                    {"index": 0, "relevance_score": 0.9},
                ],
            }).encode()

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, json.loads(request.data), timeout))
        return Response()

    monkeypatch.setattr(services.urllib.request, "urlopen", fake_urlopen)
    assert services.rerank("q", ["first", "second"]) == [0.9, 0.2]
    assert calls[0][0].endswith("/rerank")
    assert calls[0][1] == {
        "model": "reranker:free",
        "query": "q",
        "documents": ["first", "second"],
        "top_n": 2,
    }


def test_reranker_rotates_to_jina_after_openrouter_rate_limit(monkeypatch):
    import rag.reranker as reranker

    monkeypatch.setattr(reranker, "RERANK_MODEL", "reranker:free")
    monkeypatch.setattr(reranker, "JINA_API_KEY", "jina-key")
    monkeypatch.setattr(reranker, "JINA_MODEL", "jina-reranker")
    monkeypatch.setattr(reranker, "_cursor", 0)
    monkeypatch.setattr(reranker, "_states", {})
    monkeypatch.setattr(reranker, "_stats", {"attempts": 0, "successes": 0, "failures": 0, "fallbacks": 0})
    monkeypatch.setattr(reranker, "openrouter_rerank", lambda *_: (_ for _ in ()).throw(
        urllib.error.HTTPError("https://openrouter.invalid", 429, "rate", {}, None)
    ))
    monkeypatch.setattr(reranker, "_jina_rerank", lambda query, documents: [0.7] * len(documents))
    assert reranker.rerank("q", ["evidence"]) == [0.7]
    assert reranker.status()["stats"]["fallbacks"] == 1


def test_online_does_not_use_groq_keys(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="online",
        RAG_GENERATION_BASE_URL="https://online.invalid/v1",
        RAG_GENERATION_API_KEY="online-key",
        GROQ_API_KEYS="groq-secret",
    )
    assert providers.provider_status()["provider"] == "openai-compatible"
    assert providers.provider_status()["credential_count"] == 1
    assert providers.OnlineProvider().name == "online (openai/gpt-oss-120b)"


def test_groq_rotates_after_retryable_429(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="groq",
        GROQ_API_KEYS="key-a,key-b", GROQ_MODEL="gpt-oss",
    )
    monkeypatch.setattr(providers.time, "sleep", lambda _: None)
    calls = []

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self): return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

    def fake_urlopen(request, timeout):
        calls.append((
            request.get_header("Authorization"),
            request.get_header("User-agent"),
        ))
        if len(calls) == 1:
            raise urllib.error.HTTPError(request.full_url, 429, "rate", {}, None)
        return Response()

    monkeypatch.setattr(providers.urllib.request, "urlopen", fake_urlopen)
    assert providers.GroqProvider().generate("q", []) == "ok"
    assert calls == [
        ("Bearer key-a", "Watch-Fortress/1.0"),
        ("Bearer key-b", "Watch-Fortress/1.0"),
    ]


def test_general_generation_uses_general_knowledge_prompt(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="groq",
        GROQ_API_KEYS="key-a", GROQ_MODEL="gpt-oss",
    )
    captured = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def read(self): return json.dumps({"choices": [{"message": {"content": "definition"}}]}).encode()

    def fake_urlopen(request, timeout):
        captured.update(json.loads(request.data))
        return Response()

    monkeypatch.setattr(providers.urllib.request, "urlopen", fake_urlopen)
    assert providers.GroqProvider().generate_general("What does CVSS mean?") == "definition"
    assert "general security" in captured["messages"][0]["content"]
    assert captured["messages"][1]["content"] == "Question: What does CVSS mean?"


def test_non_retryable_auth_failure_does_not_rotate(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="groq",
        GROQ_API_KEYS="key-a,key-b", GROQ_MODEL="gpt-oss",
    )
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request.get_header("Authorization"))
        raise urllib.error.HTTPError(request.full_url, 401, "unauthorized", {}, None)

    monkeypatch.setattr(providers.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(providers.ProviderUnavailableError, match="groq_http_401"):
        providers.GroqProvider().generate("q", [])
    assert calls == ["Bearer key-a"]
    assert "key-a" not in providers.provider_status().__repr__()


def test_open_circuit_falls_back_without_deadlock(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="groq",
        GROQ_API_KEYS="key-a", GROQ_MODEL="gpt-oss",
    )
    providers._provider_states["groq"]["open_until"] = time.monotonic() + 30
    started = time.monotonic()
    with pytest.raises(providers.ProviderUnavailableError, match="groq_circuit_open"):
        providers.GroqProvider().generate("q", [])
    assert time.monotonic() - started < 1


def test_retryable_failures_open_circuit_with_bounded_backoff(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="groq",
        GROQ_API_KEYS="key-a", GROQ_MODEL="gpt-oss",
    )
    delays = []
    monkeypatch.setattr(providers.time, "sleep", delays.append)

    def always_fails(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 503, "unavailable", {}, None)

    monkeypatch.setattr(providers.urllib.request, "urlopen", always_fails)
    with pytest.raises(providers.ProviderUnavailableError, match="groq_retryable_http_503"):
        providers.GroqProvider().generate("q", [])
    assert len(delays) == 2
    assert delays[0] <= delays[1] < 5
    assert providers.provider_status()["circuit"] == "open"


def test_provider_circuits_are_independent(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="groq",
        GROQ_API_KEYS="groq-key", GROQ_MODEL="gpt-oss",
    )
    providers._record_provider_failure("groq")
    assert providers._provider_states["online"]["failures"] == 0
    providers._record_provider_success("online")
    assert providers._provider_states["groq"]["failures"] == 1


def test_conflicting_legacy_selection_reports_safe_warning(monkeypatch):
    providers = load_provider(
        monkeypatch, RAG_GENERATION_PROVIDER="groq",
        VULN_RAG_MODE="openrouter", GROQ_API_KEYS="super-secret-value",
    )
    status = providers.provider_status()
    assert status["provider"] == "groq"
    assert status["warning"] == "canonical_provider_overrides_legacy"
    assert "super-secret-value" not in repr(status)
