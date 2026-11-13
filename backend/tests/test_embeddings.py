from __future__ import annotations

import asyncio
import importlib


def test_warmup_embeddings_runs_one_tiny_embedding(monkeypatch):
    import rag.embeddings as embeddings

    calls = []
    monkeypatch.setattr(
        embeddings,
        "embed_texts",
        lambda texts: calls.append(texts) or [[1.0, 0.0]],
    )
    result = embeddings.warmup_embeddings()

    assert calls == [["warmup"]]
    assert result["duration_ms"] >= 0
    assert result["embedding"]["model"]


def test_lifespan_preloads_embeddings_by_default(monkeypatch):
    monkeypatch.setenv("VULN_DATABASE_URL", "sqlite:///:memory:")
    import main
    import rag.embeddings as embeddings

    calls = []
    monkeypatch.delenv("RAG_PRELOAD_EMBEDDINGS", raising=False)
    monkeypatch.setattr(embeddings, "warmup_embeddings", lambda: calls.append(True) or {
        "duration_ms": 1,
        "embedding": {"model": "test"},
    })

    async def exercise():
        async with main.lifespan(None):
            pass

    asyncio.run(exercise())
    assert calls == [True]


def test_lifespan_can_disable_embedding_preload(monkeypatch):
    monkeypatch.setenv("VULN_DATABASE_URL", "sqlite:///:memory:")
    import main
    import rag.embeddings as embeddings

    calls = []
    monkeypatch.setenv("RAG_PRELOAD_EMBEDDINGS", "false")
    monkeypatch.setattr(embeddings, "warmup_embeddings", lambda: calls.append(True))

    async def exercise():
        async with main.lifespan(None):
            pass

    asyncio.run(exercise())
    assert calls == []


def test_lifespan_continues_when_embedding_preload_fails(monkeypatch):
    monkeypatch.setenv("VULN_DATABASE_URL", "sqlite:///:memory:")
    import main
    import rag.embeddings as embeddings

    monkeypatch.setenv("RAG_PRELOAD_EMBEDDINGS", "true")
    monkeypatch.setattr(
        embeddings,
        "warmup_embeddings",
        lambda: (_ for _ in ()).throw(RuntimeError("model unavailable")),
    )

    async def exercise():
        async with main.lifespan(None):
            pass

    asyncio.run(exercise())


def test_embedding_fallback_remains_available_after_model_failure(monkeypatch):
    import rag.embeddings as embeddings

    monkeypatch.setattr(embeddings, "_sentence_transformer", False)
    vectors = embeddings.embed_texts(["offline fallback"])

    assert len(vectors) == 1
    assert len(vectors[0]) == embeddings.FALLBACK_EMBEDDING_DIMENSIONS
    assert embeddings.active_embedding_metadata()["provider"] == "hashing-fallback"
