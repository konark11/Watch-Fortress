"""Dense-vector retriever for the RAG corpus."""
from __future__ import annotations
from math import sqrt
from collections.abc import Callable


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        return 0.0
    numerator = sum(a * b for a, b in zip(left, right))
    left_norm = sqrt(sum(value * value for value in left))
    right_norm = sqrt(sum(value * value for value in right))
    return numerator / (left_norm * right_norm) if left_norm and right_norm else 0.0


class VectorRetriever:
    def __init__(self):
        self.docs: list[dict] = []
        self.embeddings: list[list[float]] = []
        self.embedder: Callable[[list[str]], list[list[float]]] | None = None

    def index(
        self,
        docs: list[dict],
        embeddings: list[list[float]] | None = None,
        embedder: Callable | None = None,
    ):
        if embeddings is None:
            from rag.embeddings import embed_texts
            embeddings = embed_texts([doc["text"] for doc in docs])
        if embedder is None:
            from rag.embeddings import embed_texts
            embedder = embed_texts
        self.docs = docs
        self.embeddings = embeddings
        self.embedder = embedder

    def retrieve(self, query: str, k: int = 5) -> list[tuple[dict, float]]:
        if not self.docs or self.embedder is None:
            return []
        query_embedding = self.embedder([query])[0]
        ranked = sorted(
            ((doc, _cosine(query_embedding, vector)) for doc, vector in zip(self.docs, self.embeddings)),
            key=lambda item: item[1],
            reverse=True,
        )
        return [(doc, score) for doc, score in ranked[:k] if score > 0.01]

    def is_ready(self) -> bool:
        return bool(self.docs and self.embeddings and self.embedder)


# Compatibility name for callers that imported the old retriever class.
TfidfRetriever = VectorRetriever
