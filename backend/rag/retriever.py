"""Dense-vector retriever for the RAG corpus."""
from __future__ import annotations
from math import sqrt
from collections.abc import Callable
import re
from math import log
from rag.settings import DENSE_TOP_K, RRF_K, SPARSE_TOP_K


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
        if embeddings and len(embeddings) != len(docs):
            raise ValueError("Embedding count does not match document count")
        dimensions = {len(vector) for vector in embeddings if isinstance(vector, list)}
        if len(dimensions) > 1:
            raise ValueError(f"Mixed embedding dimensions cannot be indexed: {sorted(dimensions)}")
        self.docs = docs
        self.embeddings = embeddings
        self.embedder = embedder

    def retrieve(self, query: str, k: int = DENSE_TOP_K) -> list[tuple[dict, float]]:
        if not self.docs or self.embedder is None:
            return []
        query_embedding = self.embedder([query])[0]
        if self.embeddings and len(query_embedding) != len(self.embeddings[0]):
            raise ValueError(
                f"Query embedding dimension {len(query_embedding)} does not match "
                f"index dimension {len(self.embeddings[0])}"
            )
        ranked = sorted(
            ((doc, _cosine(query_embedding, vector)) for doc, vector in zip(self.docs, self.embeddings)),
            key=lambda item: item[1],
            reverse=True,
        )
        return [(doc, score) for doc, score in ranked[:k] if score > 0.01]

    def is_ready(self) -> bool:
        return bool(self.docs and self.embeddings and self.embedder)


class BM25Retriever:
    def __init__(self) -> None:
        self.docs: list[dict] = []
        self.term_frequencies: list[dict[str, int]] = []
        self.idf: dict[str, float] = {}
        self.average_length = 0.0

    def index(self, docs: list[dict]) -> None:
        self.docs = docs
        self.term_frequencies = []
        document_frequency: dict[str, int] = {}
        for doc in docs:
            terms = re.findall(r"[a-z0-9]+", doc["text"].lower())
            frequencies: dict[str, int] = {}
            for term in terms:
                frequencies[term] = frequencies.get(term, 0) + 1
            self.term_frequencies.append(frequencies)
            for term in frequencies:
                document_frequency[term] = document_frequency.get(term, 0) + 1
        count = len(docs)
        self.idf = {
            term: log((count - frequency + 0.5) / (frequency + 0.5) + 1)
            for term, frequency in document_frequency.items()
        }
        self.average_length = (
            sum(sum(item.values()) for item in self.term_frequencies) / count
            if count else 0.0
        )

    def retrieve(self, query: str, k: int = SPARSE_TOP_K) -> list[tuple[dict, float]]:
        if not self.average_length:
            return []
        ranked: list[tuple[dict, float]] = []
        for doc, frequencies in zip(self.docs, self.term_frequencies):
            length = sum(frequencies.values())
            score = 0.0
            for term in re.findall(r"[a-z0-9]+", query.lower()):
                term_frequency = frequencies.get(term, 0)
                if term_frequency:
                    denominator = term_frequency + 1.5 * (
                        1 - 0.75 + 0.75 * length / self.average_length
                    )
                    score += self.idf.get(term, 0.0) * term_frequency * 2.5 / denominator
            if score > 0:
                ranked.append((doc, score))
        return sorted(ranked, key=lambda item: item[1], reverse=True)[:k]


class HybridRetriever:
    """Dense + BM25 retrieval combined with reciprocal rank fusion."""

    def __init__(self) -> None:
        self.vector = VectorRetriever()
        self.sparse = BM25Retriever()
        self.docs: list[dict] = []

    def index(self, docs, embeddings=None, embedder=None) -> None:
        self.docs = docs
        self.vector.index(docs, embeddings=embeddings, embedder=embedder)
        self.sparse.index(docs)

    def retrieve(self, query: str, k: int = DENSE_TOP_K, metadata_filter=None):
        docs = [doc for doc in self.docs if not metadata_filter or metadata_filter(doc)]
        vector = self.vector
        sparse_retriever = self.sparse
        if len(docs) != len(self.docs):
            allowed = {doc["id"] for doc in docs}
            dense_docs = [
                (doc, embedding)
                for doc, embedding in zip(self.vector.docs, self.vector.embeddings)
                if doc["id"] in allowed
            ]
            vector = VectorRetriever()
            vector.index(
                [item[0] for item in dense_docs],
                [item[1] for item in dense_docs],
                embedder=self.vector.embedder,
            )
            sparse_retriever = BM25Retriever()
            sparse_retriever.index(docs)
        dense = vector.retrieve(query, DENSE_TOP_K)
        sparse = sparse_retriever.retrieve(query, SPARSE_TOP_K)
        fused: dict[str, tuple[dict, float]] = {}
        for rank, (doc, _) in enumerate(dense, start=1):
            fused[doc["id"]] = (doc, 1 / (RRF_K + rank))
        for rank, (doc, _) in enumerate(sparse, start=1):
            current = fused.get(doc["id"])
            fused[doc["id"]] = (
                doc, (current[1] if current else 0) + 1 / (RRF_K + rank)
            )
        return sorted(fused.values(), key=lambda item: item[1], reverse=True)[:k]


class TfidfRetriever(VectorRetriever):
    """Legacy offline retriever retained for lightweight compatibility tests."""

    def index(self, docs, embeddings=None, embedder=None) -> None:
        from rag.embeddings import embed_text

        super().index(
            docs,
            embeddings=embeddings or [embed_text(doc["text"]) for doc in docs],
            embedder=embedder or (lambda texts: [embed_text(text) for text in texts]),
        )
