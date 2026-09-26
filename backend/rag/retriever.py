"""
TF-IDF based retriever.

Deliberately NOT using sentence-transformers/HuggingFace embeddings: those
require downloading model weights over the internet on first use, which
breaks the "air-gapped local RAG mode" requirement the moment the platform
is deployed somewhere without connectivity. scikit-learn's TF-IDF +
cosine similarity needs no model download at all - it fits the corpus at
query time from data already on disk - and for a knowledge base of this
size (CVE/CWE/CAPEC/ATT&CK/OWASP entries + internal docs, at most a few
thousand short documents) it retrieves comparably well to embedding
search while being trivially portable.

For deployments that DO have a local embedding model already cached
(e.g. via Ollama's embedding endpoint), swap this retriever for a FAISS/
Chroma-backed one - the query_engine only depends on `retrieve(query, k)`
returning ranked (doc, score) pairs, so the swap is isolated to this file.
"""
from __future__ import annotations
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class TfidfRetriever:
    def __init__(self):
        self.docs: list[dict] = []
        self.vectorizer: TfidfVectorizer | None = None
        self.matrix = None

    def index(self, docs: list[dict]):
        self.docs = docs
        if not docs:
            self.vectorizer, self.matrix = None, None
            return
        self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=20000)
        self.matrix = self.vectorizer.fit_transform([d["text"] for d in docs])

    def retrieve(self, query: str, k: int = 5) -> list[tuple[dict, float]]:
        if not self.docs or self.vectorizer is None:
            return []
        query_vec = self.vectorizer.transform([query])
        sims = cosine_similarity(query_vec, self.matrix).flatten()
        ranked_idx = sims.argsort()[::-1][:k]
        return [(self.docs[i], float(sims[i])) for i in ranked_idx if sims[i] > 0.01]

    def is_ready(self) -> bool:
        return self.vectorizer is not None
