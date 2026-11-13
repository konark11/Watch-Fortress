"""Central RAG model and retrieval settings."""
from __future__ import annotations

import os


EMBEDDING_MODEL = os.environ.get("RAG_EMBEDDING_MODEL", "BAAI/bge-base-en-v1.5")
EMBEDDING_REVISION = os.environ.get("RAG_EMBEDDING_REVISION", "")
RERANKER_MODEL = os.environ.get("OPENROUTER_RERANK_MODEL", "")
ANSWER_MODEL = os.environ.get(
    "RAG_GENERATION_MODEL",
    os.environ.get("VULN_ONLINE_LLM_MODEL", "openai/gpt-oss-120b"),
)
JEV_MODE = os.environ.get("RAG_JEV_MODE", os.environ.get("JEV_MODE", "disabled"))
JEV_MODEL = os.environ.get("RAG_JEV_MODEL", os.environ.get("JEV_MODEL", "jev-latest"))

CHUNK_SIZE = 450
CHUNK_OVERLAP = 50
DENSE_TOP_K = int(os.environ.get("RAG_VECTOR_CANDIDATE_K", "50"))
SPARSE_TOP_K = int(os.environ.get("RAG_LEXICAL_CANDIDATE_K", "50"))
RRF_K = 60
FINAL_EVIDENCE_K = int(os.environ.get("RAG_FINAL_EVIDENCE_K", "5"))
DEVICE = "cpu"

RAG_RETRIEVAL_BACKEND = os.environ.get("RAG_RETRIEVAL_BACKEND", "auto").lower()
VECTOR_CANDIDATE_K = DENSE_TOP_K
LEXICAL_CANDIDATE_K = SPARSE_TOP_K
FUSION_K = int(os.environ.get("RAG_FUSION_K", str(DENSE_TOP_K)))
RERANK_K = int(os.environ.get("RAG_RERANK_K", str(FINAL_EVIDENCE_K * 4)))
RERANK_ENABLED = os.environ.get(
    "RAG_RERANK_ENABLED",
    "1" if os.environ.get("OPENROUTER_RERANK_MODEL", "").strip() else "0",
).lower() in {"1", "true", "yes"}
INDEXING_BATCH_SIZE = int(os.environ.get("RAG_INDEXING_BATCH_SIZE", "64"))
FULL_REINDEX_ENABLED = os.environ.get("RAG_FULL_REINDEX_ENABLED", "0").lower() in {"1", "true", "yes"}
