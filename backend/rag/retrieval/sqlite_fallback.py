from __future__ import annotations

import json
import math
import re

from sqlalchemy.orm import Session

from rag.indexing.repository import active_records
from rag.settings import FUSION_K, LEXICAL_CANDIDATE_K, RRF_K, VECTOR_CANDIDATE_K


def _cosine(left, right) -> float:
    if not right or len(left) != len(right):
        return 0.0
    denominator = math.sqrt(sum(x * x for x in left)) * math.sqrt(sum(x * x for x in right))
    return sum(x * y for x, y in zip(left, right)) / denominator if denominator else 0.0


def _allowed(doc: dict, criteria: dict | None) -> bool:
    if not criteria:
        return True
    metadata = doc.get("metadata") or {}
    return all((
        not criteria.get("document_type") or metadata.get("document_type") == criteria["document_type"] or doc["id"].startswith(str(criteria["document_type"]).lower() + ":"),
        not criteria.get("severity") or metadata.get("severity") in (criteria["severity"], None, "unknown"),
        criteria.get("port") is None or str(criteria["port"]) in doc["text"],
        not criteria.get("vm") or criteria["vm"] in doc["text"],
        not criteria.get("cve") or str(criteria["cve"]).lower() in (doc["text"] + doc["title"]).lower(),
    ))


def retrieve(db: Session, query: str, embedding: list[float], criteria: dict | None = None, k: int = FUSION_K):
    docs = [doc for doc in active_records(db) if _allowed(doc, criteria)]
    dense = sorted(
        ((doc, _cosine(embedding, doc.get("embedding"))) for doc in docs),
        key=lambda item: (-item[1], item[0]["id"]),
    )[:VECTOR_CANDIDATE_K]
    terms = set(re.findall(r"[a-z0-9]+", query.lower()))
    lexical = sorted(
        ((doc, sum(1 for term in terms if term in doc["text"].lower())) for doc in docs),
        key=lambda item: (-item[1], item[0]["id"]),
    )
    lexical = [(doc, score) for doc, score in lexical if score][:LEXICAL_CANDIDATE_K]
    fused: dict[str, tuple[dict, float]] = {}
    for rank, (doc, _) in enumerate(dense, 1):
        fused[doc["id"]] = (doc, 1 / (RRF_K + rank))
    for rank, (doc, _) in enumerate(lexical, 1):
        current = fused.get(doc["id"])
        fused[doc["id"]] = (doc, (current[1] if current else 0) + 1 / (RRF_K + rank))
    return sorted(fused.values(), key=lambda item: (-item[1], item[0]["id"]))[:k]


def capability(db: Session) -> dict:
    return {
        "database": "sqlite",
        "vector_extension": False,
        "available": True,
        "fallback": True,
        "limitation": "Portable single-process fallback; no pgvector HNSW or multi-worker queue semantics.",
    }
