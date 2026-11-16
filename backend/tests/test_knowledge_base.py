"""Tests for vulnerability knowledge base, enrichment graph, and retrieval indexing."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from knowledge.mapper import kb
from rag.corpus import build_corpus
from rag.retriever import TfidfRetriever, VectorRetriever
from rag.embeddings import embed_text, EMBEDDING_DIMENSIONS


def test_baseline_records_preserved():
    assert "CVE-2024-3400" in kb.cve_db
    assert kb.cve_db["CVE-2024-3400"]["cvss_v3"] == 10.0
    assert "T1190" in kb.attack_db
    assert "CWE-77" in kb.cwe_db
    assert "CAPEC-88" in kb.capec_db
    assert "A01:2021" in kb.owasp_db
    assert kb.is_kev("CVE-2024-3400") is not None


def test_knowledge_base_expansion_scale():
    assert len(kb.cve_db) >= 1000
    assert len(kb.attack_db) >= 500
    assert len(kb.cwe_db) >= 800
    assert len(kb.capec_db) >= 500
    assert len(kb.owasp_db) >= 20


def test_cve_enrichment_mapping_chain():
    enrichment = kb.enrich_from_cves(["CVE-2024-3400"])
    assert "CWE-77" in enrichment["cwe_ids"] or "CWE-78" in enrichment["cwe_ids"]
    assert len(enrichment["capec_ids"]) > 0
    assert len(enrichment["attack_techniques"]) > 0
    assert len(enrichment["owasp_categories"]) > 0
    assert enrichment["kev_listed"] is True
    assert enrichment["max_cvss"] == 10.0


def test_owasp_lookup_is_case_insensitive():
    meta = kb.lookup_owasp("a01:2021")
    assert meta["name"] == "Broken Access Control"
    assert kb.lookup_owasp("A01:2021")["name"] == "Broken Access Control"


def test_corpus_and_retriever():
    corpus = build_corpus()
    assert len(corpus) >= 3000
    retriever = TfidfRetriever()
    retriever.index(corpus)
    assert retriever.is_ready()

    results = retriever.retrieve("SQL injection", k=5)
    assert len(results) > 0
    titles = [doc["title"] for doc, score in results]
    assert any("SQL Injection" in title for title in titles)


def test_deterministic_embedding_generation():
    sample_text = "CISA Known Exploited Vulnerabilities catalog requires rapid patch deployment."
    vector = embed_text(sample_text)
    assert len(vector) == EMBEDDING_DIMENSIONS
    # Check that vector is normalized (unit length approximately 1.0)
    norm = sum(v * v for v in vector) ** 0.5
    assert abs(norm - 1.0) < 1e-4


def test_vector_retriever_rejects_mixed_dimensions():
    retriever = VectorRetriever()
    try:
        retriever.index(
            [{"id": "a", "text": "a"}, {"id": "b", "text": "b"}],
            embeddings=[[1.0, 0.0], [1.0, 0.0, 0.0]],
            embedder=lambda texts: [[1.0, 0.0] for _ in texts],
        )
    except ValueError as exc:
        assert "Mixed embedding dimensions" in str(exc)
    else:
        raise AssertionError("mixed dimensions must be rejected")


def test_newly_added_cves_and_juice_shop_in_kb():
    target_cves = [
        "CVE-2026-34197",
        "CVE-2024-28752",
        "CVE-2024-39907",
        "CVE-2017-12636",
        "CVE-2017-9993",
    ]
    for cve_id in target_cves:
        assert cve_id in kb.cve_db, f"{cve_id} missing from cve_db"
        meta = kb.cve_db[cve_id]
        assert meta["cvss_v3"] > 0
        assert meta["severity"].upper() in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert len(meta["description"]) > 20
        assert len(meta.get("references", [])) > 0

    from knowledge.reference_docs import REFERENCE_DOCS
    titles = [doc["title"] for doc in REFERENCE_DOCS]
    assert any("Juice Shop" in t for t in titles)
    assert any("CVE-2026-34197" in t for t in titles)
    assert any("CVE-2024-28752" in t for t in titles)
    assert any("CVE-2024-39907" in t for t in titles)
    assert any("CVE-2017-12636" in t for t in titles)
    assert any("CVE-2017-9993" in t for t in titles)

