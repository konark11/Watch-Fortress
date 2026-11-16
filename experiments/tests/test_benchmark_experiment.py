from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from rag.benchmark_experiment import load_benchmark_questions, compare_three_ways


def test_load_benchmark_questions():
    questions = load_benchmark_questions()
    assert len(questions) == 86
    first = questions[0]
    assert first["question_id"] == "H-001"
    assert first["gold_answer"] == "CVE-2021-44228"
    assert "log4j" in first["product"].lower()
    assert first["target_cwe_class"] == "CWE-502"


def test_compare_three_ways_mock(monkeypatch):
    """Test 3-way RAG comparison pipeline structure with mock retrieval."""
    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    db = Session()

    # Mock persistent_retrieve to return deterministic candidate pool
    mock_candidates = [
        ({"id": "doc-1", "title": "CVE-2015-5254 ActiveMQ Deserialization", "text": "Apache ActiveMQ unsafe deserialization", "source": "nvd"}, 0.95),
        ({"id": "doc-2", "title": "CVE-2023-46604 ActiveMQ OpenWire", "text": "Apache ActiveMQ OpenWire flaw", "source": "nvd"}, 0.88),
        ({"id": "doc-3", "title": "CVE-2021-44228 Log4j JNDI RCE", "text": "Log4j JNDI remote code execution", "source": "nvd"}, 0.70),
    ]

    monkeypatch.setattr(
        "rag.benchmark_experiment.persistent_retrieve",
        lambda db, query, criteria, k: mock_candidates,
    )
    monkeypatch.setattr(
        "rag.benchmark_experiment.ensure_indexed",
        lambda db: None,
    )

    result = compare_three_ways(
        db=db,
        question_text="Which Apache ActiveMQ flaw allows deserialization RCE?",
        gold_cve="CVE-2015-5254",
        top_k=2,
    )

    assert result["gold_cve"] == "CVE-2015-5254"
    assert len(result["arms"]) == 3
    
    arm1 = result["arms"][0]
    assert arm1["id"] == "hybrid_rag"
    assert arm1["hit"] is True
    assert arm1["rank"] == 1
    assert arm1["total_tokens"] > 0
    assert "estimated_cost_usd" in arm1

    arm2 = result["arms"][1]
    assert arm2["id"] == "hybrid_reranker"
    assert arm2["hit"] is True

    arm3 = result["arms"][2]
    assert arm3["id"] == "hybrid_jev_reranker"
    assert arm3["hit"] is True
    assert arm3["rank"] == 1
