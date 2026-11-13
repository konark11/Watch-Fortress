import json

import pytest

from observability import redact_url, set_correlation, inject_job_context, extract_job_context
from rag.evaluation import load_reviewed_dataset, percentile, evaluate
from rag.import_cysekrag_eval import convert


def _row(case_id="case-1", split="development"):
    return {
        "case_id": case_id,
        "question": "reviewed question",
        "rubric": {"criteria": ["evidence"]},
        "gold_evidence_ids": ["doc:1"],
        "approved_citation_ids": ["doc:1"],
        "category": "security",
        "safety_freshness": "reviewed",
        "split": split,
        "provenance": {"reviewer": "reviewer-1", "reviewed_at": "2026-01-01"},
    }


def test_redaction_and_job_correlation():
    assert "secret-value" not in redact_url("/x?api_key=secret-value")
    set_correlation("corr-test")
    carrier = inject_job_context({})
    extract_job_context(carrier)
    assert carrier["correlation_id"] == "corr-test"


def test_dataset_rejects_duplicate_and_missing_provenance(tmp_path):
    path = tmp_path / "dataset.jsonl"
    path.write_text(json.dumps(_row()) + "\n" + json.dumps(_row()) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_reviewed_dataset(path)
    invalid = _row()
    invalid.pop("provenance")
    path.write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(ValueError, match="provenance"):
        load_reviewed_dataset(path)


def test_dataset_keeps_splits_separate(tmp_path):
    path = tmp_path / "dataset.jsonl"
    path.write_text(json.dumps(_row("dev", "development")) + "\n" + json.dumps(_row("test", "held_out_test")), encoding="utf-8")
    assert [row["case_id"] for row in load_reviewed_dataset(path, split="development")] == ["dev"]
    assert [row["case_id"] for row in load_reviewed_dataset(path, split="held_out_test")] == ["test"]


def test_percentile_uses_documented_linear_interpolation():
    assert percentile([10, 20, 30, 40], 50) == 25
    assert percentile([10, 20, 30, 40], 95) == 38.5


def test_evaluation_rejects_non_positive_k(tmp_path):
    path = tmp_path / "dataset.jsonl"
    path.write_text(json.dumps(_row()), encoding="utf-8")
    with pytest.raises(ValueError, match="positive"):
        evaluate(str(path), k=0, split="development")


def test_corpus_derived_dataset_is_accepted_but_not_marked_reviewed(tmp_path):
    source = tmp_path / "source.jsonl"
    source.write_text(json.dumps({
        "question_id": "Q-1", "question": "Which CVE?", "gold_answer": "CVE-2021-44228",
        "gold_evidence_ids": ["CVE-2021-44228", "CWE-502"], "answerable": True,
        "question_type": "cve", "split": "dev", "source_hash": "x", "corpus_sha256": "abc",
    }) + "\n", encoding="utf-8")
    output = tmp_path / "converted.jsonl"
    convert(source, output)
    row = load_reviewed_dataset(output, split="development")[0]
    assert row["gold_evidence_ids"] == ["cve:CVE-2021-44228", "cwe:CWE-502"]
    assert row["approved_citation_ids"] == []
    assert row["provenance"]["review_status"] == "corpus_derived_not_human_reviewed"
