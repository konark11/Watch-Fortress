"""Reproducible, provenance-backed evaluation of the production RAG path."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean


def _load_local_env() -> None:
    """Match the development environment loading used by the API entrypoint."""
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and not os.environ.get(key):
            os.environ[key] = value.strip().strip("\"'")


_load_local_env()

from models.database import SessionLocal
from rag.embeddings import active_embedding_metadata
from rag.llm_providers import provider_status
from rag.query_engine import ask, production_retrieve
from rag.reranker import status as reranker_status
from rag.settings import (
    DENSE_TOP_K, SPARSE_TOP_K, FUSION_K, RERANK_K, FINAL_EVIDENCE_K,
    EMBEDDING_MODEL, EMBEDDING_REVISION, RERANKER_MODEL,
)

VALID_SPLITS = {"development", "held_out_test"}
VALID_PURPOSES = {"development", "final-held-out"}
REQUIRED_FIELDS = {
    "case_id", "question", "rubric", "gold_evidence_ids",
    "approved_citation_ids", "category", "safety_freshness", "split", "provenance",
}


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_reviewed_dataset(path: str | Path, *, split: str | None = None) -> list[dict]:
    dataset = Path(path)
    if not dataset.is_file():
        raise ValueError("dataset_not_found")
    rows, seen = [], set()
    for line_number, line in enumerate(dataset.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid_json_line:{line_number}") from exc
        missing = REQUIRED_FIELDS - set(row)
        if missing:
            raise ValueError(f"missing_provenance_fields:{','.join(sorted(missing))}")
        case_id = row["case_id"]
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise ValueError("duplicate_case_id")
        if row["split"] not in VALID_SPLITS:
            raise ValueError("invalid_split")
        provenance = row["provenance"]
        if not isinstance(provenance, dict):
            raise ValueError("missing_review_provenance")
        review_status = provenance.get("review_status", "human_reviewed")
        if review_status == "human_reviewed":
            if not isinstance(provenance.get("reviewer"), str) or not provenance["reviewer"].strip() or not isinstance(provenance.get("reviewed_at"), str) or not provenance["reviewed_at"].strip():
                raise ValueError("missing_review_provenance")
        elif review_status == "corpus_derived_not_human_reviewed":
            if not isinstance(provenance.get("source_dataset"), str) or not provenance["source_dataset"].strip() or not isinstance(provenance.get("source_corpus_sha256"), str) or not provenance["source_corpus_sha256"].strip():
                raise ValueError("missing_corpus_provenance")
        else:
            raise ValueError("invalid_review_status")
        for field in ("gold_evidence_ids", "approved_citation_ids"):
            if not isinstance(row[field], list) or any(not isinstance(value, str) or not value.strip() for value in row[field]):
                raise ValueError("invalid_evidence_annotations")
        seen.add(case_id)
        rows.append(row)
    if split and split not in VALID_SPLITS:
        raise ValueError("invalid_split")
    selected = [row for row in rows if split is None or row["split"] == split]
    if not selected:
        raise ValueError("dataset_empty")
    return selected


def percentile(values: list[float], percentage: float) -> float:
    """Linear-interpolated percentile (0..100) over sorted observations."""
    if not values:
        raise ValueError("percentile_empty")
    if not 0 <= percentage <= 100:
        raise ValueError("percentile_invalid")
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentage / 100
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _git_revision() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _ndcg(ids: list[str], gold: set[str], k: int) -> float:
    ranked = ids[:k]
    dcg = sum(1.0 / math.log2(index + 2) for index, item in enumerate(ranked) if item in gold)
    ideal = sum(1.0 / math.log2(index + 2) for index in range(min(len(gold), k)))
    return dcg / ideal if ideal else 0.0


def _safe_failure(exc: Exception) -> str:
    return type(exc).__name__


def evaluate(
    dataset_path: str,
    output_path: str | None = None,
    k: int = FINAL_EVIDENCE_K,
    split: str | None = None,
    *,
    purpose: str = "development",
    answer_mode: bool = False,
) -> dict:
    if k <= 0:
        raise ValueError("k_must_be_positive")
    if purpose not in VALID_PURPOSES:
        raise ValueError("invalid_run_purpose")
    if purpose == "final-held-out" and split != "held_out_test":
        raise ValueError("final_held_out_requires_held_out_split")
    dataset = Path(dataset_path)
    rows = load_reviewed_dataset(dataset, split=split)
    started = time.monotonic()
    reranker_before = reranker_status()
    db = SessionLocal()
    backend = None
    cases = []
    failures = []
    try:
        from rag.indexing.repository import latest_run
        from rag.retrieval.service import backend_name
        backend = backend_name(db)
        active_run = latest_run(db)
        if not active_run or active_run["state"] not in {"ready", "stale"}:
            raise RuntimeError("rag_index_not_ready")
        for row in rows:
            case_started = time.monotonic()
            try:
                if answer_mode:
                    result = ask(db, row["question"])
                    ids = [item["id"] for item in result.get("sources", []) if isinstance(item, dict) and isinstance(item.get("id"), str)]
                    observed = bool(result.get("sources"))
                    generation = {
                        "provider": result.get("provider") or provider_status().get("provider"),
                        "model": provider_status().get("model"),
                        "degradation_reason": (result.get("degradation") or {}).get("reason") if isinstance(result.get("degradation"), dict) else None,
                    }
                else:
                    ranked = production_retrieve(db, row["question"], k)
                    ids = [doc["id"] for doc, _ in ranked]
                    observed = False
                    generation = {"provider": None, "model": None, "degradation_reason": None}
                case = {
                    "case_id": row["case_id"],
                    "retrieved_evidence_ids": ids[:k],
                    "generated_citation_ids": ids[:k] if answer_mode and observed else [],
                    "latency_ms": round((time.monotonic() - case_started) * 1000, 2),
                    "generation": generation,
                    "error": None,
                }
            except Exception as exc:
                case = {
                    "case_id": row["case_id"], "retrieved_evidence_ids": [],
                    "generated_citation_ids": [], "latency_ms": round((time.monotonic() - case_started) * 1000, 2),
                    "generation": {"provider": None, "model": None, "degradation_reason": None},
                    "error": _safe_failure(exc),
                }
                failures.append({"case_id": row["case_id"], "reason": case["error"]})
            cases.append(case)
    except Exception as exc:
        report = {"status": "FAILED", "error": _safe_failure(exc)}
        if output_path:
            Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    finally:
        db.close()

    by_id = {row["case_id"]: row for row in rows}
    recall, mrr, ndcg = [], [], []
    citation_precision, citation_recall = [], []
    for case in cases:
        gold = set(by_id[case["case_id"]]["gold_evidence_ids"])
        ids = case["retrieved_evidence_ids"]
        recall.append(float(any(item in gold for item in ids[:k])))
        mrr.append(next((1 / index for index, value in enumerate(ids, 1) if value in gold), 0.0))
        ndcg.append(_ndcg(ids, gold, k))
        if answer_mode and case["generated_citation_ids"]:
            approved = set(by_id[case["case_id"]]["approved_citation_ids"])
            generated = set(case["generated_citation_ids"])
            citation_precision.append(len(generated & approved) / len(generated))
            citation_recall.append(len(generated & approved) / len(approved) if approved else 0.0)
    active = active_embedding_metadata()
    reranker_after = reranker_status()
    reranker_fallbacks = (
        reranker_after.get("stats", {}).get("fallbacks", 0)
        - reranker_before.get("stats", {}).get("fallbacks", 0)
    )
    report = {
        "status": "RUN",
        "run_purpose": purpose,
        "dataset": {
            "path": str(dataset), "sha256": _hash_file(dataset), "rows": len(rows),
            "split": split or rows[0]["split"],
            "reviewed_provenance": all(
                row["provenance"].get("review_status", "human_reviewed") == "human_reviewed"
                for row in rows
            ),
            "provenance_status": sorted({
                row["provenance"].get("review_status", "human_reviewed") for row in rows
            }),
        },
        "metrics": {
            "retrieval": {f"recall_at_{k}": mean(recall), "mrr": mean(mrr), f"ndcg_at_{k}": mean(ndcg)},
            "latency_ms": {"percentile_convention": "linear interpolation over sorted per-case latencies", "p50": percentile([c["latency_ms"] for c in cases], 50), "p95": percentile([c["latency_ms"] for c in cases], 95)},
            "answer_quality": "NOT RUN", "citation_precision": mean(citation_precision) if citation_precision else "NOT RUN", "citation_recall": mean(citation_recall) if citation_recall else "NOT RUN",
        },
        "provenance": {
            "timestamp": datetime.now(timezone.utc).isoformat(), "software": "watch-fortress", "python": platform.python_version(), "code_revision": _git_revision(),
            "retrieval_backend": backend,
            "embedding_model": active.get("model", EMBEDDING_MODEL), "embedding_revision": active.get("revision") or EMBEDDING_REVISION or None,
            "embedding_implementation": active.get("implementation"), "reranker_model": RERANKER_MODEL,
            "reranker": reranker_after,
            "generation": {"provider": provider_status().get("provider"), "model": provider_status().get("model")} if answer_mode else "NOT RUN",
            "retrieval_parameters": {"vector_candidate_k": DENSE_TOP_K, "lexical_candidate_k": SPARSE_TOP_K, "fusion_k": FUSION_K, "rerank_k": RERANK_K, "final_evidence_k": k, "filter_configuration": "production metadata criteria"},
            "index_run_id": str(active_run["public_id"]), "index_state": active_run["state"],
        },
        "failures": failures,
        "fallback_count": sum(1 for c in cases if c["generation"].get("degradation_reason")),
        "reranker_fallback_count": reranker_fallbacks,
        "duration_ms": round((time.monotonic() - started) * 1000, 2), "cases": cases,
    }
    if output_path:
        Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the persistent production RAG retrieval path")
    parser.add_argument("dataset")
    parser.add_argument("--output", default="rag-evaluation-results.json")
    parser.add_argument("-k", type=int, default=FINAL_EVIDENCE_K)
    parser.add_argument("--split", choices=sorted(VALID_SPLITS), required=True)
    parser.add_argument("--purpose", choices=sorted(VALID_PURPOSES), default="development")
    parser.add_argument("--answer-mode", action="store_true", help="Run the real assistant generation flow; otherwise retrieval-only")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset, args.output, args.k, args.split, purpose=args.purpose, answer_mode=args.answer_mode), indent=2))


if __name__ == "__main__":
    main()
