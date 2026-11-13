"""Import CysekRAG corpus-derived questions into Watch Fortress eval schema.

The source data remains corpus-derived. This command preserves source hashes
and intentionally does not invent human review, approved citations, or answer
quality labels.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


_PREFIXES = ("CVE", "CWE", "CAPEC")


def _watch_fortress_id(value: str) -> str:
    value = value.strip()
    upper = value.upper()
    for prefix in _PREFIXES:
        if upper.startswith(f"{prefix}-"):
            return f"{prefix.lower()}:{upper}"
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def convert(source: Path, output: Path, split_manifest: Path | None = None) -> dict:
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError("source_dataset_empty")
    source_hash = _sha256(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    counts = {"development": 0, "held_out_test": 0}
    skipped_unanswerable = 0
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for source_row in rows:
            split = {"dev": "development", "test": "held_out_test"}.get(source_row.get("split"))
            if split is None:
                raise ValueError(f"invalid_source_split:{source_row.get('split')}")
            evidence = [_watch_fortress_id(value) for value in source_row.get("gold_evidence_ids", [])]
            if not evidence:
                if not source_row.get("answerable", False):
                    skipped_unanswerable += 1
                    continue
                raise ValueError(f"missing_gold_evidence:{source_row.get('question_id')}")
            row = {
                "case_id": f"cysekrag-{source_row['question_id']}",
                "question": source_row["question"],
                "rubric": {
                    "expected_answer": source_row.get("gold_answer"),
                    "answerable": bool(source_row.get("answerable")),
                    "source_question_type": source_row.get("question_type"),
                },
                "gold_evidence_ids": evidence,
                # The source does not provide human-approved citations.
                "approved_citation_ids": [],
                "category": source_row.get("question_type", "unknown"),
                "safety_freshness": "corpus_derived",
                "split": split,
                "provenance": {
                    "review_status": "corpus_derived_not_human_reviewed",
                    "source_dataset": source.name,
                    "source_dataset_sha256": source_hash,
                    "source_question_id": source_row["question_id"],
                    "source_hash": source_row.get("source_hash"),
                    "source_corpus_sha256": source_row.get("corpus_sha256"),
                    "split_manifest_sha256": _sha256(split_manifest) if split_manifest else None,
                },
            }
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            counts[split] += 1
    os.replace(temporary, output)
    return {"source_rows": len(rows), "output_rows": sum(counts.values()), "skipped_unanswerable_without_evidence": skipped_unanswerable, "splits": counts, "output": str(output)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert CysekRAG questions to Watch Fortress evaluation JSONL")
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split-manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(convert(args.source, args.output, args.split_manifest), indent=2))


if __name__ == "__main__":
    main()
