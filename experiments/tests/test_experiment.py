from __future__ import annotations

import csv
from pathlib import Path

from experiments.evaluation import bootstrap_ci
from experiments.io import load_data
from experiments.methods import api_method, rule_predict


def _write_inputs(tmp_path: Path) -> tuple[Path, Path]:
    findings = tmp_path / "findings.csv"
    pairs = tmp_path / "pairs.csv"
    finding_rows = [
        ["A", "Nmap", "asset-1", "192.0.2.1", "80", "tcp", "http", "", "HTTP service detected", "info", "service detected"],
        ["B", "Nessus", "asset-1", "192.0.2.1", "80", "tcp", "http", "CVE-1", "Issue", "high", "issue"],
        ["C", "Nessus", "asset-1", "192.0.2.1", "80", "tcp", "http", "CVE-1", "Issue repeat", "high", "issue"],
        ["D", "Nessus", "asset-2", "192.0.2.2", "443", "tcp", "https", "", "Other", "low", "other"],
        ["E", "Nessus", "asset-1", "192.0.2.1", "80", "udp", "http", "", "Other", "low", "other"],
    ]
    with findings.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["finding_id", "scanner", "asset_id", "ip", "port", "protocol", "service", "cve", "title", "severity", "description"])
        writer.writerows(finding_rows)
    with pairs.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["pair_id", "finding_a", "finding_b", "label", "split", "provenance"])
        writer.writerows([
            ["p1", "A", "B", "RELATED", "train", "REAL_SCAN"],
            ["p2", "B", "C", "SAME", "train", "REAL_SCAN"],
            ["p3", "B", "D", "DIFFERENT", "test", "REAL_SCAN"],
        ])
    return findings, pairs


def test_csv_validation_and_split_integrity(tmp_path: Path):
    findings, pairs = _write_inputs(tmp_path)
    data = load_data(findings, pairs)
    assert data.errors == []
    assert any("both train and test" in warning for warning in data.warnings)


def test_rule_based_method_on_five_hand_checked_pairs(tmp_path: Path):
    findings_path, pairs_path = _write_inputs(tmp_path)
    data = load_data(findings_path, pairs_path)
    pairs = [
        ("A", "B", "RELATED"), ("B", "C", "SAME"), ("B", "D", "DIFFERENT"),
        ("A", "D", "DIFFERENT"), ("C", "D", "DIFFERENT"),
    ]
    for first, second, expected in pairs:
        result = rule_predict(type("Pair", (), {"finding_a": first, "finding_b": second})(), data.findings)
        assert result.label == expected


def test_bootstrap_ci_is_reproducible():
    truth = ["SAME", "RELATED", "DIFFERENT", "SAME"]
    predicted = ["SAME", "DIFFERENT", "DIFFERENT", "RELATED"]
    assert bootstrap_ci(truth, predicted, "macro_f1", 100, 7) == bootstrap_ci(truth, predicted, "macro_f1", 100, 7)


def test_api_method_is_not_run_without_key(monkeypatch):
    monkeypatch.delenv("MISSING_EXPERIMENT_KEY", raising=False)
    method, reason = api_method("M3", "https://example.invalid", "model", "MISSING_EXPERIMENT_KEY")
    assert method is None
    assert reason == "MISSING_EXPERIMENT_KEY is not set"


def test_api_method_accepts_direct_key_value():
    method, reason = api_method("M3", "https://example.invalid", "model", "sk-test-key")
    assert method is not None
    assert reason is None
