from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

FINDING_COLUMNS = {
    "finding_id", "scanner", "asset_id", "ip", "port", "protocol",
    "service", "cve", "title", "severity", "description",
}
PAIR_COLUMNS = {"pair_id", "finding_a", "finding_b", "label", "split", "provenance"}
LABELS = {"SAME", "RELATED", "DIFFERENT"}
SPLITS = {"train", "test"}
PROTOCOLS = {"tcp", "udp"}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    scanner: str
    asset_id: str
    ip: str
    port: str
    protocol: str
    service: str
    cve: str
    title: str
    severity: str
    description: str


@dataclass(frozen=True)
class Pair:
    pair_id: str
    finding_a: str
    finding_b: str
    label: str
    split: str
    provenance: str


@dataclass
class LoadedData:
    findings: dict[str, Finding]
    pairs: list[Pair]
    errors: list[str]
    warnings: list[str]


def _read_csv(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                return [], [f"{path}: missing CSV header"]
            return list(reader), [f"{path}: missing required columns: {sorted(set())}"] if not reader.fieldnames else []
    except OSError as exc:
        return [], [f"{path}: cannot read file: {exc}"]


def load_data(findings_path: str | Path, pairs_path: str | Path) -> LoadedData:
    findings_file, pairs_file = Path(findings_path), Path(pairs_path)
    finding_rows, finding_errors = _read_csv(findings_file)
    pair_rows, pair_errors = _read_csv(pairs_file)
    errors = finding_errors + pair_errors
    warnings: list[str] = []

    finding_headers = set(finding_rows[0]) if finding_rows else set()
    pair_headers = set(pair_rows[0]) if pair_rows else set()
    if finding_rows and (missing := FINDING_COLUMNS - finding_headers):
        errors.append(f"{findings_file}: missing required columns: {sorted(missing)}")
    if pair_rows and (missing := PAIR_COLUMNS - pair_headers):
        errors.append(f"{pairs_file}: missing required columns: {sorted(missing)}")

    findings: dict[str, Finding] = {}
    for line, row in enumerate(finding_rows, start=2):
        finding_id = (row.get("finding_id") or "").strip()
        if not finding_id:
            errors.append(f"{findings_file}:{line}: finding_id is required")
            continue
        if finding_id in findings:
            errors.append(f"{findings_file}:{line}: duplicate finding_id {finding_id}")
            continue
        protocol = (row.get("protocol") or "").strip().lower()
        if protocol not in PROTOCOLS:
            errors.append(f"{findings_file}:{line}: protocol must be tcp or udp, got {protocol!r}")
        findings[finding_id] = Finding(*(row.get(column, "").strip() for column in (
            "finding_id", "scanner", "asset_id", "ip", "port", "protocol",
            "service", "cve", "title", "severity", "description",
        )))

    pairs: list[Pair] = []
    pair_ids: set[str] = set()
    for line, row in enumerate(pair_rows, start=2):
        pair_id = (row.get("pair_id") or "").strip()
        if not pair_id:
            errors.append(f"{pairs_file}:{line}: pair_id is required")
            continue
        if pair_id in pair_ids:
            errors.append(f"{pairs_file}:{line}: duplicate pair_id {pair_id}")
            continue
        pair_ids.add(pair_id)
        finding_a = (row.get("finding_a") or "").strip()
        finding_b = (row.get("finding_b") or "").strip()
        label = (row.get("label") or "").strip().upper()
        split = (row.get("split") or "").strip().lower()
        provenance = (row.get("provenance") or "").strip()
        if finding_a not in findings:
            errors.append(f"{pairs_file}:{line}: unknown finding_a {finding_a}")
        if finding_b not in findings:
            errors.append(f"{pairs_file}:{line}: unknown finding_b {finding_b}")
        if label not in LABELS:
            errors.append(f"{pairs_file}:{line}: label must be one of {sorted(LABELS)}, got {label!r}")
        if split not in SPLITS:
            errors.append(f"{pairs_file}:{line}: split must be train or test, got {split!r}")
        if provenance != "REAL_SCAN":
            warnings.append(f"{pairs_file}:{line}: {pair_id} provenance is {provenance or '<missing>'}, not REAL_SCAN")
        pairs.append(Pair(pair_id, finding_a, finding_b, label, split, provenance))

    train_assets = {
        asset
        for pair in pairs if pair.split == "train"
        for asset in _pair_assets(pair, findings)
    }
    test_assets = {
        asset
        for pair in pairs if pair.split == "test"
        for asset in _pair_assets(pair, findings)
    }
    overlap = train_assets & test_assets
    if overlap:
        affected = sum(
            1 for pair in pairs
            if pair.split == "test" and set(_pair_assets(pair, findings)) & overlap
        )
        warnings.append(
            f"split integrity: {len(overlap)} asset(s) occur in both train and test; "
            f"{affected} test pair(s) affected"
        )
    return LoadedData(findings, pairs, errors, warnings)


def _pair_assets(pair: Pair, findings: dict[str, Finding]) -> Iterable[str]:
    assets = []
    for finding_id in (pair.finding_a, pair.finding_b):
        finding = findings.get(finding_id)
        if finding:
            assets.append(finding.asset_id)
    return assets
