from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from sqlalchemy.orm import Session

from models.database import Finding, Port, Scan

FINDING_HEADERS = [
    "finding_id", "scanner", "asset_id", "ip", "port", "protocol",
    "service", "cve", "title", "severity", "description",
]
PAIR_HEADERS = ["pair_id", "finding_a", "finding_b", "label", "split", "provenance"]
DATA_DIR = Path(__file__).resolve().parent / "data"


def _asset_id(ip: str) -> str:
    return "LAB-" + ip.replace(".", "-").replace(":", "-")


def _protocol_service(db: Session, finding: Finding) -> tuple[str, str]:
    raw = finding.raw_data or {}
    protocol = str(raw.get("protocol", "tcp")).lower()
    service = str(raw.get("svc_name", "") or raw.get("service", ""))
    if finding.port_number:
        port = (
            db.query(Port)
            .join(Port.asset)
            .filter(Port.port_number == finding.port_number, Port.asset.has(ip_address=finding.asset_ip))
            .first()
        )
        if port:
            protocol = (port.protocol or protocol).lower()
            service = service or port.service_name or ""
    return protocol if protocol in {"tcp", "udp"} else "tcp", service


def sync_database_dataset(db: Session) -> dict[str, int]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    findings = db.query(Finding).order_by(Finding.id).all()
    rows = []
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for finding in findings:
        protocol, service = _protocol_service(db, finding)
        finding_id = f"DB-{finding.id:06d}"
        rows.append({
            "finding_id": finding_id,
            "scanner": finding.scanner_source.value if finding.scanner_source else "unknown",
            "asset_id": _asset_id(finding.asset_ip),
            "ip": finding.asset_ip or "",
            "port": finding.port_number or "",
            "protocol": protocol,
            "service": service,
            "cve": ";".join(finding.cve_ids or []),
            "title": finding.title or "",
            "severity": finding.severity.value if finding.severity else "info",
            "description": finding.description or "",
        })
        if finding.port_number:
            grouped[(_asset_id(finding.asset_ip), str(finding.port_number))].append(finding_id)

    with (DATA_DIR / "real_findings.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FINDING_HEADERS)
        writer.writeheader()
        writer.writerows(rows)

    pair_rows = []
    pair_number = 1
    for finding_ids in grouped.values():
        for index, finding_a in enumerate(finding_ids):
            for finding_b in finding_ids[index + 1:]:
                pair_rows.append({
                    "pair_id": f"CANDIDATE-{pair_number:06d}",
                    "finding_a": finding_a,
                    "finding_b": finding_b,
                    "label": "",
                    "split": "",
                    "provenance": "REAL_SCAN",
                })
                pair_number += 1
    with (DATA_DIR / "real_candidate_pairs.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PAIR_HEADERS)
        writer.writeheader()
        writer.writerows(pair_rows)
    return {"findings": len(rows), "candidate_pairs": len(pair_rows)}


def dataset_status() -> dict[str, object]:
    findings = DATA_DIR / "real_findings.csv"
    candidates = DATA_DIR / "real_candidate_pairs.csv"
    return {
        "findings_path": str(findings.relative_to(DATA_DIR.parent.parent)),
        "candidate_pairs_path": str(candidates.relative_to(DATA_DIR.parent.parent)),
        "findings_count": sum(1 for _ in findings.open(encoding="utf-8")) - 1 if findings.exists() else 0,
        "candidate_pairs_count": sum(1 for _ in candidates.open(encoding="utf-8")) - 1 if candidates.exists() else 0,
    }


def candidate_pairs() -> list[dict[str, str]]:
    path = DATA_DIR / "real_candidate_pairs.csv"
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        pairs = list(csv.DictReader(handle))
    findings_path = DATA_DIR / "real_findings.csv"
    if not findings_path.exists():
        return pairs
    with findings_path.open(encoding="utf-8", newline="") as handle:
        findings = {row["finding_id"]: row for row in csv.DictReader(handle)}
    for pair in pairs:
        for side in ("a", "b"):
            finding = findings.get(pair[f"finding_{side}"], {})
            pair[f"finding_{side}_details"] = {
                "scanner": finding.get("scanner", ""),
                "asset_id": finding.get("asset_id", ""),
                "ip": finding.get("ip", ""),
                "port": finding.get("port", ""),
                "service": finding.get("service", ""),
                "cve": finding.get("cve", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "description": finding.get("description", ""),
            }
    return pairs


def save_labeled_pairs(rows: list[dict[str, str]]) -> int:
    valid_labels = {"SAME", "RELATED", "DIFFERENT"}
    valid_splits = {"train", "test"}
    clean_rows = []
    for row in rows:
        if row.get("label") not in valid_labels or row.get("split") not in valid_splits:
            raise ValueError(f"{row.get('pair_id', '<unknown>')}: label and split are required")
        clean_rows.append({
            "pair_id": row["pair_id"],
            "finding_a": row["finding_a"],
            "finding_b": row["finding_b"],
            "label": row["label"],
            "split": row["split"],
            "provenance": "REAL_SCAN",
        })
    path = DATA_DIR / "real_labeled_pairs.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PAIR_HEADERS)
        writer.writeheader()
        writer.writerows(clean_rows)
    return len(clean_rows)
