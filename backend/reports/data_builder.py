"""
Builds the data structure every report format (PDF/HTML/DOCX/JSON) renders
from. Keeping ONE data-assembly step means all four output formats are
always in sync - a PDF and a DOCX generated from the same scope will never
disagree about the numbers, because they're rendering the same dict.
"""
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func

from models.database import Vulnerability, Asset, VulnStatus, Severity
from correlation.risk_scoring import risk_band

_COMPLIANCE_PATH = os.path.join(os.path.dirname(__file__), "..", "knowledge", "data", "compliance_mapping.json")
with open(_COMPLIANCE_PATH) as f:
    _COMPLIANCE_MAP = json.load(f)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_report_data(db: Session, report_type: str, scope_asset_ids: list[int] | None = None, compliance_framework: str | None = None) -> dict:
    query = db.query(Vulnerability).filter(Vulnerability.status != VulnStatus.FALSE_POSITIVE)
    if scope_asset_ids:
        query = query.filter(Vulnerability.asset_id.in_(scope_asset_ids))
    vulns = query.order_by(Vulnerability.risk_score.desc()).all()

    total_assets = db.query(func.count(Asset.id)).scalar() or 0
    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    for v in vulns:
        severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1

    kev_count = sum(1 for v in vulns if v.kev_listed)
    exploitable_count = sum(1 for v in vulns if v.exploit_available)
    top_risk = vulns[:10]

    asset_risk: dict[int, float] = {}
    for v in vulns:
        asset_risk[v.asset_id] = max(asset_risk.get(v.asset_id, 0), v.risk_score)
    critical_assets = sorted(asset_risk.items(), key=lambda kv: -kv[1])[:10]
    critical_assets_detail = []
    for asset_id, score in critical_assets:
        asset = db.get(Asset, asset_id)
        if asset:
            critical_assets_detail.append({"ip": asset.ip_address, "hostname": asset.hostname, "max_risk_score": score, "criticality": asset.criticality.value})

    findings_detail = []
    for v in vulns:
        asset = db.get(Asset, v.asset_id)
        findings_detail.append({
            "id": v.id,
            "title": v.canonical_title,
            "description": v.description or "",
            "severity": v.severity.value,
            "cvss_score": v.cvss_score,
            "risk_score": v.risk_score,
            "risk_band": risk_band(v.risk_score),
            "cve_ids": v.cve_ids or [],
            "cwe_ids": v.cwe_ids or [],
            "capec_ids": v.capec_ids or [],
            "attack_techniques": v.attack_techniques or [],
            "owasp_categories": v.owasp_categories or [],
            "exploit_available": v.exploit_available,
            "kev_listed": v.kev_listed,
            "asset_ip": asset.ip_address if asset else "unknown",
            "asset_hostname": asset.hostname if asset else "",
            "port": v.port_number,
            "remediation": v.remediation or "No specific remediation guidance recorded.",
            "status": v.status.value,
            "source_scanners": v.source_scanners or [],
        })

    data = {
        "report_type": report_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "All assets" if not scope_asset_ids else f"{len(scope_asset_ids)} selected asset(s)",
        "summary": {
            "total_assets": total_assets,
            "total_vulnerabilities": len(vulns),
            "severity_counts": severity_counts,
            "kev_count": kev_count,
            "exploitable_count": exploitable_count,
        },
        "top_risk_findings": [
            {"title": v.canonical_title, "severity": v.severity.value, "risk_score": v.risk_score, "asset_ip": (db.get(Asset, v.asset_id).ip_address if db.get(Asset, v.asset_id) else "unknown")}
            for v in top_risk
        ],
        "critical_assets": critical_assets_detail,
        "findings": findings_detail,
    }

    if report_type == "compliance" and compliance_framework:
        framework_map = _COMPLIANCE_MAP.get(compliance_framework, {})
        compliance_rows = []
        for v in vulns:
            controls = set()
            for owasp_id in (v.owasp_categories or []):
                controls.update(framework_map.get(owasp_id, []))
            if not controls:
                controls.update(framework_map.get("default", []))
            compliance_rows.append({
                "finding": v.canonical_title,
                "severity": v.severity.value,
                "asset_ip": (db.get(Asset, v.asset_id).ip_address if db.get(Asset, v.asset_id) else "unknown"),
                "controls": sorted(controls),
            })
        data["compliance_framework"] = compliance_framework
        data["compliance_rows"] = compliance_rows

    return data
