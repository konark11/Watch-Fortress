from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from models.database import get_db, Vulnerability, Asset, Scan, Severity, VulnStatus, User
from auth.security import get_current_user
from knowledge.mapper import kb

router = APIRouter()


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    total_assets = db.query(func.count(Asset.id)).scalar() or 0
    total_vulns = db.query(func.count(Vulnerability.id)).scalar() or 0

    by_severity = dict(db.query(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity).all())
    by_severity = {k.value: v for k, v in by_severity.items()}
    for s in Severity:
        by_severity.setdefault(s.value, 0)

    by_status = dict(db.query(Vulnerability.status, func.count(Vulnerability.id)).group_by(Vulnerability.status).all())
    by_status = {k.value: v for k, v in by_status.items()}

    kev_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.kev_listed == True).scalar() or 0  # noqa: E712
    exploitable_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.exploit_available == True).scalar() or 0  # noqa: E712

    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    recent_scans = db.query(Scan).order_by(Scan.id.desc()).limit(10).all()

    # Attack surface: internet-exposed assets and their open ports
    exposed_assets = db.query(Asset).filter(Asset.internet_exposed == True).all()  # noqa: E712

    # Risk heatmap by asset criticality x severity
    heatmap_rows = (
        db.query(Asset.criticality, Vulnerability.severity, func.count(Vulnerability.id))
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .group_by(Asset.criticality, Vulnerability.severity)
        .all()
    )
    heatmap = [{"criticality": c.value, "severity": s.value, "count": n} for c, s, n in heatmap_rows]

    # Top ATT&CK techniques observed
    technique_counts: dict[str, int] = {}
    for (techs,) in db.query(Vulnerability.attack_techniques).all():
        for t in (techs or []):
            technique_counts[t] = technique_counts.get(t, 0) + 1
    technique_heatmap = [
        {"technique": t, **kb.lookup_attack(t), "count": c}
        for t, c in sorted(technique_counts.items(), key=lambda kv: -kv[1])[:12]
    ]

    return {
        "total_assets": total_assets,
        "total_vulnerabilities": total_vulns,
        "total_scans": total_scans,
        "internet_exposed_assets": len(exposed_assets),
        "by_severity": by_severity,
        "by_status": by_status,
        "kev_count": kev_count,
        "exploitable_count": exploitable_count,
        "risk_heatmap": heatmap,
        "technique_heatmap": technique_heatmap,
        "recent_scans": [
            {"id": s.id, "name": s.name, "scanner_type": s.scanner_type.value, "status": s.status.value, "findings_count": s.findings_count}
            for s in recent_scans
        ],
    }


@router.get("/trends")
def vulnerability_trends(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Vulnerability count over time, bucketed by first_seen date - powers
    the 'Vulnerability Trends' chart."""
    rows = (
        db.query(func.substr(Vulnerability.first_seen, 1, 10), Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(func.substr(Vulnerability.first_seen, 1, 10), Vulnerability.severity)
        .order_by(func.substr(Vulnerability.first_seen, 1, 10))
        .all()
    )
    return {"trends": [{"date": d, "severity": s.value, "count": c} for d, s, c in rows]}


@router.get("/attack-surface")
def attack_surface(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    from models.database import Port, SSLCertificate
    exposed = db.query(Asset).filter(Asset.internet_exposed == True).all()  # noqa: E712
    out = []
    for a in exposed:
        ports = db.query(Port).filter(Port.asset_id == a.id).all()
        certs = db.query(SSLCertificate).filter(SSLCertificate.asset_id == a.id).all()
        vuln_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.asset_id == a.id).scalar() or 0
        out.append({
            "ip_address": a.ip_address, "hostname": a.hostname, "criticality": a.criticality.value,
            "open_ports": [{"port": p.port_number, "service": p.service_name} for p in ports],
            "expired_or_self_signed_certs": sum(1 for c in certs if c.self_signed or c.expired),
            "vulnerability_count": vuln_count,
        })
    return {"exposed_assets": out, "count": len(out)}
