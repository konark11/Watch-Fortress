from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from models.database import get_db, Asset, Port, SSLCertificate, Vulnerability, Finding, User, Criticality
from auth.security import get_current_user, require_permission
from auth.audit import log_action
from api.schemas import AssetUpdate

router = APIRouter()


@router.get("")
def list_assets(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    assets = db.query(Asset).all()
    out = []
    for a in assets:
        vuln_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.asset_id == a.id).scalar() or 0
        max_risk = db.query(func.max(Vulnerability.risk_score)).filter(Vulnerability.asset_id == a.id).scalar() or 0
        out.append({
            "id": a.id, "ip_address": a.ip_address, "hostname": a.hostname, "os_name": a.os_name,
            "criticality": a.criticality.value, "internet_exposed": a.internet_exposed,
            "tags": a.tags, "first_seen": a.first_seen, "last_seen": a.last_seen,
            "vulnerability_count": vuln_count, "max_risk_score": round(max_risk, 1),
            "port_count": db.query(func.count(Port.id)).filter(Port.asset_id == a.id).scalar() or 0,
        })
    return {"assets": out, "count": len(out)}


@router.get("/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    ports = db.query(Port).filter(Port.asset_id == asset_id).all()
    certs = db.query(SSLCertificate).filter(SSLCertificate.asset_id == asset_id).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id).order_by(Vulnerability.risk_score.desc()).all()
    return {
        "id": asset.id, "ip_address": asset.ip_address, "hostname": asset.hostname,
        "os_name": asset.os_name, "os_accuracy": asset.os_accuracy,
        "criticality": asset.criticality.value, "internet_exposed": asset.internet_exposed,
        "tags": asset.tags, "notes": asset.notes,
        "first_seen": asset.first_seen, "last_seen": asset.last_seen,
        "ports": [{"port": p.port_number, "protocol": p.protocol, "service": p.service_name, "product": p.product, "version": p.version} for p in ports],
        "ssl_certificates": [{"port": c.port_number, "subject": c.subject, "issuer": c.issuer, "valid_to": c.valid_to, "self_signed": c.self_signed} for c in certs],
        "vulnerabilities": [
            {"id": v.id, "title": v.canonical_title, "severity": v.severity.value, "risk_score": v.risk_score, "cve_ids": v.cve_ids, "status": v.status.value}
            for v in vulns
        ],
    }


@router.patch("/{asset_id}")
def update_asset(asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db), user: User = Depends(require_permission("asset.write"))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    if payload.criticality is not None:
        try:
            asset.criticality = Criticality(payload.criticality)
        except ValueError:
            raise HTTPException(400, "Invalid criticality value")
    if payload.internet_exposed is not None:
        asset.internet_exposed = payload.internet_exposed
    if payload.notes is not None:
        asset.notes = payload.notes
    if payload.tags is not None:
        asset.tags = payload.tags
    db.commit()
    log_action(db, user, "asset.update", target=f"asset:{asset.ip_address}", details=str(payload.dict(exclude_unset=True)))
    return {"ok": True}


@router.delete("/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("asset.write"))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    vuln_ids = [v.id for v in db.query(Vulnerability.id).filter(Vulnerability.asset_id == asset_id).all()]
    if vuln_ids:
        # Findings reference vulnerabilities loosely (nullable FK) - detach
        # rather than delete, so the raw scan history stays intact even
        # after the asset and its correlated vulnerabilities are gone.
        db.query(Finding).filter(Finding.vulnerability_id.in_(vuln_ids)).update({"vulnerability_id": None}, synchronize_session=False)
        db.query(Vulnerability).filter(Vulnerability.id.in_(vuln_ids)).delete(synchronize_session=False)

    db.query(Port).filter(Port.asset_id == asset_id).delete(synchronize_session=False)
    db.query(SSLCertificate).filter(SSLCertificate.asset_id == asset_id).delete(synchronize_session=False)

    ip = asset.ip_address
    db.delete(asset)
    db.commit()
    log_action(db, user, "asset.delete", target=f"asset:{ip}")
    return {"ok": True}
