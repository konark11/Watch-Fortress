from __future__ import annotations
import json
import urllib.request
import urllib.error
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models.database import get_db, ThreatIOC, IOCType, Vulnerability, Asset, User
from auth.security import get_current_user, require_permission
from auth.audit import log_action
from api.schemas import IOCCreate

router = APIRouter()


def _geolocate_ip(ip: str) -> dict | None:
    """Best-effort, free, no-API-key IP geolocation via ip-api.com, used
    only to plot an IOC on the threat map. This is intelligence *about*
    an indicator we already have - not a live scan of anything - so it's
    a single lightweight lookup, not something that needs to be batched
    or rate-limited beyond ip-api's own free-tier limit. Any failure
    (offline, private/reserved IP, rate limited) is swallowed - the IOC
    still gets saved, it just won't appear on the map."""
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon", timeout=4) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return {"lat": data.get("lat"), "lon": data.get("lon"), "country": data.get("country"), "city": data.get("city")}
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    return None


@router.get("/iocs")
def list_iocs(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    iocs = db.query(ThreatIOC).order_by(ThreatIOC.created_at.desc()).all()
    return {"iocs": [
        {
            "id": i.id, "ioc_type": i.ioc_type.value, "value": i.value,
            "threat_actor": i.threat_actor, "campaign": i.campaign, "source": i.source,
            "related_cves": i.related_cves or [], "confidence": i.confidence, "notes": i.notes,
            "latitude": i.latitude, "longitude": i.longitude, "country": i.country, "city": i.city,
            "created_by": i.created_by, "created_at": i.created_at,
        }
        for i in iocs
    ]}


@router.post("/iocs")
def create_ioc(payload: IOCCreate, db: Session = Depends(get_db), user: User = Depends(require_permission("ti.write"))):
    try:
        ioc_type = IOCType(payload.ioc_type)
    except ValueError:
        raise HTTPException(400, f"Invalid ioc_type. Must be one of {[t.value for t in IOCType]}")

    geo = _geolocate_ip(payload.value) if ioc_type == IOCType.IP else None

    ioc = ThreatIOC(
        ioc_type=ioc_type, value=payload.value, threat_actor=payload.threat_actor,
        campaign=payload.campaign, source=payload.source, related_cves=payload.related_cves,
        confidence=payload.confidence, notes=payload.notes, created_by=user.username,
        latitude=geo["lat"] if geo else None, longitude=geo["lon"] if geo else None,
        country=geo["country"] if geo else None, city=geo["city"] if geo else None,
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    log_action(db, user, "ti.create", target=f"ioc:{ioc.value}", details=payload.threat_actor or "")
    return {"id": ioc.id, "geolocated": geo is not None}


@router.delete("/iocs/{ioc_id}")
def delete_ioc(ioc_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("ti.write"))):
    ioc = db.get(ThreatIOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    db.delete(ioc)
    db.commit()
    log_action(db, user, "ti.delete", target=f"ioc:{ioc.value}")
    return {"ok": True}


@router.get("/map")
def map_points(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """IOCs that were successfully geolocated - what the threat-hunter map renders."""
    iocs = db.query(ThreatIOC).filter(ThreatIOC.ioc_type == IOCType.IP, ThreatIOC.latitude.isnot(None)).all()
    return {"points": [
        {
            "id": i.id, "value": i.value, "lat": i.latitude, "lon": i.longitude,
            "country": i.country, "city": i.city, "threat_actor": i.threat_actor,
            "campaign": i.campaign, "confidence": i.confidence,
        }
        for i in iocs
    ]}


@router.get("/exposure")
def exposure(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """The actual point of this module: cross-reference CVEs tied to IOCs
    we've encountered against our OWN vulnerability inventory, so an
    analyst can see 'this adversary/campaign is known to target CVEs we
    currently have open' instead of treating threat intel and vuln
    management as two disconnected tools."""
    iocs_with_cves = db.query(ThreatIOC).filter(ThreatIOC.related_cves.isnot(None)).all()
    vulns = db.query(Vulnerability).all()

    # Build cve -> [vulnerability] index once rather than re-scanning the
    # whole vulnerability table for every IOC.
    cve_to_vulns: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        for cve in (v.cve_ids or []):
            cve_to_vulns.setdefault(cve, []).append(v)

    matches = []
    for ioc in iocs_with_cves:
        for cve in (ioc.related_cves or []):
            for v in cve_to_vulns.get(cve, []):
                matches.append({
                    "cve": cve,
                    "ioc_id": ioc.id, "ioc_value": ioc.value, "ioc_type": ioc.ioc_type.value,
                    "threat_actor": ioc.threat_actor, "campaign": ioc.campaign,
                    "vulnerability_id": v.id, "vulnerability_title": v.canonical_title,
                    "severity": v.severity.value, "status": v.status.value, "asset_id": v.asset_id,
                })

    return {"matches": matches, "exposed_vulnerability_count": len({m["vulnerability_id"] for m in matches})}


# Ordered worst-to-best - lower number sorts first, and is used to rank
# both individual vulnerabilities and which asset needs attention first.
_TIER_PRIORITY = {
    "confirmed_active_targeted": 0,
    "confirmed_active": 1,
    "adversary_observed": 2,
    "dormant_exploit": 3,
    "no_known_exploit": 4,
}


@router.get("/exploit-pipeline")
def exploit_pipeline(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """The core Threat Intel <-> Vulnerability Management pipeline.

    For every vulnerability our own scans found, combine two independent
    signals into one priority tier:
      1) Exploit maturity - kev_listed means CISA has confirmed this CVE
         is being ACTIVELY exploited in the wild right now. exploit_available
         (without kev_listed) means a working exploit/PoC exists publicly
         but there's no confirmed active campaign using it - i.e. DORMANT:
         weaponizable, but not (yet) confirmed to be in use.
      2) Adversary evidence - whether any IOC we've actually logged from a
         real encounter references this exact CVE, meaning a specific
         threat actor/campaign has been tied to it against us or in an
         incident we responded to, independent of whether it's globally
         KEV-listed.

    A vulnerability that is both actively exploited AND tied to an IOC we
    encountered ourselves is the clearest "this is a real, current threat"
    signal the platform can produce - stronger than either signal alone.
    Rolled up per-asset (so an analyst can see which specific machines
    carry that risk) and organization-wide.
    """
    vulns = db.query(Vulnerability).all()
    iocs = db.query(ThreatIOC).filter(ThreatIOC.related_cves.isnot(None)).all()
    assets = {a.id: a for a in db.query(Asset).all()}

    cve_to_iocs: dict[str, list[ThreatIOC]] = {}
    for ioc in iocs:
        for cve in (ioc.related_cves or []):
            cve_to_iocs.setdefault(cve, []).append(ioc)

    tier_counts = {k: 0 for k in _TIER_PRIORITY}
    assets_map: dict[int, dict] = {}

    for v in vulns:
        matched_iocs, seen = [], set()
        for cve in (v.cve_ids or []):
            for ioc in cve_to_iocs.get(cve, []):
                if ioc.id not in seen:
                    seen.add(ioc.id)
                    matched_iocs.append({"ioc_id": ioc.id, "value": ioc.value, "threat_actor": ioc.threat_actor, "campaign": ioc.campaign, "matched_cve": cve})

        adversary_observed = len(matched_iocs) > 0

        if v.kev_listed and adversary_observed:
            tier = "confirmed_active_targeted"
        elif v.kev_listed:
            tier = "confirmed_active"
        elif adversary_observed:
            tier = "adversary_observed"
        elif v.exploit_available:
            tier = "dormant_exploit"
        else:
            tier = "no_known_exploit"

        tier_counts[tier] += 1
        if tier == "no_known_exploit":
            continue  # keep the per-asset payload focused on what this pipeline actually flags

        asset = assets.get(v.asset_id)
        bucket = assets_map.setdefault(v.asset_id, {
            "asset_id": v.asset_id,
            "ip_address": asset.ip_address if asset else "unknown",
            "hostname": asset.hostname if asset else None,
            "criticality": asset.criticality.value if asset else None,
            "vulnerabilities": [],
        })
        bucket["vulnerabilities"].append({
            "vulnerability_id": v.id, "title": v.canonical_title, "cve_ids": v.cve_ids or [],
            "severity": v.severity.value, "status": v.status.value, "risk_score": v.risk_score,
            "kev_listed": v.kev_listed, "exploit_available": v.exploit_available,
            "adversary_observed": adversary_observed, "matched_iocs": matched_iocs, "tier": tier,
        })

    asset_list = list(assets_map.values())
    for a in asset_list:
        a["vulnerabilities"].sort(key=lambda e: _TIER_PRIORITY.get(e["tier"], 9))
    asset_list.sort(key=lambda a: min((_TIER_PRIORITY.get(v["tier"], 9) for v in a["vulnerabilities"]), default=9))

    return {
        "overall": {
            "tier_counts": tier_counts,
            "total_vulnerabilities": len(vulns),
            "assets_affected": len(asset_list),
        },
        "assets": asset_list,
    }
