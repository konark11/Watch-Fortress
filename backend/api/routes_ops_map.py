from __future__ import annotations
import json
import urllib.request
import urllib.error
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models.database import get_db, OpsMarker, OpsMarkerType, OpsArrow, OpsArrowType, User
from auth.security import require_permission
from auth.audit import log_action
from api.schemas import OpsMarkerCreate, OpsArrowCreate

router = APIRouter()


def _lookup_elevation(lat: float, lon: float) -> float | None:
    """Best-effort real elevation via the free, no-key Open-Elevation API -
    same "free public API, no account needed, fails safe" pattern as the
    IP geolocation lookup in the Threat Intel module. A failure here
    (offline, service down) just means the marker saves without an
    altitude rather than blocking the save."""
    try:
        url = f"https://api.open-elevation.com/api/v1/lookup?locations={lat},{lon}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            results = data.get("results", [])
            if results:
                return results[0].get("elevation")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    return None

# Every route here requires ops.access, which - unlike ti.write or
# kb.write - is mapped to Administrator only. This entire module is meant
# to be reachable exclusively through the Admin panel, so both reads and
# writes are gated the same way rather than opening read access more
# broadly the way other modules do.


@router.get("/markers")
def list_markers(db: Session = Depends(get_db), _: User = Depends(require_permission("ops.access"))):
    markers = db.query(OpsMarker).order_by(OpsMarker.created_at.desc()).all()
    return {"markers": [
        {
            "id": m.id, "grid_id": m.grid_id, "latitude": m.latitude, "longitude": m.longitude,
            "marker_type": m.marker_type.value, "title": m.title, "notes": m.notes,
            "altitude": m.altitude, "source_label": m.source_label,
            "created_by": m.created_by, "created_at": m.created_at,
        }
        for m in markers
    ]}


@router.post("/markers")
def create_marker(payload: OpsMarkerCreate, db: Session = Depends(get_db), user: User = Depends(require_permission("ops.access"))):
    try:
        marker_type = OpsMarkerType(payload.marker_type)
    except ValueError:
        raise HTTPException(400, f"Invalid marker_type. Must be one of {[t.value for t in OpsMarkerType]}")

    altitude = _lookup_elevation(payload.latitude, payload.longitude)

    marker = OpsMarker(
        grid_id=payload.grid_id, latitude=payload.latitude, longitude=payload.longitude,
        marker_type=marker_type, title=payload.title, notes=payload.notes,
        altitude=altitude, source_label=payload.source_label, created_by=user.username,
    )
    db.add(marker)
    db.commit()
    db.refresh(marker)
    log_action(db, user, "ops.mark", target=f"grid:{marker.grid_id}", details=f"{marker_type.value} — {marker.title}")
    return {"id": marker.id, "altitude": altitude}


@router.delete("/markers/{marker_id}")
def delete_marker(marker_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("ops.access"))):
    marker = db.get(OpsMarker, marker_id)
    if not marker:
        raise HTTPException(404, "Marker not found")
    db.delete(marker)
    db.commit()
    log_action(db, user, "ops.unmark", target=f"grid:{marker.grid_id}", details=marker.title)
    return {"ok": True}


@router.get("/arrows")
def list_arrows(db: Session = Depends(get_db), _: User = Depends(require_permission("ops.access"))):
    arrows = db.query(OpsArrow).order_by(OpsArrow.created_at.desc()).all()
    return {"arrows": [
        {
            "id": a.id, "arrow_type": a.arrow_type.value, "label": a.label,
            "start_lat": a.start_lat, "start_lon": a.start_lon,
            "end_lat": a.end_lat, "end_lon": a.end_lon, "notes": a.notes,
            "created_by": a.created_by, "created_at": a.created_at,
        }
        for a in arrows
    ]}


@router.post("/arrows")
def create_arrow(payload: OpsArrowCreate, db: Session = Depends(get_db), user: User = Depends(require_permission("ops.access"))):
    try:
        arrow_type = OpsArrowType(payload.arrow_type)
    except ValueError:
        raise HTTPException(400, f"Invalid arrow_type. Must be one of {[t.value for t in OpsArrowType]}")

    arrow = OpsArrow(
        arrow_type=arrow_type, label=payload.label,
        start_lat=payload.start_lat, start_lon=payload.start_lon,
        end_lat=payload.end_lat, end_lon=payload.end_lon,
        notes=payload.notes, created_by=user.username,
    )
    db.add(arrow)
    db.commit()
    db.refresh(arrow)
    log_action(db, user, "ops.draw_arrow", target=arrow.label or f"{arrow_type.value} arrow", details=f"({arrow.start_lat:.1f},{arrow.start_lon:.1f}) -> ({arrow.end_lat:.1f},{arrow.end_lon:.1f})")
    return {"id": arrow.id}


@router.delete("/arrows/{arrow_id}")
def delete_arrow(arrow_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("ops.access"))):
    arrow = db.get(OpsArrow, arrow_id)
    if not arrow:
        raise HTTPException(404, "Arrow not found")
    db.delete(arrow)
    db.commit()
    log_action(db, user, "ops.remove_arrow", target=arrow.label or "arrow")
    return {"ok": True}
