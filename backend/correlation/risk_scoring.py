"""
Risk Prioritization Engine.

Combines the six factors the spec calls out - CVSS, exploit availability,
internet exposure, asset criticality, known active exploitation (CISA KEV),
and business impact (approximated here by asset criticality + internet
exposure, since "business impact" isn't a scanner-derived signal) - into a
single 0-100 risk score. Weighted, transparent, and reproducible: given the
same inputs you always get the same score, and every component's
contribution is returned alongside the total so an analyst can see WHY a
finding was ranked the way it was, not just the number.
"""
from __future__ import annotations
from models.database import Criticality

CRITICALITY_WEIGHT = {
    Criticality.LOW: 0.4,
    Criticality.MEDIUM: 0.6,
    Criticality.HIGH: 0.85,
    Criticality.CRITICAL: 1.0,
}


def compute_risk_score(
    cvss_score: float | None,
    exploit_available: bool,
    kev_listed: bool,
    internet_exposed: bool,
    asset_criticality: Criticality,
) -> dict:
    """Returns {"score": float 0-100, "components": {...}} so the reasoning
    behind every risk ranking is auditable, not a black box."""
    cvss = cvss_score if cvss_score is not None else 5.0  # neutral default when unscored
    base = (cvss / 10.0) * 40.0  # CVSS contributes up to 40 points

    exploit_pts = 20.0 if exploit_available else 0.0
    kev_pts = 20.0 if kev_listed else 0.0  # actively-exploited-in-the-wild is the strongest real-world signal
    exposure_pts = 12.0 if internet_exposed else 3.0
    criticality_pts = CRITICALITY_WEIGHT.get(asset_criticality, 0.6) * 8.0

    total = base + exploit_pts + kev_pts + exposure_pts + criticality_pts
    total = max(0.0, min(100.0, total))

    return {
        "score": round(total, 1),
        "components": {
            "cvss_contribution": round(base, 1),
            "exploit_available_contribution": exploit_pts,
            "kev_contribution": kev_pts,
            "exposure_contribution": exposure_pts,
            "asset_criticality_contribution": round(criticality_pts, 1),
        },
    }


def risk_band(score: float) -> str:
    if score >= 80:
        return "Critical Priority"
    if score >= 60:
        return "High Priority"
    if score >= 35:
        return "Medium Priority"
    return "Low Priority"
