"""Evidence-based analysis of authentication failures.

AuditLog is the source of truth for event counts and entity correlations.
The knowledge retriever is used only for contextual attack-pattern matches;
it is never used to aggregate or invent log events.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from math import sqrt

from sqlalchemy.orm import Session

from models.database import AuditLog
from rag.corpus import build_corpus
from rag.retriever import TfidfRetriever


def _utc_day_bounds(day: datetime) -> tuple[datetime, datetime]:
    start = day.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=1)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _event_rows(db: Session, start: datetime, end: datetime) -> list[AuditLog]:
    rows = (
        db.query(AuditLog)
        .filter(
            AuditLog.action == "auth.login_failed",
            AuditLog.timestamp >= start.replace(tzinfo=None),
            AuditLog.timestamp < end.replace(tzinfo=None),
        )
        .order_by(AuditLog.timestamp.asc())
        .all()
    )
    return rows


def analyze_login_failures(db: Session, day: datetime | None = None) -> dict:
    """Analyze the UTC calendar day before *day*, compared with the prior day.

    The returned evidence is deterministic and contains the raw aggregate
    values needed for an LLM or UI to explain the conclusion.
    """
    reference = _as_utc(day or datetime.now(timezone.utc))
    yesterday_start, yesterday_end = _utc_day_bounds(reference - timedelta(days=1))
    previous_start = yesterday_start - timedelta(days=1)
    previous_end = yesterday_start
    failures = _event_rows(db, yesterday_start, yesterday_end)
    previous_failures = _event_rows(db, previous_start, previous_end)

    ip_counts = Counter(row.ip_address or "unknown" for row in failures)
    user_counts = Counter(row.username or "unknown" for row in failures)
    five_minute_counts = Counter(
        (_as_utc(row.timestamp) - yesterday_start).total_seconds() // 300
        for row in failures
    )
    top_ip, top_ip_count = ip_counts.most_common(1)[0] if ip_counts else (None, 0)
    top_user, top_user_count = user_counts.most_common(1)[0] if user_counts else (None, 0)
    peak_five_minute = max(five_minute_counts.values(), default=0)

    current_count = len(failures)
    previous_count = len(previous_failures)
    increase = current_count - previous_count
    rate_ratio = current_count / max(previous_count, 1)
    historical_counts = [
        len(_event_rows(db, yesterday_start - timedelta(days=offset), yesterday_end - timedelta(days=offset)))
        for offset in range(2, 8)
    ]
    baseline_mean = sum(historical_counts) / len(historical_counts) if historical_counts else 0
    baseline_stddev = sqrt(
        sum((count - baseline_mean) ** 2 for count in historical_counts) / len(historical_counts)
    ) if historical_counts else 0
    baseline_z = (current_count - baseline_mean) / baseline_stddev if baseline_stddev else (
        1.0 if current_count > baseline_mean else 0.0
    )

    rules: list[dict] = []
    score = 0.0
    if current_count > previous_count and current_count >= 5:
        rules.append({"name": "daily_volume_increase", "matched": True, "evidence": f"{current_count} failures vs {previous_count} the prior day"})
        score += 0.2
    if len(user_counts) >= 5 and top_ip_count >= 5:
        rules.append({"name": "credential_stuffing", "matched": True, "evidence": f"{top_ip_count} failures from {top_ip} across {len(user_counts)} usernames"})
        score += 0.35
    if len(ip_counts) >= 5 and top_user_count >= 5:
        rules.append({"name": "distributed_brute_force", "matched": True, "evidence": f"{top_user_count} failures for {top_user} across {len(ip_counts)} IPs"})
        score += 0.35
    if peak_five_minute >= 10:
        rules.append({"name": "temporal_burst", "matched": True, "evidence": f"{peak_five_minute} failures in one five-minute interval"})
        score += 0.2

    if score >= 0.55:
        conclusion = "likely attack activity"
    elif score >= 0.2 or (current_count >= 5 and baseline_z >= 2):
        conclusion = "suspicious and needs investigation"
    else:
        conclusion = "not enough evidence to classify as an attack"

    retriever = TfidfRetriever()
    retriever.index(build_corpus(db))
    context = retriever.retrieve(
        "credential stuffing brute force password spraying repeated failed logins", k=3
    )

    return {
        "period": {
            "start": yesterday_start.isoformat(),
            "end": yesterday_end.isoformat(),
            "timezone": "UTC",
        },
        "summary": {
            "failure_count": current_count,
            "previous_day_count": previous_count,
            "increase": increase,
            "rate_ratio": round(rate_ratio, 2),
            "baseline_mean": round(baseline_mean, 2),
            "baseline_z_score": round(baseline_z, 2),
            "unique_ips": len(ip_counts),
            "unique_users": len(user_counts),
            "peak_five_minute_count": peak_five_minute,
        },
        "conclusion": conclusion,
        "confidence": round(min(score + (0.15 if baseline_z >= 2 else 0), 0.95), 2),
        "rules": rules,
        "top_ips": [{"ip": ip, "failures": count} for ip, count in ip_counts.most_common(10)],
        "top_users": [{"username": user, "failures": count} for user, count in user_counts.most_common(10)],
        "knowledge_matches": [
            {"source": doc["source"], "title": doc["title"], "relevance": round(relevance, 3)}
            for doc, relevance in context
        ],
        "limitations": [
            "Analysis uses UTC calendar days.",
            "Audit data has no country, device, or successful-login context, so impossible-travel and geographic claims are not evaluated.",
            "The conclusion is a detection signal, not proof of attacker intent.",
        ],
    }


def render_login_analysis(analysis: dict) -> str:
    summary = analysis["summary"]
    rules = analysis["rules"]
    evidence = "; ".join(rule["evidence"] for rule in rules) or "No attack-pattern rule matched."
    return (
        f"On {analysis['period']['start'][:10]}, there were **{summary['failure_count']}** failed sign-ins. "
        f"The day before had **{summary['previous_day_count']}** "
        f"({summary['increase']:+d} change, {summary['rate_ratio']}x).\n\n"
        f"Assessment: **{analysis['conclusion']}**.\n\n"
        f"What led to this: {evidence}\n\n"
        "This is a warning sign, not proof of an attack. The available records do not show "
        "where sign-ins came from or whether any sign-in later succeeded."
    )
