"""Offline relevance and noise reduction for security-document ingestion."""
from __future__ import annotations

import re


SECURITY_TERMS = {
    "attack", "authentication", "authorization", "breach", "cve", "credential",
    "exploit", "firewall", "incident", "malware", "mitre", "network", "patch",
    "phishing", "privilege", "ransomware", "remediation", "risk", "security",
    " vulnerability", "threat", "token", "endpoint", "ioc", "detection",
}
NOISE_TERMS = {"table of contents", "copyright", "all rights reserved", "references"}


def clean_text(text: str) -> str:
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    seen: set[str] = set()
    cleaned: list[str] = []
    for line in lines:
        normalized = line.casefold()
        if not line or normalized in seen:
            continue
        seen.add(normalized)
        cleaned.append(line)
    return "\n".join(cleaned)


def relevance_score(text: str) -> float:
    lowered = f" {text.casefold()} "
    words = set(re.findall(r"[a-z0-9][a-z0-9_-]{2,}", lowered))
    matches = sum(term.strip() in words or term in lowered for term in SECURITY_TERMS)
    noise = sum(term in lowered for term in NOISE_TERMS)
    return round(max(0.0, min(1.0, matches / 8 - noise * 0.15)), 3)


def is_indexable(text: str, score: float) -> bool:
    # Keep short chunks containing a security identifier, even when prose is sparse.
    has_identifier = bool(re.search(r"\b(?:CVE-\d{4}-\d+|T\d{4}(?:\.\d{3})?)\b", text, re.I))
    return score >= 0.125 or has_identifier
