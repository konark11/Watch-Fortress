"""Small, read-only fallback lookups for questions not covered by local RAG."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request


NVD_URL = os.environ.get(
    "VULN_NVD_URL",
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
)
LOOKUP_TIMEOUT = 8


def _description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    english = next((item["value"] for item in descriptions if item.get("lang") == "en"), "")
    return " ".join(english.split())


def lookup_question(question: str) -> dict | None:
    """Return one NVD document for an exact CVE or a useful keyword match."""
    cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", question, re.IGNORECASE)
    params = {"cveId": cve_match.group(0).upper()} if cve_match else {
        "keywordSearch": question[:180],
        "resultsPerPage": "1",
    }
    url = f"{NVD_URL}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=LOOKUP_TIMEOUT) as response:
            payload = json.loads(response.read())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve", {})
    cve_id = cve.get("id")
    description = _description(cve)
    if not cve_id or not description:
        return None
    metrics = cve.get("metrics", {})
    metric = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
    cvss = metric.get("cvssData", {})
    return {
        "id": f"nvd:{cve_id}",
        "source": "NVD (internet lookup)",
        "title": cve_id,
        "text": (
            f"{cve_id}: {description} "
            f"CVSS v3 score: {cvss.get('baseScore', 'not published')}. "
            f"Severity: {cvss.get('baseSeverity', 'not published')}."
        ),
    }
