"""Small, read-only fallback lookups for questions not covered by local RAG."""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request


NVD_URL = os.environ.get(
    "VULN_NVD_URL",
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
)
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_USER_AGENT = "Watch-Fortress/1.0"
logger = logging.getLogger(__name__)


def lookup_timeout() -> int:
    try:
        value = int(os.environ.get("RAG_NVD_LOOKUP_TIMEOUT_SECONDS", "3"))
    except ValueError:
        value = 3
    return min(max(value, 1), 10)


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
    headers = {
        "Accept": "application/json",
        "User-Agent": NVD_USER_AGENT,
    }
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=lookup_timeout()) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        logger.warning("NVD lookup HTTP failure: status=%s", exc.code)
        return None
    except urllib.error.URLError as exc:
        logger.warning("NVD lookup network failure: reason_type=%s", type(exc.reason).__name__)
        return None
    except TimeoutError:
        logger.warning("NVD lookup timed out")
        return None
    except OSError as exc:
        logger.warning("NVD lookup OS failure: error_type=%s", type(exc).__name__)
        return None
    except ValueError:
        logger.warning("NVD lookup returned invalid JSON")
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
