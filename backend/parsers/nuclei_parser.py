"""
Nuclei JSON output parser.

Nuclei (`nuclei -jsonl -o out.jsonl`) emits one JSON object per line
(or a JSON array with `-json`), each representing a single template
match against a target. Template `info.severity`, `info.classification`
(cve-id, cwe-id, cvss-score) map directly onto our normalized schema.
"""
from __future__ import annotations
import json
import re
from urllib.parse import urlparse
from parsers.common import ParseResult, ParsedHost, ParsedFinding

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def parse_nuclei_json(text: str) -> ParseResult:
    result = ParseResult()
    text = text.strip()
    records = []
    if text.startswith("["):
        try:
            records = json.loads(text)
        except json.JSONDecodeError:
            records = []
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    hosts_seen: dict[str, ParsedHost] = {}

    for rec in records:
        host_url = rec.get("host") or rec.get("matched-at") or rec.get("matched_at", "")
        ip = rec.get("ip", "")
        if not ip and host_url:
            parsed = urlparse(host_url if "://" in host_url else f"//{host_url}")
            ip = parsed.hostname or host_url

        if not ip:
            continue
        if ip not in hosts_seen:
            hosts_seen[ip] = ParsedHost(ip_address=ip, hostname=host_url if host_url != ip else "")

        port_num = None
        matched = rec.get("matched-at") or rec.get("matched_at", "")
        m = re.search(r":(\d+)(?:/|$)", matched)
        if m:
            port_num = int(m.group(1))

        info = rec.get("info", {})
        severity = str(info.get("severity", "info")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "info"

        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id", []) or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cve_ids = [c.upper() for c in cve_ids]

        cwe_ids = classification.get("cwe-id", []) or []
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        cvss_score = classification.get("cvss-score")
        try:
            cvss_score = float(cvss_score) if cvss_score is not None else None
        except (TypeError, ValueError):
            cvss_score = None

        template_id = rec.get("template-id", rec.get("templateID", ""))

        result.findings.append(ParsedFinding(
            asset_ip=ip,
            title=info.get("name", template_id or "Nuclei finding"),
            description=info.get("description", "")[:2000] if info.get("description") else "",
            severity=severity,
            cvss_score=cvss_score,
            port_number=port_num,
            cve_ids=cve_ids,
            plugin_id=f"nuclei:{template_id}",
            solution=info.get("remediation", ""),
            raw_data={"template_id": template_id, "cwe_ids": cwe_ids, "matched_at": matched, "tags": info.get("tags", [])},
        ))

    result.hosts = list(hosts_seen.values())
    return result
