"""Generic CSV/JSON catch-all parser for custom scripts or scanners not
explicitly supported, plus the parser registry with format auto-detection."""
from __future__ import annotations
import csv
import io
import json
from parsers.common import ParseResult, ParsedHost, ParsedFinding

SEVERITY_ALIASES = {"informational": "info", "moderate": "medium", "severe": "high"}


def _normalize_severity(v: str) -> str:
    v = (v or "info").strip().lower()
    return SEVERITY_ALIASES.get(v, v) if SEVERITY_ALIASES.get(v, v) in {"info", "low", "medium", "high", "critical"} else "info"


def parse_generic_csv(text: str) -> ParseResult:
    result = ParseResult()
    reader = csv.DictReader(io.StringIO(text))
    hosts_seen: dict[str, ParsedHost] = {}
    for row in reader:
        lower = {k.strip().lower(): v for k, v in row.items() if k}
        ip = lower.get("host") or lower.get("ip") or lower.get("asset") or lower.get("target", "")
        if not ip:
            continue
        if ip not in hosts_seen:
            hosts_seen[ip] = ParsedHost(ip_address=ip)
        cve_raw = lower.get("cve") or lower.get("cve_id") or lower.get("cves", "")
        cve_ids = [c.strip().upper() for c in cve_raw.replace(";", ",").split(",") if c.strip()] if cve_raw else []
        port_val = lower.get("port", "")
        try:
            port_num = int(port_val) if port_val else None
        except ValueError:
            port_num = None
        cvss_val = lower.get("cvss") or lower.get("cvss_score", "")
        try:
            cvss_score = float(cvss_val) if cvss_val else None
        except ValueError:
            cvss_score = None

        result.findings.append(ParsedFinding(
            asset_ip=ip,
            title=lower.get("title") or lower.get("name") or lower.get("finding", "Custom finding"),
            description=lower.get("description", ""),
            severity=_normalize_severity(lower.get("severity", "info")),
            cvss_score=cvss_score,
            port_number=port_num,
            cve_ids=cve_ids,
            plugin_id="custom:csv",
            solution=lower.get("solution") or lower.get("remediation", ""),
            raw_data=dict(row),
        ))
    result.hosts = list(hosts_seen.values())
    return result


def parse_generic_json(text: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return result
    records = data if isinstance(data, list) else data.get("findings", data.get("results", [data]))
    hosts_seen: dict[str, ParsedHost] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        lower = {k.lower(): v for k, v in rec.items()}
        ip = lower.get("host") or lower.get("ip") or lower.get("asset") or lower.get("target", "")
        if not ip:
            continue
        if ip not in hosts_seen:
            hosts_seen[ip] = ParsedHost(ip_address=str(ip))
        cve_ids = lower.get("cve_ids") or lower.get("cves") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cve_ids = [str(c).upper() for c in cve_ids]

        result.findings.append(ParsedFinding(
            asset_ip=str(ip),
            title=str(lower.get("title") or lower.get("name") or "Custom finding"),
            description=str(lower.get("description", "")),
            severity=_normalize_severity(str(lower.get("severity", "info"))),
            cvss_score=float(lower["cvss_score"]) if lower.get("cvss_score") is not None else None,
            port_number=int(lower["port"]) if lower.get("port") else None,
            cve_ids=cve_ids,
            plugin_id="custom:json",
            solution=str(lower.get("solution", "")),
            raw_data=rec,
        ))
    result.hosts = list(hosts_seen.values())
    return result
