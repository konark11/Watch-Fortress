"""
OpenVAS / Greenbone Vulnerability Management (GVM) XML report parser.

Handles the standard GVM XML export (`<report><results><result>...`),
where each <result> has a <host>, <port>, <nvt> (Network Vulnerability
Test) block with oid/cve/cvss_base, and a <threat>/<severity>.
"""
from __future__ import annotations
from xml.etree import ElementTree as ET
from parsers.common import ParseResult, ParsedHost, ParsedPort, ParsedFinding

THREAT_MAP = {"Log": "info", "Low": "low", "Medium": "medium", "High": "high", "Critical": "critical"}


def parse_openvas_xml(xml_text: str) -> ParseResult:
    result = ParseResult()
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result

    hosts_seen: dict[str, ParsedHost] = {}

    results_el = root.find(".//results")
    if results_el is None:
        results_el = root  # some exports have <result> at top level

    for result_el in results_el.findall(".//result"):
        host_el = result_el.find("host")
        ip = (host_el.text or "").strip() if host_el is not None else ""
        if not ip:
            continue

        if ip not in hosts_seen:
            hosts_seen[ip] = ParsedHost(ip_address=ip)

        port_text = result_el.findtext("port", default="")
        port_num = None
        protocol = "tcp"
        if port_text and "/" in port_text:
            num_part, proto_part = port_text.split("/", 1)
            if num_part.isdigit():
                port_num = int(num_part)
                protocol = proto_part.strip() or "tcp"
                if not any(p.port_number == port_num for p in hosts_seen[ip].ports):
                    hosts_seen[ip].ports.append(ParsedPort(port_number=port_num, protocol=protocol))

        nvt_el = result_el.find("nvt")
        name = result_el.findtext("name", default="") or (nvt_el.findtext("name", default="") if nvt_el is not None else "")
        oid = nvt_el.get("oid", "") if nvt_el is not None else ""

        cve_text = nvt_el.findtext("cve", default="") if nvt_el is not None else ""
        cve_ids = []
        if cve_text and cve_text.upper() != "NOCVE":
            cve_ids = [c.strip().upper() for c in cve_text.split(",") if c.strip()]

        cvss_text = nvt_el.findtext("cvss_base", default="") if nvt_el is not None else ""
        cvss_score = None
        if cvss_text:
            try:
                cvss_score = float(cvss_text)
            except ValueError:
                pass

        threat = result_el.findtext("threat", default="Log")
        severity = THREAT_MAP.get(threat, "info")

        description = result_el.findtext("description", default="") or ""
        solution = ""
        if nvt_el is not None:
            solution_el = nvt_el.find("solution")
            if solution_el is not None:
                solution = solution_el.text or ""

        if severity == "info" and not cve_ids:
            continue

        result.findings.append(ParsedFinding(
            asset_ip=ip,
            title=name or f"OpenVAS NVT {oid}",
            description=description[:2000],
            severity=severity,
            cvss_score=cvss_score,
            port_number=port_num,
            cve_ids=cve_ids,
            plugin_id=f"openvas:{oid}",
            solution=solution[:2000],
            raw_data={"oid": oid, "threat": threat},
        ))

    result.hosts = list(hosts_seen.values())
    return result
