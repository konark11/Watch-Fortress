"""
Nessus .nessus file parser (Tenable Nessus XML export format).

.nessus files are XML with a <Report><ReportHost> per scanned host and
one <ReportItem> per finding, with severity 0-4 (info/low/medium/high/critical)
and rich metadata: plugin ID, CVE list, CVSS base score, solution text.
"""
from __future__ import annotations
from xml.etree import ElementTree as ET
from parsers.common import ParseResult, ParsedHost, ParsedPort, ParsedFinding

SEVERITY_MAP = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def parse_nessus_xml(xml_text: str) -> ParseResult:
    result = ParseResult()
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result

    for report_el in root.findall(".//Report"):
        for host_el in report_el.findall("ReportHost"):
            ip = host_el.get("name", "")
            hostname = ""
            os_name = ""

            for tag_el in host_el.findall("./HostProperties/tag"):
                name = tag_el.get("name", "")
                if name == "host-ip" and not ip:
                    ip = tag_el.text or ""
                elif name in ("host-fqdn", "hostname"):
                    hostname = tag_el.text or hostname
                elif name == "operating-system":
                    os_name = tag_el.text or ""

            if not ip:
                continue

            parsed_host = ParsedHost(ip_address=ip, hostname=hostname, os_name=os_name)
            seen_ports = set()

            for item_el in host_el.findall("ReportItem"):
                port_num = int(item_el.get("port", "0"))
                protocol = item_el.get("protocol", "tcp")
                svc_name = item_el.get("svc_name", "")
                severity_num = item_el.get("severity", "0")
                severity = SEVERITY_MAP.get(severity_num, "info")
                plugin_id = item_el.get("pluginID", "")
                plugin_name = item_el.get("pluginName", "")

                if port_num and port_num not in seen_ports:
                    seen_ports.add(port_num)
                    parsed_host.ports.append(ParsedPort(
                        port_number=port_num, protocol=protocol, service_name=svc_name,
                    ))

                # Plugin family "Port scanners"/"Settings" entries are informational
                # noise, not vulnerabilities - skip pure info unless it has a CVE.
                cve_els = item_el.findall("cve")
                cve_ids = [c.text.strip().upper() for c in cve_els if c.text]

                if severity == "info" and not cve_ids:
                    continue

                description_el = item_el.find("description")
                solution_el = item_el.find("solution")
                cvss_el = item_el.find("cvss3_base_score")
                if cvss_el is None or not cvss_el.text:
                    cvss_el = item_el.find("cvss_base_score")

                cvss_score = None
                if cvss_el is not None and cvss_el.text:
                    try:
                        cvss_score = float(cvss_el.text)
                    except ValueError:
                        pass

                result.findings.append(ParsedFinding(
                    asset_ip=ip,
                    title=plugin_name or f"Nessus plugin {plugin_id}",
                    description=(description_el.text or "") if description_el is not None else "",
                    severity=severity,
                    cvss_score=cvss_score,
                    port_number=port_num or None,
                    cve_ids=cve_ids,
                    plugin_id=f"nessus:{plugin_id}",
                    solution=(solution_el.text or "") if solution_el is not None else "",
                    raw_data={"plugin_id": plugin_id, "svc_name": svc_name},
                ))

            result.hosts.append(parsed_host)

    return result
