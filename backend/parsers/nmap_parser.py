"""
Nmap XML parser (`nmap -oX -` / `nmap -oX output.xml`).

Extracts hosts, open ports, service/version detection, OS fingerprinting,
and (when the `ssl-cert` NSE script was run) SSL certificate details.
Also surfaces NSE vulnerability-scan script output (e.g. `vulners`,
`vulscan`, `http-vuln-*`) as Findings when present, since Nmap with the
right scripts is itself a lightweight vulnerability scanner.
"""
from __future__ import annotations
from xml.etree import ElementTree as ET
from parsers.common import ParseResult, ParsedHost, ParsedPort, ParsedSSLCert, ParsedFinding

CVE_PATTERN = __import__("re").compile(r"CVE-\d{4}-\d{4,7}", __import__("re").IGNORECASE)


def parse_nmap_xml(xml_text: str) -> ParseResult:
    result = ParseResult()
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        os_name, os_accuracy = "", None
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_name = match.get("name", "")
                try:
                    os_accuracy = int(match.get("accuracy", "0"))
                except ValueError:
                    os_accuracy = None

        parsed_host = ParsedHost(ip_address=ip, hostname=hostname, os_name=os_name, os_accuracy=os_accuracy)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                port_num = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")
                service_el = port_el.find("service")
                service_name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                banner = f"{product} {version}".strip()

                parsed_host.ports.append(ParsedPort(
                    port_number=port_num, protocol=protocol, state=state,
                    service_name=service_name, product=product, version=version, banner=banner,
                ))

                # --- NSE script output: ssl-cert + vulnerability scripts ---
                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    script_output = script_el.get("output", "")

                    if script_id == "ssl-cert":
                        cert = _parse_ssl_cert_script(port_num, script_el, script_output)
                        parsed_host.ssl_certs.append(cert)

                    elif script_id in ("vulners", "vulscan") or script_id.startswith("http-vuln-") or script_id.startswith("vuln"):
                        cves = CVE_PATTERN.findall(script_output)
                        if cves or "VULNERABLE" in script_output.upper():
                            severity = "high" if cves else "medium"
                            result.findings.append(ParsedFinding(
                                asset_ip=ip,
                                title=f"NSE script finding: {script_id} on port {port_num}",
                                description=script_output[:2000],
                                severity=severity,
                                port_number=port_num,
                                cve_ids=list(set(c.upper() for c in cves)),
                                plugin_id=f"nmap-nse:{script_id}",
                                raw_data={"script_id": script_id, "output": script_output[:4000]},
                            ))

        result.hosts.append(parsed_host)

    return result


def _parse_ssl_cert_script(port_num: int, script_el, output: str) -> ParsedSSLCert:
    subject, issuer, valid_from, valid_to = "", "", "", ""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Subject:"):
            subject = line.replace("Subject:", "").strip()
        elif line.startswith("Issuer:"):
            issuer = line.replace("Issuer:", "").strip()
        elif line.startswith("Not valid before:"):
            valid_from = line.replace("Not valid before:", "").strip()
        elif line.startswith("Not valid after:"):
            valid_to = line.replace("Not valid after:", "").strip()
    self_signed = bool(subject) and subject == issuer
    return ParsedSSLCert(
        port_number=port_num, subject=subject, issuer=issuer,
        valid_from=valid_from, valid_to=valid_to, self_signed=self_signed,
    )
