from __future__ import annotations
from parsers.common import ParseResult
from parsers.nmap_parser import parse_nmap_xml
from parsers.nessus_parser import parse_nessus_xml
from parsers.openvas_parser import parse_openvas_xml
from parsers.nuclei_parser import parse_nuclei_json
from parsers.generic_parser import parse_generic_csv, parse_generic_json


def parse_scan_output(scanner_type: str, text: str, filename: str = "") -> ParseResult:
    scanner_type = scanner_type.lower()
    if scanner_type == "nmap":
        return parse_nmap_xml(text)
    if scanner_type == "nessus":
        return parse_nessus_xml(text)
    if scanner_type == "openvas":
        return parse_openvas_xml(text)
    if scanner_type == "nuclei":
        return parse_nuclei_json(text)
    if scanner_type == "custom":
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            return parse_generic_json(text)
        return parse_generic_csv(text)
    # "import" / unknown - sniff by content and extension
    stripped = text.strip()
    if filename.endswith(".nessus"):
        return parse_nessus_xml(text)
    if stripped.startswith("<?xml") or stripped.startswith("<"):
        if "NessusClientData" in text[:2000]:
            return parse_nessus_xml(text)
        if "<nmaprun" in text[:2000]:
            return parse_nmap_xml(text)
        if "<report" in text[:2000].lower() or "openvas" in text[:2000].lower():
            return parse_openvas_xml(text)
        return parse_nmap_xml(text)
    if stripped.startswith("{") or stripped.startswith("["):
        if '"template-id"' in text[:5000] or '"matched-at"' in text[:5000]:
            return parse_nuclei_json(text)
        return parse_generic_json(text)
    return parse_generic_csv(text)
