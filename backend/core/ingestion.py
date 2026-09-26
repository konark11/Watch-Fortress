from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from models.database import Asset, Port, SSLCertificate, Scan, Finding, ScannerType, Severity, Criticality
from parsers.registry import parse_scan_output
from parsers.common import ParseResult
from correlation.engine import correlate_new_findings

# Common ports that indicate an asset is likely internet-facing. This is a
# heuristic (a real deployment would cross-reference actual network
# topology / firewall rules) used only to seed the `internet_exposed` flag
# for risk scoring when nothing else is known about the asset.
INTERNET_FACING_PORTS = {80, 443, 21, 25, 22, 3389, 8080, 8443}


def ingest_scan_result(db: Session, scan: Scan, raw_text: str, filename: str = "") -> dict:
    parsed: ParseResult = parse_scan_output(scan.scanner_type.value, raw_text, filename)

    asset_ids_touched = []
    for host in parsed.hosts:
        asset = _upsert_asset(db, host)
        asset_ids_touched.append(asset.id)

    new_finding_ids = []
    valid_severities = {s.value for s in Severity}
    for pf in parsed.findings:
        finding = Finding(
            scan_id=scan.id,
            scanner_source=scan.scanner_type,
            asset_ip=pf.asset_ip,
            port_number=pf.port_number,
            title=pf.title[:500],
            description=pf.description,
            severity=Severity(pf.severity) if pf.severity in valid_severities else Severity.INFO,
            cvss_score=pf.cvss_score,
            cve_ids=pf.cve_ids,
            plugin_id=pf.plugin_id,
            solution=pf.solution,
            raw_data=pf.raw_data,
        )
        db.add(finding)
        db.flush()
        new_finding_ids.append(finding.id)

        if not db.query(Asset).filter(Asset.ip_address == pf.asset_ip).first():
            asset = Asset(ip_address=pf.asset_ip, internet_exposed=pf.port_number in INTERNET_FACING_PORTS)
            db.add(asset)
            db.flush()
            asset_ids_touched.append(asset.id)

    db.commit()

    correlation_summary = correlate_new_findings(db, new_finding_ids)

    scan.findings_count = len(new_finding_ids)
    db.commit()

    return {
        "hosts_discovered": len(parsed.hosts),
        "findings_ingested": len(new_finding_ids),
        "vulnerabilities_created": correlation_summary["created"],
        "vulnerabilities_merged": correlation_summary["merged"],
    }


def _upsert_asset(db: Session, host) -> Asset:
    asset = db.query(Asset).filter(Asset.ip_address == host.ip_address).first()
    if asset is None:
        asset = Asset(
            ip_address=host.ip_address,
            hostname=host.hostname,
            os_name=host.os_name,
            os_accuracy=host.os_accuracy,
            criticality=Criticality.MEDIUM,
        )
        db.add(asset)
        db.flush()
    else:
        if host.hostname:
            asset.hostname = host.hostname
        if host.os_name:
            asset.os_name = host.os_name
            asset.os_accuracy = host.os_accuracy
        asset.last_seen = datetime.now(timezone.utc)

    exposed = any(p.port_number in INTERNET_FACING_PORTS for p in host.ports)
    if exposed:
        asset.internet_exposed = True

    existing_ports = {p.port_number: p for p in db.query(Port).filter(Port.asset_id == asset.id).all()}
    for p in host.ports:
        if p.port_number in existing_ports:
            row = existing_ports[p.port_number]
            row.service_name = p.service_name or row.service_name
            row.product = p.product or row.product
            row.version = p.version or row.version
            row.banner = p.banner or row.banner
        else:
            db.add(Port(
                asset_id=asset.id, port_number=p.port_number, protocol=p.protocol,
                state=p.state, service_name=p.service_name, product=p.product,
                version=p.version, banner=p.banner,
            ))

    for cert in host.ssl_certs:
        db.add(SSLCertificate(
            asset_id=asset.id, port_number=cert.port_number, subject=cert.subject,
            issuer=cert.issuer, valid_from=cert.valid_from, valid_to=cert.valid_to,
            self_signed=cert.self_signed,
        ))

    db.flush()
    return asset
