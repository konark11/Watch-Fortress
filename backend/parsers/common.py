"""
Common intermediate representation that every scan-result parser converts
into. Keeping ONE shape here means the ingestion pipeline, correlation
engine, and asset-upsert logic only need to understand this shape - not
five different XML/JSON schemas.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedPort:
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class ParsedSSLCert:
    port_number: int
    subject: str = ""
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    self_signed: bool = False
    expired: bool = False


@dataclass
class ParsedHost:
    ip_address: str
    hostname: str = ""
    os_name: str = ""
    os_accuracy: Optional[int] = None
    ports: list[ParsedPort] = field(default_factory=list)
    ssl_certs: list[ParsedSSLCert] = field(default_factory=list)


@dataclass
class ParsedFinding:
    asset_ip: str
    title: str
    description: str = ""
    severity: str = "info"          # info|low|medium|high|critical
    cvss_score: Optional[float] = None
    port_number: Optional[int] = None
    cve_ids: list[str] = field(default_factory=list)
    plugin_id: str = ""
    solution: str = ""
    raw_data: dict = field(default_factory=dict)


@dataclass
class ParseResult:
    hosts: list[ParsedHost] = field(default_factory=list)
    findings: list[ParsedFinding] = field(default_factory=list)
