"""
Shodan integration - real host/device reconnaissance data (open ports,
banners, known vulnerabilities Shodan associates with a host) for an IP
already logged as an IOC. Same pattern as every other external API in
this project: a thin wrapper, best-effort, fails safe.

Needs an API key (unlike ip-api.com or Open-Elevation, Shodan is not
free) - set VULN_SHODAN_API_KEY. See run_online.sh for where this
project's other API keys live.
"""
from __future__ import annotations
import json
import os
import urllib.request
import urllib.error


def is_configured() -> bool:
    return bool(os.environ.get("VULN_SHODAN_API_KEY"))


def host_lookup(ip: str, timeout: int = 10) -> dict | None:
    api_key = os.environ.get("VULN_SHODAN_API_KEY")
    if not api_key:
        return None
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        # 404 = Shodan has no data for this IP, not an error worth surfacing loudly
        if e.code == 404:
            return {"ip": ip, "no_data": True}
        return None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None

    ports = sorted(set(data.get("ports", [])))
    services = []
    for item in data.get("data", [])[:20]:
        services.append({
            "port": item.get("port"),
            "transport": item.get("transport"),
            "product": item.get("product"),
            "version": item.get("version"),
            "banner": (item.get("data") or "").strip()[:300],
        })

    return {
        "ip": data.get("ip_str", ip),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "country": data.get("country_name"),
        "city": data.get("city"),
        "hostnames": data.get("hostnames", []),
        "os": data.get("os"),
        "ports": ports,
        "vulns": sorted(data.get("vulns", [])) if data.get("vulns") else [],
        "services": services,
        "last_update": data.get("last_update"),
    }
