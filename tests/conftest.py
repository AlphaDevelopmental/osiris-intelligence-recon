"""Shared fixtures: an offline fake of the OSIRIS HTTP API. No test touches the network."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
import requests

from osiris.api_client import OsirisClient, RateBudget

# Same shape as a real /api/osint/dns response (captured 2026-11-07), neutral data.
# The A bucket deliberately contains a CNAME answer (type 5), which OSIRIS copies
# into summary.ip_addresses unfiltered.
DNS_ROOT = {
    "domain": "example.com",
    "records": {
        "A": [{"name": "example.com.", "type": 1, "ttl": 300, "data": "93.184.215.14"}],
        "AAAA": [{"name": "example.com.", "type": 28, "ttl": 300, "data": "2606:2800:21f:cb07:6820:80da:af6b:8b2c"}],
        "MX": [
            {"name": "example.com.", "type": 15, "ttl": 300, "data": "10 mx1.mailhost.example.net."},
            {"name": "example.com.", "type": 15, "ttl": 300, "data": "20 mail.example.com."},
        ],
        "NS": [{"name": "example.com.", "type": 2, "ttl": 21600, "data": "a.iana-servers.net."}],
        "TXT": [
            {
                "name": "example.com.",
                "type": 16,
                "ttl": 300,
                "data": "v=spf1 +a +mx +ip4:198.51.100.7 include:spf.mailhost.example.net ~all",
            }
        ],
        "CNAME": [],
        "SOA": [
            {"name": "example.com.", "type": 6, "ttl": 1800, "data": "a.iana-servers.net. noc.example.com. 1 2 3 4 5"}
        ],
    },
    "timestamp": "2026-11-07T06:15:43.843Z",
    "summary": {
        "ip_addresses": ["93.184.215.14"],
        "mail_servers": ["10 mx1.mailhost.example.net."],
        "nameservers": ["a.iana-servers.net."],
        "total_records": 7,
    },
}

DNS_WWW = {
    "domain": "www.example.com",
    "records": {
        "A": [
            {"name": "www.example.com.", "type": 5, "ttl": 300, "data": "cdn.example.com."},
            {"name": "cdn.example.com.", "type": 1, "ttl": 300, "data": "93.184.215.20"},
        ],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
        "SOA": [],
    },
    "summary": {"ip_addresses": ["cdn.example.com.", "93.184.215.20"]},
}

DNS_INTERNAL = {
    "domain": "intranet.example.com",
    "records": {"A": [{"name": "intranet.example.com.", "type": 1, "ttl": 60, "data": "10.1.2.3"}]},
    "summary": {"ip_addresses": ["10.1.2.3"]},
}

CERTS = {
    "domain": "example.com",
    "certificates": [
        {
            "id": 1,
            "issuer": "CN=Test CA",
            "common_name": "*.example.com",
            "name_value": "*.example.com\nexample.com\nwww.example.com",
            "serial": "01",
        }
    ],
    "subdomains": [
        "www.example.com",
        "api.example.com",
        "intranet.example.com",
        "evilexample.com",
        "admin@example.com",
    ],
    "total_certs": 3,
    "unique_subdomains": 5,
}

WHOIS = {
    "domain": "example.com",
    "registration": "1995-08-14T04:00:00Z",
    "http": {
        "status": 200,
        "headers": {"server": "Apache", "x-powered-by": "PHP/8.1.34"},
        "redirected": False,
        "final_url": "https://example.com/",
    },
    "security_score": {"score": 0, "max": 7, "grade": "F"},
    "sanctions_match": None,
}

IP_INFO = {
    "ip": "93.184.215.14",
    "geo": {
        "country": "United States",
        "org": "Example Hosting",
        "isp": "Example ISP",
        "as_number": "AS64500 Example Net",
        "is_hosting": True,
    },
    "reputation": {"risk_level": "MEDIUM"},
    "sanctions_match": None,
}

SHODAN = {
    "ip": "93.184.215.14",
    "ports": [80, 443, 3306],
    "cpes": ["cpe:/a:apache:http_server"],
    "hostnames": ["example.com", "a.tenant.test", "b.tenant.test", "c.tenant.test"],
    "tags": [],
    "vulns": ["CVE-2021-44228", "CVE-2099-0001"],
}

BGP = {"query": "93.184.215.14", "type": "ip", "ip": {"asn": {"asn": 64500, "name": "EXAMPLE-NET"}}}
BGP_ASN = {"query": "AS64500", "type": "asn", "asn": {"asn": 64500, "name": "EXAMPLE-NET"}}
THREATS = {"timestamp": "x", "otx": {"pulse_count": 2}, "threat_level": "MEDIUM", "tor_exit_node": False}
HUDSON = {"query": "example.com", "type": "domain", "compromised": True, "totalStealers": 4, "employees": 1, "users": 3}
CYBER_ATTACKS = {
    "indicators": [
        {
            "ip": "93.184.215.20",
            "port": 443,
            "malware": "QakBot",
            "status": "offline",
            "first_seen": "2026-01-01",
            "source": "abuse.ch Feodo Tracker",
        },
        {"ip": "203.0.113.200", "port": 80, "malware": "Emotet", "source": "x"},
    ]
}
MALWARE = {"threats": []}
CYBER_THREATS = {
    "threats": [
        {"id": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j", "severity": "CRITICAL"},
        {"id": "CVE-2026-0001", "vendor": "WordPress", "product": "WordPress Core"},
    ]
}
CVE = {"id": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL", "source": "mitre"}


class FakeResponse:
    def __init__(self, status: int, body: Any = None, headers: dict[str, str] | None = None, raw: bytes | None = None):
        self.status_code = status
        self.headers = requests.structures.CaseInsensitiveDict(headers or {"Content-Type": "application/json"})
        self._body = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())

    def iter_content(self, size: int):
        for i in range(0, len(self._body), size):
            yield self._body[i : i + size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    """Routes GET requests by path. A handler returns FakeResponse, a dict (200 JSON) or raises."""

    def __init__(self, routes: dict[str, Callable[[dict[str, str]], Any] | Any]):
        self.routes = routes
        self.headers: dict[str, str] = {}
        self.requests: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, params=None, timeout=None, stream=False, **kw):
        path = "/" + url.split("://", 1)[1].split("/", 1)[1]
        params = dict(params or {})
        self.requests.append((path, params))
        handler = self.routes.get(path)
        if handler is None:
            return FakeResponse(404, {"error": "no route"})
        result = handler(params) if callable(handler) else handler
        if isinstance(result, Exception):
            raise result
        return result if isinstance(result, FakeResponse) else FakeResponse(200, result)

    def calls_to(self, path: str) -> list[dict[str, str]]:
        return [p for (pth, p) in self.requests if pth == path]


def osiris_routes() -> dict[str, Any]:
    dns = {"example.com": DNS_ROOT, "www.example.com": DNS_WWW, "intranet.example.com": DNS_INTERNAL}

    def dns_handler(p):
        return dns.get(p.get("domain"), {"domain": p.get("domain"), "records": {}, "summary": {"ip_addresses": []}})

    def bgp_handler(p):
        return BGP_ASN if p.get("query", "").startswith("AS") else BGP

    return {
        "/api/osint/dns": dns_handler,
        "/api/osint/certs": CERTS,
        "/api/osint/whois": WHOIS,
        "/api/osint/ip": lambda p: {**IP_INFO, "ip": p["ip"]},
        "/api/osint/shodan": lambda p: {**SHODAN, "ip": p["ip"]},
        "/api/osint/portscan": lambda p: {
            "target": p["target"],
            "ip": p["target"],
            "source": "internetdb",
            "ports": [],
            "vulns": [],
        },
        "/api/osint/bgp": bgp_handler,
        "/api/osint/threats": THREATS,
        "/api/osint/hudsonrock": lambda p: (
            HUDSON if "query" in p else FakeResponse(400, {"error": "Missing query parameter"})
        ),
        "/api/entity/expand": {"nodes": [{"id": "ip:x"}], "links": []},
        "/api/cyber-attacks": CYBER_ATTACKS,
        "/api/malware": MALWARE,
        "/api/cyber-threats": CYBER_THREATS,
        "/api/osint/cve": lambda p: {**CVE, "id": p["cve"]},
        "/api/health": {"status": "serving"},
        "/api/stats": {"stats": {}},
        "/api/oi": {"name": "OSIRIS OI"},
        "/api/osint/sweep": {"center": {}, "target_ip": "x", "cidr": 24},
    }


@pytest.fixture
def no_sleep():
    slept: list[float] = []
    return slept


def make_client(routes: dict[str, Any], slept: list[float] | None = None, **kw) -> tuple[OsirisClient, FakeSession]:
    slept = slept if slept is not None else []
    session = FakeSession(routes)
    budget = RateBudget(buckets={}, sleep=slept.append)
    client = OsirisClient(
        "https://osiris.test", session=session, sleep=slept.append, budget=budget, backoff_base=0.01, **kw
    )
    return client, session
