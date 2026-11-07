"""Parse OSIRIS DNS / CT responses and keep a scoped, deduplicated asset inventory."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .models import FIRST_PARTY, HOSTING, REFERENCED, TARGET, THIRD_PARTY, Asset
from .targets import TargetError, enrichable_ip, in_domain, normalize_hostname, parse_ip

RR_A, RR_CNAME, RR_AAAA = 1, 5, 28


@dataclass
class DnsParse:
    domain: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    spf_ips: list[str] = field(default_factory=list)
    spf_includes: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)


def _host(value: str) -> str | None:
    try:
        return normalize_hostname(value)
    except TargetError:
        return None


def _add(seq: list[str], value: str | None) -> None:
    if value and value not in seq:
        seq.append(value)


def parse_dns(payload: dict[str, Any]) -> DnsParse:
    """Extract addresses and hosts from an /api/osint/dns response.

    Answers are classified by their RR `type` code, not by which bucket OSIRIS
    put them in: an A query that follows a CNAME returns the CNAME answer too,
    and OSIRIS copies it into `summary.ip_addresses` unfiltered. Values from
    `summary.ip_addresses` are accepted only if they parse as IP addresses.
    """
    out = DnsParse(domain=str(payload.get("domain", "")))
    records = payload.get("records") or {}
    if not isinstance(records, dict):
        records = {}
    for bucket, answers in records.items():
        if not isinstance(answers, list):
            continue
        for ans in answers:
            if not isinstance(ans, dict):
                continue
            data = str(ans.get("data", "")).strip()
            rtype = ans.get("type")
            if rtype in (RR_A, RR_AAAA) or (rtype is None and bucket in ("A", "AAAA")):
                ip = parse_ip(data)
                if ip is not None:
                    _add(out.ipv4 if ip.version == 4 else out.ipv6, str(ip))
            elif rtype == RR_CNAME or (rtype is None and bucket == "CNAME"):
                _add(out.cnames, _host(data))
            elif bucket == "MX" or rtype == 15:
                _add(out.mx, _host(data.split()[-1]) if data else None)
            elif bucket == "NS" or rtype == 2:
                _add(out.ns, _host(data))
            elif bucket == "TXT" or rtype == 16:
                txt = data.strip('"')
                out.txt.append(txt)
                if txt.lower().startswith("v=spf1"):
                    _parse_spf(txt, out)
    summary = payload.get("summary") or {}
    for value in summary.get("ip_addresses") or []:
        ip = parse_ip(str(value))
        if ip is not None:
            _add(out.ipv4 if ip.version == 4 else out.ipv6, str(ip))
    return out


_SPF_IP = re.compile(r"^[+?~-]?ip[46]:(\S+)$", re.I)
_SPF_INC = re.compile(r"^[+?~-]?include:(\S+)$", re.I)


def _parse_spf(txt: str, out: DnsParse) -> None:
    for term in txt.split()[1:]:
        m = _SPF_IP.match(term)
        if m:
            _add(out.spf_ips, m.group(1))
            continue
        m = _SPF_INC.match(term)
        if m:
            _add(out.spf_includes, _host(m.group(1)))


@dataclass
class CertParse:
    domain: str
    subdomains: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)  # names that failed the scope boundary
    certificates: int = 0
    total_certs: int | None = None
    error: str | None = None


def parse_certs(payload: dict[str, Any], root: str) -> CertParse:
    """Extract in-scope hostnames from an /api/osint/certs response.

    OSIRIS filters with `endsWith(domain)`, which accepts `evilexample.com` for
    `example.com`; names are re-checked on a label boundary here.
    """
    out = CertParse(domain=root, error=payload.get("error"))
    certs = payload.get("certificates") or []
    out.certificates = len(certs) if isinstance(certs, list) else 0
    out.total_certs = payload.get("total_certs")
    names: list[str] = list(payload.get("subdomains") or [])
    for cert in certs if isinstance(certs, list) else []:
        if isinstance(cert, dict):
            names.extend(str(cert.get("name_value", "")).splitlines())
            names.append(str(cert.get("common_name", "")))
    for raw in names:
        if not raw or "@" in raw:
            continue
        host = _host(raw.strip())
        if host is None:
            continue
        if in_domain(host, root):
            _add(out.subdomains, host)
        else:
            _add(out.rejected, host)
    out.subdomains.sort(key=lambda h: (h.count("."), h))
    return out


class AssetInventory:
    """Deduplicated inventory. Every asset records source(s), timestamp, parent and depth."""

    def __init__(self, root_domain: str | None, allow_private: bool = False) -> None:
        self.root = root_domain
        self.allow_private = allow_private
        self._assets: dict[tuple[str, str], Asset] = {}

    def __iter__(self):
        return iter(self._assets.values())

    def __len__(self) -> int:
        return len(self._assets)

    def get(self, kind: str, value: str) -> Asset | None:
        return self._assets.get((kind, value))

    def relation_for_host(self, host: str) -> str:
        if self.root and host == self.root:
            return TARGET
        if self.root and in_domain(host, self.root):
            return FIRST_PARTY
        return THIRD_PARTY

    def add(
        self,
        value: str,
        kind: str,
        relation: str,
        source: str,
        parent: str | None = None,
        depth: int = 0,
        note: str | None = None,
    ) -> Asset:
        # The root domain is one asset however it is reached (CNAME/MX/NS pointing back at it).
        if self.root and value == self.root and kind in ("domain", "hostname", "mail_host", "nameserver"):
            kind, relation = "domain", TARGET
        key = (kind, value)
        asset = self._assets.get(key)
        if asset is None:
            asset = Asset(value=value, kind=kind, relation=relation, sources=[source], parent=parent, depth=depth)
            self._assets[key] = asset
        else:
            if source not in asset.sources:
                asset.sources.append(source)
            # A stronger relation wins (target > first_party > hosting > third_party > referenced).
            order = [TARGET, FIRST_PARTY, HOSTING, THIRD_PARTY, REFERENCED]
            if order.index(relation) < order.index(asset.relation):
                asset.relation = relation
            asset.depth = min(asset.depth, depth)
        if note and note not in asset.notes:
            asset.notes.append(note)
        return asset

    def add_ip(self, value: str, relation: str, source: str, parent: str | None, depth: int) -> Asset | None:
        ip = parse_ip(value)
        if ip is None:
            return None
        ok, cat = enrichable_ip(ip, self.allow_private)
        note = None if ok else f"{cat} address — excluded from public-IP enrichment"
        return self.add(str(ip), f"ipv{ip.version}", relation, source, parent, depth, note)

    def ips(self, relations: tuple[str, ...] = (TARGET, HOSTING)) -> list[Asset]:
        out = []
        for a in self._assets.values():
            if a.kind in ("ipv4", "ipv6") and a.relation in relations:
                ip = parse_ip(a.value)
                if ip is not None and enrichable_ip(ip, self.allow_private)[0]:
                    out.append(a)
        return out

    def hosts(self, relations: tuple[str, ...] = (TARGET, FIRST_PARTY)) -> list[Asset]:
        return [a for a in self._assets.values() if a.kind in ("domain", "hostname") and a.relation in relations]

    def to_list(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in sorted(self._assets.values(), key=lambda a: (a.relation, a.kind, a.value))]
