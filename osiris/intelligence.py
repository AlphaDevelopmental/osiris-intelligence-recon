"""Matching target assets against OSIRIS threat feeds and per-indicator intelligence."""

from __future__ import annotations

import re
from typing import Any

from .models import Evidence, Finding

RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    2375: "Docker API (plaintext)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


def c2_matches(ips: set[str], payload: dict[str, Any], list_key: str) -> list[dict[str, Any]]:
    """Return feed entries (from /api/cyber-attacks `indicators` or /api/malware `threats`) whose ip is in `ips`."""
    rows = payload.get(list_key) if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []
    return [r for r in rows if isinstance(r, dict) and str(r.get("ip", "")) in ips]


def kev_matches(techs: list[dict[str, str]], payload: dict[str, Any]) -> list[dict[str, Any]]:
    """KEV/CVE feed rows whose vendor or product names a technology seen on the target.

    Matching is by product name only; version applicability is NOT determined.
    """
    rows = payload.get("threats") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not techs:
        return []
    names = {t["product"].lower() for t in techs if len(t.get("product", "")) >= 3}
    names.discard("http")
    hits = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        text = f"{r.get('vendor', '')} {r.get('product', '')}".lower()
        words = set(re.findall(r"[a-z0-9.+-]+", text))
        if names & words:
            hits.append(r)
    return hits


def cves_from_index(payload: dict[str, Any]) -> list[str]:
    vulns = payload.get("vulns") if isinstance(payload, dict) else None
    if isinstance(vulns, dict):
        vulns = list(vulns)
    if not isinstance(vulns, list):
        return []
    return sorted({str(v).upper() for v in vulns if re.match(r"(?i)^CVE-\d{4}-\d{4,}$", str(v))})


def index_findings(
    ip: str, payload: dict[str, Any], ref: str, endpoint: str, cve_details: dict[str, dict[str, Any]], kev_ids: set[str]
) -> list[Finding]:
    """Findings from a Shodan/InternetDB record. All index data is third-party and possibly stale."""
    out: list[Finding] = []
    ports = sorted(
        {
            p.get("port") if isinstance(p, dict) else p
            for p in (payload.get("ports") or [])
            if isinstance(p, (int, dict))
        }
        - {None}
    )
    risky = [(p, RISKY_PORTS[p]) for p in ports if p in RISKY_PORTS]
    if risky:
        out.append(
            Finding(
                id="",
                title="Index reports internet-exposed administrative or database services",
                asset=ip,
                observation="Shodan's index lists: " + ", ".join(f"{p}/{name}" for p, name in risky) + ".",
                evidence=[Evidence(endpoint, ref, f"ports={ports}")],
                confidence="medium",
                impact="Database, remote-admin and file-sharing services exposed to the internet are frequent "
                "targets for credential attacks and exploitation.",
                severity="medium",
                severity_justification="Exposure of these service classes is a well-established risk; rated medium rather "
                "than higher because the data comes from a third-party index (may be stale) and "
                "authentication/patch state is unknown.",
                remediation="Confirm whether the services are reachable; restrict them to VPN or allow-listed sources.",
                verification="unverified",
                category="exposure",
            )
        )
    cves = cves_from_index(payload)
    if cves:
        kev = [c for c in cves if c in kev_ids]
        scored = []
        for c in cves[:15]:
            d = cve_details.get(c) or {}
            scored.append(f"{c} (CVSS {d.get('cvss', 'n/a')}{', KEV' if c in kev else ''})")
        out.append(
            Finding(
                id="",
                title=f"Index associates {len(cves)} CVE identifier(s) with this address",
                asset=ip,
                observation="Shodan infers these CVEs from software version strings: "
                + "; ".join(scored)
                + ("" if len(cves) <= 15 else f"; +{len(cves) - 15} more")
                + ".",
                evidence=[Evidence(endpoint, ref, "vulns=" + ",".join(cves[:30]))],
                confidence="low",
                impact="If accurate, the host runs software with known vulnerabilities.",
                severity="medium" if kev else "informational",
                severity_justification=("At least one CVE is on the CISA KEV list (known exploited). " if kev else "")
                + "Version-inferred index data has a high false-positive rate (e.g. vendor backports "
                "keep old version strings); nothing was confirmed against the host.",
                remediation="Verify installed versions and patch levels on the host; patch or mitigate confirmed items.",
                verification="unverified",
                category="vulnerable-software",
            )
        )
    hostnames = [h for h in (payload.get("hostnames") or []) if isinstance(h, str)]
    if len(hostnames) > 3:
        out.append(
            Finding(
                id="",
                title="Address appears to be shared hosting",
                asset=ip,
                observation=f"The index lists {len(hostnames)} hostnames for this address; co-hosted names were "
                "recorded as count only and were not investigated.",
                evidence=[Evidence(endpoint, ref, f"hostname_count={len(hostnames)}")],
                confidence="medium",
                impact="Neighbouring tenants share the IP reputation and server; findings on the IP may not belong "
                "to the target.",
                severity="informational",
                severity_justification="Context for interpreting other IP-level findings.",
                remediation="Consider dedicated hosting for critical services.",
                verification="observed",
                category="infrastructure",
            )
        )
    return out
