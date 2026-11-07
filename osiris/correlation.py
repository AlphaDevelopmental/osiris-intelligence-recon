"""Turn intelligence results into evidence-backed findings, then rank and number them."""

from __future__ import annotations

from typing import Any

from .discovery import DnsParse
from .models import SEVERITIES, Evidence, Finding


def c2_finding(ip: str, rows: list[dict[str, Any]], endpoint: str, ref: str) -> Finding:
    names = sorted({str(r.get("malware", "?")) for r in rows})
    srcs = sorted({str(r.get("source", "?")) for r in rows})
    excerpt = "; ".join(
        f"{r.get('ip')}:{r.get('port')} {r.get('malware')} status={r.get('status', 'n/a')} "
        f"first_seen={r.get('first_seen')}"
        for r in rows[:5]
    )
    return Finding(
        id="",
        title="Target address listed in a malware C2 feed",
        asset=ip,
        observation=f"{ip} appears in {', '.join(srcs)} as infrastructure for {', '.join(names)}.",
        evidence=[Evidence(endpoint, ref, excerpt)],
        confidence="medium",
        impact="The address hosted, or hosts, command-and-control infrastructure; on shared hosting this may "
        "be another tenant. Reputation blocking of the address is likely.",
        severity="high",
        severity_justification="Listing by a curated abuse feed is strong external evidence of malicious activity on "
        "the address; not 'critical' because attribution to the target's own systems is unconfirmed.",
        remediation="Investigate the host for compromise, check other tenants with the provider, review feed "
        "listing details and request delisting once resolved.",
        verification="unverified",
        category="threat-intel",
    )


def hudsonrock_finding(domain: str, data: dict[str, Any], ref: str) -> Finding | None:
    total = int(data.get("totalStealers") or data.get("total") or 0)
    if total <= 0:
        return None
    employees = int(data.get("employees") or 0)
    users = int(data.get("users") or 0)
    third = int(data.get("third_parties") or 0)
    return Finding(
        id="",
        title="Infostealer infections associated with the domain (Hudson Rock)",
        asset=domain,
        observation=f"Hudson Rock reports {total} compromised machine(s) with credentials for this domain "
        f"(employees: {employees}, users: {users}, third parties: {third}). Credentials themselves "
        "were not retrieved; the upstream service redacts them.",
        evidence=[
            Evidence("GET /api/osint/hudsonrock", ref, f"totalStealers={total}; employees={employees}; users={users}")
        ],
        confidence="medium",
        impact="Stolen session cookies or passwords for the organisation's services may be in criminal "
        "circulation, enabling account takeover.",
        severity="high" if employees else "medium",
        severity_justification=(
            "Employee credentials are reported, which can grant internal access."
            if employees
            else "Only user/customer credentials reported; organisational access less likely."
        ),
        remediation="Force password resets for affected accounts, revoke sessions, enforce MFA, and review "
        "Hudson Rock's per-URL data (on their platform) to identify affected services.",
        verification="unverified",
        category="credential-exposure",
    )


def otx_finding(indicator: str, data: dict[str, Any], ref: str) -> Finding | None:
    otx = data.get("otx") or {}
    pulses = int(otx.get("pulse_count") or 0)
    out_tor = data.get("tor_exit_node") is True
    if pulses <= 0 and not out_tor:
        return None
    obs = []
    if pulses:
        obs.append(f"referenced by {pulses} AlienVault OTX pulse(s) (OSIRIS threat_level={data.get('threat_level')})")
    if out_tor:
        obs.append("listed as a Tor exit node")
    return Finding(
        id="",
        title="Indicator referenced in open threat intelligence",
        asset=indicator,
        observation=f"{indicator} is " + " and ".join(obs) + ".",
        evidence=[
            Evidence("GET /api/osint/threats", ref, f"pulse_count={pulses}; tor_exit_node={data.get('tor_exit_node')}")
        ],
        confidence="low",
        impact="Pulses may reference an indicator for many reasons, including benign mentions or shared infrastructure.",
        severity="informational",
        severity_justification="OTX pulse counts are not curated verdicts; OSIRIS's HIGH/MEDIUM level is a simple count "
        "threshold and is not treated as a severity.",
        remediation="Review the referencing pulses in OTX before acting.",
        verification="unverified",
        category="threat-intel",
    )


def sanctions_finding(asset: str, match: dict[str, Any], endpoint: str, ref: str) -> Finding:
    hits = match.get("hits") or []
    values = ", ".join(str(h.get("matched_value")) for h in hits[:5])
    return Finding(
        id="",
        title="Exact-name match against the OFAC SDN list",
        asset=asset,
        observation=f"OSIRIS matched: {values}.",
        evidence=[Evidence(endpoint, ref, f"sanctions_match: {values}")],
        confidence="low",
        impact="Possible sanctions compliance concern; exact-name matches produce false positives.",
        severity="informational",
        justification="Name match only; identity not confirmed.",
        remediation="Refer to compliance staff for manual review.",
        verification="unverified",
        category="compliance",
    )


def spf_findings(domain: str, dns: DnsParse, ref: str) -> list[Finding]:
    spf = [t for t in dns.txt if t.lower().startswith("v=spf1")]
    if not spf:
        if dns.mx:
            return [
                Finding(
                    id="",
                    title="No SPF record published",
                    asset=domain,
                    observation="The domain publishes MX records but no v=spf1 TXT record.",
                    evidence=[Evidence("GET /api/osint/dns", ref, "TXT: no v=spf1")],
                    confidence="high",
                    impact="Receivers cannot validate senders, easing spoofing of the domain.",
                    severity="low",
                    severity_justification="Direct DNS observation; DMARC was not checked (OSIRIS rejects _dmarc names).",
                    remediation="Publish an SPF record listing authorised senders, ending in -all or ~all.",
                    verification="observed",
                    category="email-security",
                )
            ]
        return []
    record = spf[0]
    tail = record.split()[-1].lower()
    if tail in ("+all", "all"):
        sev, just = "high", "Any host on the internet is authorised to send as the domain."
    elif tail == "?all":
        sev, just = "low", "Neutral policy gives receivers no guidance."
    else:
        return []
    return [
        Finding(
            id="",
            title=f"Permissive SPF policy ({tail})",
            asset=domain,
            observation=f"SPF record: {record}",
            evidence=[Evidence("GET /api/osint/dns", ref, record)],
            confidence="high",
            impact="Facilitates email spoofing of the domain.",
            severity=sev,
            justification=just,
            remediation="End the SPF record with -all (or ~all during transition) and deploy DMARC.",
            verification="observed",
            category="email-security",
        )
    ]


def kev_tech_finding(asset: str, techs: list[dict[str, str]], rows: list[dict[str, Any]], ref: str) -> Finding | None:
    if not rows:
        return None
    ids = ", ".join(f"{r.get('id')} ({r.get('vendor')} {r.get('product')})" for r in rows[:8])
    products = ", ".join(sorted({t["product"] for t in techs}))
    return Finding(
        id="",
        title="Recently published exploited-vulnerability entries name technology seen on the target",
        asset=asset,
        observation=f"Technology observed: {products}. Matching entries in the OSIRIS cyber-threats feed: {ids}.",
        evidence=[Evidence("GET /api/cyber-threats", ref, ids)],
        confidence="low",
        impact="If the target runs an affected version, it may be exposed to actively exploited flaws.",
        severity="informational",
        severity_justification="Matched on product name only; version applicability was not determined.",
        remediation="Check each entry's affected versions against the deployed software and patch where applicable.",
        verification="unverified",
        category="threat-intel",
    )


_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def finalize(findings: list[Finding]) -> list[Finding]:
    """Deduplicate (title+asset), merge evidence, sort by severity, assign stable IDs."""
    merged: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.title, f.asset)
        if key in merged:
            existing = merged[key]
            existing.evidence.extend(e for e in f.evidence if e not in existing.evidence)
            if _ORDER[f.severity] < _ORDER[existing.severity]:
                existing.severity, existing.severity_justification = f.severity, f.severity_justification
        else:
            merged[key] = f
    ordered = sorted(merged.values(), key=lambda f: (_ORDER.get(f.severity, 99), f.category, f.asset, f.title))
    for i, f in enumerate(ordered, 1):
        f.id = f"OSR-{i:03d}"
    return ordered
