"""Passive reconnaissance pipeline with bounded, scope-aware enrichment.

domain → DNS → CT → subdomain DNS → IP extraction → IP intel / Shodan index / BGP-ASN
       → threat intelligence → correlation → findings
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import date
from typing import Any
from urllib.parse import urlsplit

from . import registry as reg
from .api_client import STATUS_UNAVAILABLE, ApiResult, OsirisClient
from .correlation import (
    c2_finding,
    hudsonrock_counts,
    hudsonrock_finding,
    kev_tech_finding,
    otx_finding,
    sanctions_finding,
    spf_findings,
)
from .discovery import AssetInventory, DnsParse, parse_certs, parse_dns
from .http_analysis import (
    OSIRIS_WHOIS_HEADERS,
    HttpObservation,
    analyze,
    detect_technologies,
    observation_record,
    parse_raw_headers,
)
from .intelligence import c2_matches, cves_from_index, index_findings, kev_matches
from .models import (
    EXECUTED,
    FAILED,
    FIRST_PARTY,
    HOSTING,
    INCOMPATIBLE,
    PLANNED,
    REFERENCED,
    SKIPPED,
    TARGET,
    THIRD_PARTY,
    UNAVAILABLE,
    EndpointExecution,
    Finding,
    utcnow,
)
from .targets import Target

log = logging.getLogger("osiris.pipeline")

MODES = ("recon", "intelligence", "all", "active")

# Which input kinds become available from a given target kind, without leaving scope.
DERIVABLE: dict[str, set[str]] = {
    "domain": {"domain", "ipv4", "ipv6", "asn", "cve"},
    "ipv4": {"ipv4", "asn", "cve"},
    "ipv6": {"ipv6", "asn", "cve"},
    "email": {"email"},  # the mail domain may be a shared provider: never expanded automatically
    "cve": {"cve"},
    "asn": {"asn"},
    "phone": {"phone"},
    "mac": {"mac"},
}


@dataclass
class ReconConfig:
    mode: str = "recon"
    include_global: bool = False
    max_depth: int = 1
    max_subdomains: int = 15
    max_ips: int = 8
    max_asns: int = 5
    max_cves: int = 10
    allow_private: bool = False
    strict_passive: bool = False
    org_name: str | None = None
    github_user: str | None = None
    observed_headers: str | None = None
    observed_headers_name: str = "observed-headers"
    dry_run: bool = False
    today: date | None = None

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        for name in ("max_depth", "max_subdomains", "max_ips", "max_asns", "max_cves"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be >= 0")
        # Hard ceilings: discovery can never become unbounded, whatever the CLI says.
        self.max_depth = min(self.max_depth, 3)
        self.max_subdomains = min(self.max_subdomains, 200)
        self.max_ips = min(self.max_ips, 64)
        self.max_asns = min(self.max_asns, 16)
        self.max_cves = min(self.max_cves, 50)


class ExecutionTracker:
    """Gives every registered endpoint a final status and an explanation."""

    def __init__(self, cfg: ReconConfig, target: Target) -> None:
        self.cfg = cfg
        avail = set(DERIVABLE.get(target.kind, set()))
        if cfg.org_name:
            avail.add("org_name")
        if cfg.github_user:
            avail.add("github_user")
        self.execs: dict[str, EndpointExecution] = {}
        self.pending_reason: dict[str, str] = {}
        for ep in reg.ENDPOINTS:
            disp = reg.default_disposition(ep, cfg.mode, cfg.include_global)
            if disp is None and ep.inputs and not (set(ep.inputs) & avail):
                disp = (
                    INCOMPATIBLE,
                    f"Requires {' or '.join(ep.inputs)} input; target is {target.kind}"
                    + (" (mail domains are not expanded automatically)." if target.kind == "email" else "."),
                )
            status, reason = disp if disp else ("pending", "")
            self.execs[ep.key] = EndpointExecution(ep.key, ep.method, ep.path, ep.group, status, reason)

    def selected(self, ep: reg.Endpoint) -> bool:
        return self.execs[ep.key].status == "pending"

    def record(self, ep: reg.Endpoint, res: ApiResult) -> None:
        if res.record:
            self.execs[ep.key].calls.append(res.record)

    def note(self, ep: reg.Endpoint, reason: str) -> None:
        """Explain why a selected endpoint ended up with no calls (or was capped)."""
        if self.execs[ep.key].status == "pending":
            self.pending_reason[ep.key] = reason

    def finalize(self) -> list[EndpointExecution]:
        for key, ex in self.execs.items():
            if ex.status != "pending":
                continue
            calls = ex.calls
            if self.cfg.dry_run:
                ex.status, ex.reason = PLANNED, self.pending_reason.get(key, "Would run in this mode.")
            elif not calls:
                ex.status = SKIPPED
                ex.reason = self.pending_reason.get(key, "No compatible input was discovered for this endpoint.")
            elif any(c.status == "success" for c in calls):
                ok = sum(c.status == "success" for c in calls)
                degraded = sum(c.degraded for c in calls)
                ex.status = EXECUTED
                ex.reason = f"{ok}/{len(calls)} call(s) succeeded" + (
                    f"; {degraded} returned an upstream error inside a 2xx body" if degraded else ""
                )
                extra = self.pending_reason.get(key)
                if extra:
                    ex.reason += f"; {extra}"
            elif all(c.status == STATUS_UNAVAILABLE for c in calls):
                ex.status = UNAVAILABLE
                ex.reason = f"Service unavailable/not configured: {calls[-1].error or 'HTTP 503'}"
            else:
                ex.status = FAILED
                errs = sorted(
                    {
                        f"{c.status}"
                        + (f" (HTTP {c.http_status})" if c.http_status else "")
                        + (f": {c.error}" if c.error else "")
                        for c in calls
                    }
                )
                ex.reason = "; ".join(errs)[:600]
        return list(self.execs.values())


@dataclass
class ScanState:
    target: Target
    config: ReconConfig
    started_at: str = field(default_factory=utcnow)
    completed_at: str | None = None
    inventory: AssetInventory | None = None
    findings: list[Finding] = field(default_factory=list)
    http_observations: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, str]] = field(default_factory=list)
    intel: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    endpoints: list[EndpointExecution] = field(default_factory=list)
    active: dict[str, Any] | None = None
    cancelled: bool = False


class ReconPipeline:
    def __init__(self, client: OsirisClient, cfg: ReconConfig, target: Target) -> None:
        self.client = client
        self.cfg = cfg
        self.target = target
        self.tracker = ExecutionTracker(cfg, target)
        self.state = ScanState(target=target, config=cfg)
        self.inv = AssetInventory(target.domain if target.kind == "domain" else None, cfg.allow_private)
        self.state.inventory = self.inv
        self.dns: dict[str, DnsParse] = {}
        self.index: dict[str, tuple[str, str, dict[str, Any]]] = {}  # ip -> (endpoint, call_id, payload)
        self.kev_ids: set[str] = set()
        self.kev_payload: dict[str, Any] | None = None
        self._kev_ref = ""
        self._dns_ref: dict[str, str] = {}
        self.cve_details: dict[str, dict[str, Any]] = {}

    # ── call helper ──────────────────────────────────────────────────
    def call(
        self, path: str, params: dict[str, str] | None = None, purpose: str = "", keep_raw: bool = True
    ) -> ApiResult | None:
        ep = reg.get(path)
        if not self.tracker.selected(ep):
            return None
        if self.cfg.dry_run:
            return None
        res = self.client.get(ep, params, purpose=purpose)
        self.tracker.record(ep, res)
        if res.ok and keep_raw and res.record:
            self.state.raw[res.record.call_id] = {"endpoint": ep.key, "params": res.record.params, "data": res.data}
        return res

    @staticmethod
    def ref(res: ApiResult | None) -> str:
        return res.record.call_id if res and res.record else ""

    # ── entry point ──────────────────────────────────────────────────
    def run(self) -> ScanState:
        t = self.target
        try:
            if t.kind == "domain":
                self.inv.add(t.value, "domain", TARGET, "input")
                self._discover_domain(t.value)
            elif t.is_ip:
                self.inv.add_ip(t.value, TARGET, "input", None, 0)
            else:
                self.inv.add(t.value, t.kind, TARGET, "input")
            self._enrich_ips()
            self._enrich_asns()
            if self.cfg.mode in ("intelligence", "all", "active"):
                self._intelligence()
            if self.cfg.mode == "all":
                self._all_mode()
            self._http_observations()
            self._index_findings()
        except KeyboardInterrupt:
            self.state.cancelled = True
            self.state.notes.append("Run cancelled by operator; results are partial.")
            log.warning("cancelled — writing partial results")
        return self.state

    def finish(self) -> ScanState:
        from .correlation import finalize

        self.state.findings = finalize(self.state.findings)
        self.state.endpoints = self.tracker.finalize()
        self.state.completed_at = utcnow()
        return self.state

    # ── discovery ────────────────────────────────────────────────────
    def _discover_domain(self, root: str) -> None:
        cfg = self.cfg
        queue: deque[tuple[str, int, str]] = deque([(root, 0, "input")])
        queued = {root}
        resolved = 0
        dns_ep = reg.get("/api/osint/dns")

        dns_root = self._dns(root, 0)
        resolved += 1
        if dns_root:
            for f in spf_findings(root, dns_root, self._dns_ref.get(root, "")):
                self.state.findings.append(f)

        if cfg.strict_passive:
            ex = self.tracker.execs["GET /api/osint/whois"]
            ex.status, ex.reason = (
                SKIPPED,
                ("--strict-passive: this route makes the OSIRIS server send a HEAD request to the target."),
            )
        else:
            res = self.call("/api/osint/whois", {"domain": root}, "registration + header sample")
            if res and res.ok:
                self._whois(root, res)

        if cfg.max_depth >= 1:
            res = self.call("/api/osint/certs", {"domain": root}, "certificate transparency")
            if res and res.ok:
                ct = parse_certs(res.data, root)
                self.state.intel["certificate_transparency"] = {
                    "call": self.ref(res),
                    "certificates": ct.certificates,
                    "total_certs": ct.total_certs,
                    "subdomains": len(ct.subdomains),
                    "rejected_out_of_scope": ct.rejected[:50],
                    "error": ct.error,
                }
                if ct.error:
                    self.state.notes.append(
                        f"Certificate transparency degraded: {ct.error}. Subdomain coverage is incomplete."
                    )
                for host in ct.subdomains:
                    if host == root:
                        continue
                    self.inv.add(host, "hostname", FIRST_PARTY, f"ct:{self.ref(res)}", root, 1)
                    if host not in queued:
                        queue.append((host, 1, "ct"))
                        queued.add(host)
        else:
            self.tracker.note(reg.get("/api/osint/certs"), "--max-depth 0 disables subdomain discovery.")

        # first-party MX/NS hosts join the queue; third-party ones are recorded only
        for kind, hosts in (
            ("mail_host", dns_root.mx if dns_root else []),
            ("nameserver", dns_root.ns if dns_root else []),
        ):
            for h in hosts:
                rel = self.inv.relation_for_host(h)
                rel = FIRST_PARTY if rel == TARGET else rel
                self.inv.add(
                    h,
                    kind,
                    rel,
                    f"dns:{self._dns_ref.get(root, '')}",
                    root,
                    1,
                    None if rel == FIRST_PARTY else "third-party provider; not enriched",
                )
                if rel == FIRST_PARTY and h not in queued:
                    queue.append((h, 1, kind))
                    queued.add(h)

        queue.popleft()  # root already resolved
        skipped: list[str] = []
        while queue:
            host, depth, _src = queue.popleft()
            if depth > cfg.max_depth:
                skipped.append(host)
                continue
            if resolved >= cfg.max_subdomains + 1:
                skipped.append(host)
                continue
            parsed = self._dns(host, depth)
            resolved += 1
            if parsed:
                for cname in parsed.cnames:
                    if self.inv.relation_for_host(cname) in (TARGET, FIRST_PARTY):
                        self.inv.add(cname, "hostname", FIRST_PARTY, f"cname:{host}", host, depth + 1)
                        if cname not in queued:
                            queue.append((cname, depth + 1, "cname"))
                            queued.add(cname)
        if skipped:
            for h in skipped:
                a = self.inv.get("hostname", h) or self.inv.get("mail_host", h)
                if a:
                    a.notes.append("not resolved: discovery limit (--max-subdomains/--max-depth)")
            msg = f"{len(skipped)} discovered hostname(s) not resolved due to discovery limits."
            self.state.notes.append(msg)
            self.tracker.note(dns_ep, msg)

    def _dns(self, host: str, depth: int) -> DnsParse | None:
        res = self.call("/api/osint/dns", {"domain": host}, f"resolve {host}")
        if not res or not res.ok or not isinstance(res.data, dict):
            return None
        parsed = parse_dns(res.data)
        self.dns[host] = parsed
        for kind in ("domain", "hostname", "mail_host"):
            asset = self.inv.get(kind, host)
            if asset:
                asset.enriched = True
        ref = self.ref(res)
        self._dns_ref[host] = ref
        rel = self.inv.relation_for_host(host)
        for ip in parsed.ipv4 + parsed.ipv6:
            if rel in (TARGET, FIRST_PARTY):
                self.inv.add_ip(ip, HOSTING, f"dns:{ref}", host, depth + 1)
        for cname in parsed.cnames:
            if self.inv.relation_for_host(cname) == THIRD_PARTY:
                self.inv.add(
                    cname,
                    "hostname",
                    THIRD_PARTY,
                    f"cname:{ref}",
                    host,
                    depth + 1,
                    "CNAME target outside the target domain; not enriched",
                )
        for spf_ip in parsed.spf_ips:
            self.inv.add(
                spf_ip,
                "cidr" if "/" in spf_ip else "ip_reference",
                REFERENCED,
                f"spf:{ref}",
                host,
                depth + 1,
                "authorised mail sender in SPF; not enriched",
            )
        for inc in parsed.spf_includes:
            self.inv.add(inc, "hostname", REFERENCED, f"spf:{ref}", host, depth + 1, "SPF include; not enriched")
        return parsed

    def _whois(self, root: str, res: ApiResult) -> None:
        data = res.data if isinstance(res.data, dict) else {}
        self.state.intel["whois"] = {
            "call": self.ref(res),
            "registration": data.get("registration"),
            "expiration": data.get("expiration"),
            "nameservers": (data.get("rdap") or {}).get("nameservers"),
            "osiris_security_score": data.get("security_score"),
            "osiris_security_score_note": "Heuristic count of 5 headers from a HEAD request; reference only, not "
            "used for severity.",
        }
        http = data.get("http")
        if isinstance(http, dict) and isinstance(http.get("headers"), dict):
            headers = {k.lower(): [str(v)] for k, v in http["headers"].items()}
            obs = HttpObservation(
                url=str(http.get("final_url") or f"https://{root}/"),
                status=http.get("status"),
                headers=headers,
                source="osiris-whois",
                reference=self.ref(res),
                header_subset=OSIRIS_WHOIS_HEADERS,
            )
            self._add_observation(obs)
        if data.get("sanctions_match"):
            self.state.findings.append(
                sanctions_finding(root, data["sanctions_match"], "GET /api/osint/whois", self.ref(res))
            )

    # ── IP / ASN enrichment ──────────────────────────────────────────
    def _enrich_ips(self) -> None:
        cfg = self.cfg
        ips = self.inv.ips()
        if not ips:
            reason = "No enrichable public IP address was discovered."
            for p in (
                "/api/osint/ip",
                "/api/osint/shodan",
                "/api/osint/bgp",
                "/api/osint/portscan",
                "/api/entity/expand",
                "/api/osint/sweep",
            ):
                self.tracker.note(reg.get(p), reason)
            return
        if len(ips) > cfg.max_ips:
            for a in ips[cfg.max_ips :]:
                a.notes.append("not enriched: --max-ips limit")
            self.state.notes.append(f"{len(ips) - cfg.max_ips} IP(s) not enriched due to --max-ips {cfg.max_ips}.")
            ips = ips[: cfg.max_ips]
        intel = self.cfg.mode in ("intelligence", "all", "active")
        self.state.intel.setdefault("ips", {})
        for a in ips:
            ip, v4 = a.value, a.kind == "ipv4"
            summary: dict[str, Any] = {"relation": a.relation}
            res = self.call("/api/osint/ip", {"ip": ip}, "geolocation/ASN")
            if res and res.ok:
                geo = (res.data or {}).get("geo") or {}
                summary.update(
                    ip_call=self.ref(res),
                    country=geo.get("country"),
                    org=geo.get("org"),
                    isp=geo.get("isp"),
                    as_number=geo.get("as_number"),
                    is_hosting=geo.get("is_hosting"),
                )
                if (res.data or {}).get("sanctions_match"):
                    self.state.findings.append(
                        sanctions_finding(ip, res.data["sanctions_match"], "GET /api/osint/ip", self.ref(res))
                    )
            res = self.call("/api/osint/shodan", {"ip": ip}, "InternetDB index")
            if res and res.ok and isinstance(res.data, dict):
                self.index[ip] = ("GET /api/osint/shodan", self.ref(res), res.data)
                summary.update(
                    ports=res.data.get("ports"),
                    cves=len(cves_from_index(res.data)),
                    index_hostnames=len(res.data.get("hostnames") or []),
                )
            if v4:
                res = self.call("/api/osint/bgp", {"query": ip}, "IP→ASN")
                if res and res.ok:
                    asn = ((res.data or {}).get("ip") or {}).get("asn") or {}
                    summary.update(asn=asn.get("asn"), asn_name=asn.get("name"), bgp_call=self.ref(res))
            if intel:
                if v4:
                    res = self.call("/api/osint/threats", {"query": ip}, "OTX reputation / Tor exit")
                    if res and res.ok and isinstance(res.data, dict):
                        summary["threat_level"] = res.data.get("threat_level")
                        f = otx_finding(ip, res.data, self.ref(res))
                        if f:
                            self.state.findings.append(f)
                res = self.call("/api/osint/portscan", {"target": ip}, "Shodan host record")
                if res and res.ok and isinstance(res.data, dict):
                    summary["portscan_source"] = res.data.get("source")
                    if res.data.get("source") == "shodan" or ip not in self.index:
                        self.index[ip] = ("GET /api/osint/portscan", self.ref(res), res.data)
                res = self.call("/api/entity/expand", {"type": "ip", "id": ip}, "entity graph")
                if res and res.ok and isinstance(res.data, dict):
                    summary["graph_nodes"] = len(res.data.get("nodes") or [])
            a.enriched = True
            self.state.intel["ips"][ip] = summary
        if not any(a.kind == "ipv4" for a in ips):
            self.tracker.note(
                reg.get("/api/osint/bgp"), "Only IPv6 addresses found; upstream BGP route accepts IPv4/ASN."
            )
            self.tracker.note(
                reg.get("/api/osint/threats"), "Only IPv6 addresses found; upstream treats IPv6 as a domain."
            )

    def _enrich_asns(self) -> None:
        asns: list[str] = []
        if self.target.kind == "asn":
            asns.append(self.target.value)
        for s in (self.state.intel.get("ips") or {}).values():
            for value in (s.get("asn"), s.get("as_number")):
                m = re.match(r"^(?:AS)?(\d+)", str(value or ""), re.I)
                if m and f"AS{m.group(1)}" not in asns:
                    asns.append(f"AS{m.group(1)}")
        for asn in asns[: self.cfg.max_asns]:
            self.inv.add(
                asn,
                "asn",
                THIRD_PARTY if self.target.kind != "asn" else TARGET,
                "bgp/ip",
                None,
                2,
                None if self.target.kind == "asn" else "network operator; prefixes not expanded",
            )
            res = self.call("/api/osint/bgp", {"query": asn}, "ASN holder")
            if res and res.ok:
                self.state.intel.setdefault("asns", {})[asn] = (res.data or {}).get("asn")
        if len(asns) > self.cfg.max_asns:
            self.state.notes.append(f"{len(asns) - self.cfg.max_asns} ASN(s) not queried due to --max-asns.")

    # ── threat intelligence ──────────────────────────────────────────
    def _intelligence(self) -> None:
        t = self.target
        if t.kind == "domain":
            res = self.call("/api/osint/threats", {"query": t.value}, "OTX domain reputation")
            if res and res.ok and isinstance(res.data, dict):
                self.state.intel["domain_threats"] = {
                    "call": self.ref(res),
                    "threat_level": res.data.get("threat_level"),
                    "otx": res.data.get("otx"),
                }
                f = otx_finding(t.value, res.data, self.ref(res))
                if f:
                    self.state.findings.append(f)
        hr_query = {"domain": ("domain", t.value), "email": ("email", t.value), "phone": ("phone", t.value)}.get(t.kind)
        if hr_query:
            res = self.call(
                "/api/osint/hudsonrock", {"query": hr_query[1], "type": hr_query[0]}, "infostealer exposure"
            )
            if res and res.ok and isinstance(res.data, dict):
                counts = hudsonrock_counts(res.data) if t.kind == "domain" else {}
                self.state.intel["hudsonrock"] = {
                    "call": self.ref(res),
                    **{k: res.data.get(k) for k in ("employees", "users", "third_parties")},
                    **counts,
                    "osiris_compromised_flag": res.data.get("compromised"),
                    "note": "`total` is per-domain; `totalStealers` (Hudson Rock corpus size) is ignored.",
                }
                for u in counts.get("urls", []):
                    host = urlsplit(u["url"]).hostname or ""
                    if host and self.inv.relation_for_host(host) == FIRST_PARTY:
                        self.inv.add(
                            host,
                            "hostname",
                            FIRST_PARTY,
                            f"hudsonrock:{self.ref(res)}",
                            t.value,
                            1,
                            "seen in Hudson Rock login URLs; discovered after the DNS stage, not resolved",
                        )
                if t.kind == "domain":
                    f = hudsonrock_finding(t.value, res.data, self.ref(res))
                    if f:
                        self.state.findings.append(f)

        # Global feeds used for correlation with discovered infrastructure.
        ips = {a.value for a in self.inv.ips(relations=(TARGET, HOSTING))}
        for path, key in (("/api/cyber-attacks", "indicators"), ("/api/malware", "threats")):
            res = self.call(path, None, "C2 correlation", keep_raw=False)
            if res and res.ok and isinstance(res.data, dict):
                rows = res.data.get(key) or []
                hits = c2_matches(ips, res.data, key)
                self.state.intel.setdefault("feeds", {})[path] = {
                    "call": self.ref(res),
                    "rows": len(rows),
                    "matches": len(hits),
                }
                for ip in sorted({str(h.get("ip")) for h in hits}):
                    self.state.findings.append(
                        c2_finding(ip, [h for h in hits if str(h.get("ip")) == ip], f"GET {path}", self.ref(res))
                    )
        res = self.call("/api/cyber-threats", None, "KEV correlation", keep_raw=False)
        if res and res.ok and isinstance(res.data, dict):
            self.kev_payload = res.data
            self._kev_ref = self.ref(res)
            self.kev_ids = {str(r.get("id", "")).upper() for r in res.data.get("threats") or [] if isinstance(r, dict)}
            self.state.intel.setdefault("feeds", {})["/api/cyber-threats"] = {
                "call": self.ref(res),
                "rows": len(self.kev_ids),
            }

        # CVE details for identifiers the index associated with target IPs (bounded).
        cves: list[str] = []
        for _ep, _ref, payload in self.index.values():
            for c in cves_from_index(payload):
                if c not in cves:
                    cves.append(c)
        if t.kind == "cve":
            cves.insert(0, t.value)
        for c in cves[: self.cfg.max_cves]:
            res = self.call("/api/osint/cve", {"cve": c}, "CVE details")
            if res and res.ok and isinstance(res.data, dict):
                self.cve_details[c] = {
                    "cvss": res.data.get("cvss"),
                    "severity": res.data.get("severity"),
                    "source": res.data.get("source"),
                    "call": self.ref(res),
                }
        if len(cves) > self.cfg.max_cves:
            self.state.notes.append(f"{len(cves) - self.cfg.max_cves} CVE(s) not looked up due to --max-cves.")
        if not cves:
            self.tracker.note(reg.get("/api/osint/cve"), "No CVE identifiers were associated with target assets.")
        self.state.intel["cves"] = self.cve_details

    def _all_mode(self) -> None:
        t, cfg = self.target, self.cfg
        for path in ("/api/health", "/api/stats", "/api/oi"):
            self.call(path, None, "platform status", keep_raw=False)
        single = {
            "email": ("/api/osint/leaks", {"email": t.value}),
            "mac": ("/api/osint/mac", {"mac": t.value}),
            "phone": ("/api/osint/phone", {"number": t.value}),
        }.get(t.kind)
        if single:
            self.call(single[0], single[1], f"{t.kind} lookup")
        if cfg.github_user:
            self.call("/api/osint/github", {"user": cfg.github_user}, "GitHub profile")
        else:
            self.tracker.note(reg.get("/api/osint/github"), "Supply --github-user to query a GitHub account.")
        if cfg.org_name:
            res = self.call("/api/osint/sanctions", {"query": cfg.org_name, "limit": "10"}, "OFAC SDN search")
            if res and res.ok and isinstance(res.data, dict) and res.data.get("total"):
                self.state.notes.append(
                    f"Sanctions search for '{cfg.org_name}' returned {res.data.get('total')} "
                    "substring/alias match(es); see raw data — not treated as a finding."
                )
        else:
            self.tracker.note(reg.get("/api/osint/sanctions"), "Supply --org-name for an OFAC SDN search.")
        v4 = [a.value for a in self.inv.ips() if a.kind == "ipv4"][:3]
        for ip in v4:
            self.call("/api/osint/sweep", {"ip": ip}, "geolocation (handler performs no sweep)")
        if cfg.include_global:
            for ep in reg.ENDPOINTS:
                if (
                    ep.category == reg.GLOBAL
                    and self.tracker.selected(ep)
                    and not self.tracker.execs[ep.key].calls
                    and not any(p.required for p in ep.params)
                ):
                    res = self.call(ep.path, dict(ep.default_params) or None, "global context feed", keep_raw=False)
                    if res and res.ok and isinstance(res.data, dict):
                        self.state.intel.setdefault("global_feeds", {})[ep.path] = _shape(res.data)

    # ── analysis ─────────────────────────────────────────────────────
    def _add_observation(self, obs: HttpObservation) -> None:
        self.state.findings.extend(analyze(obs, self.cfg.today))
        techs = detect_technologies(obs)
        for tech in techs:
            if tech not in self.state.technologies:
                self.state.technologies.append(tech)
        self.state.http_observations.append(observation_record(obs))

    def _http_observations(self) -> None:
        if self.cfg.observed_headers:
            status, headers = parse_raw_headers(self.cfg.observed_headers)
            host = self.target.domain or self.target.value
            url = f"https://{host}/"
            self._add_observation(
                HttpObservation(
                    url=url,
                    status=status,
                    headers=headers,
                    source="user-supplied",
                    reference=self.cfg.observed_headers_name,
                )
            )
        if self.kev_payload and self.state.technologies:
            rows = kev_matches(self.state.technologies, self.kev_payload)
            f = kev_tech_finding(self.target.domain or self.target.value, self.state.technologies, rows, self._kev_ref)
            if f:
                self.state.findings.append(f)

    def _index_findings(self) -> None:
        for ip, (endpoint, ref, payload) in self.index.items():
            self.state.findings.extend(index_findings(ip, payload, ref, endpoint, self.cve_details, self.kev_ids))


def _shape(data: dict[str, Any]) -> dict[str, Any]:
    """Summarise a global feed without storing it."""
    return {k: (f"{len(v)} item(s)" if isinstance(v, (list, dict)) else v) for k, v in data.items()}
