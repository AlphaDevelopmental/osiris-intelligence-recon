"""Authorised active reconnaissance: scope enforcement, audit logging, conservative execution.

Active stage = requests that reach the target:
  * direct HTTP(S) requests and a TLS handshake from this machine (header/cookie/TLS analysis)
  * OSIRIS /api/scanner jobs (the scanner backend contacts the target)

It never performs brute forcing, credential attacks, denial-of-service testing or
exploitation. The OSIRIS scanner `vuln` type is refused by this client because the
backend's behaviour is not published.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

import requests

from . import USER_AGENT
from . import registry as reg
from .api_client import OsirisClient
from .http_analysis import HttpObservation
from .models import utcnow
from .targets import TargetError, enrichable_ip, in_domain, normalize_hostname, parse_ip

log = logging.getLogger("osiris.active")

AUTH_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,63}$")
SAFE_SCANNER_TYPES = ("headers", "ssl", "tech", "rdns", "whois", "geoloc", "subdomains", "quick")
DEFAULT_SCANNER_TYPES = ("headers", "ssl", "tech")
REFUSED_SCANNER_TYPES = {"vuln": "backend behaviour unpublished; may include intrusive checks"}


class ActiveError(RuntimeError):
    """Active mode precondition failure. The run must stop."""


# ── scope ───────────────────────────────────────────────────────────────
@dataclass
class Scope:
    hosts: set[str] = field(default_factory=set)  # exact hostnames
    wildcards: set[str] = field(default_factory=set)  # "*.example.com" -> "example.com" (subdomains only)
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    excluded_hosts: set[str] = field(default_factory=set)
    excluded_wildcards: set[str] = field(default_factory=set)
    excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    source: str = ""

    @classmethod
    def parse(cls, text: str, source: str = "") -> Scope:
        scope = cls(source=source)
        for lineno, line in enumerate(text.splitlines(), 1):
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            exclude = entry.startswith("!")
            entry = entry.lstrip("!").strip()
            try:
                if "/" in entry:
                    net = ipaddress.ip_network(entry, strict=False)
                    (scope.excluded_networks if exclude else scope.networks).append(net)
                elif parse_ip(entry) is not None:
                    ip = parse_ip(entry)
                    net = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")
                    (scope.excluded_networks if exclude else scope.networks).append(net)
                elif entry.startswith("*."):
                    (scope.excluded_wildcards if exclude else scope.wildcards).add(normalize_hostname(entry[2:]))
                else:
                    (scope.excluded_hosts if exclude else scope.hosts).add(normalize_hostname(entry))
            except (ValueError, TargetError) as exc:
                raise ActiveError(f"scope line {lineno}: invalid entry {entry!r} ({exc})") from exc
        return scope

    @classmethod
    def load(cls, path: str | Path) -> Scope:
        p = Path(path)
        if not p.is_file():
            raise ActiveError(f"scope file not found: {p}")
        scope = cls.parse(p.read_text(encoding="utf-8"), str(p))
        if scope.empty:
            raise ActiveError(f"scope file has no entries: {p}")
        return scope

    @property
    def empty(self) -> bool:
        return not (self.hosts or self.wildcards or self.networks)

    def host_allowed(self, host: str) -> tuple[bool, str]:
        h = host.rstrip(".").lower()
        if h in self.excluded_hosts or any(in_domain(h, w) and h != w for w in self.excluded_wildcards):
            return False, "explicitly excluded"
        if h in self.hosts:
            return True, "exact host in scope"
        if any(in_domain(h, w) and h != w for w in self.wildcards):
            return True, "matches wildcard"
        return False, "host not in scope"

    def ip_allowed(self, value: str) -> tuple[bool, str]:
        ip = parse_ip(value)
        if ip is None:
            return False, "not an IP"
        if any(ip in n for n in self.excluded_networks):
            return False, "explicitly excluded"
        if any(ip in n for n in self.networks):
            return True, "address in scope"
        return False, "address not in scope"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "hosts": sorted(self.hosts),
            "wildcards": sorted(f"*.{w}" for w in self.wildcards),
            "networks": [str(n) for n in self.networks],
            "excluded_hosts": sorted(self.excluded_hosts),
            "excluded_wildcards": sorted(f"*.{w}" for w in self.excluded_wildcards),
            "excluded_networks": [str(n) for n in self.excluded_networks],
        }


# ── audit log ───────────────────────────────────────────────────────────
class AuditLog:
    """Append-only JSONL record of every active decision and request."""

    def __init__(self, path: Path | None, authorization: str) -> None:
        self.path = path
        self.authorization = authorization
        self.entries: list[dict[str, Any]] = []
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: Any) -> None:
        entry = {"ts": utcnow(), "authorization": self.authorization, "event": event, **fields}
        self.entries.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")


# ── transport (injectable for tests) ────────────────────────────────────
@dataclass
class HttpResponse:
    status: int
    headers: dict[str, list[str]]
    location: str | None


class Transport(Protocol):
    def http_get(self, url: str, timeout: float) -> HttpResponse: ...
    def tls_probe(self, host: str, port: int, timeout: float) -> dict[str, Any]: ...


class RequestsTransport:
    """GET without following redirects; reads at most 64 KiB of body, then closes."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def http_get(self, url: str, timeout: float) -> HttpResponse:
        with self.session.get(url, allow_redirects=False, timeout=timeout, stream=True) as r:
            next(r.iter_content(65536), b"")
            headers: dict[str, list[str]] = {}
            for name, value in r.raw.headers.items():
                headers.setdefault(name.lower(), []).append(value)
            return HttpResponse(r.status_code, headers, r.headers.get("Location"))

    def tls_probe(self, host: str, port: int, timeout: float) -> dict[str, Any]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert() or {}
                    return {
                        "protocol": tls.version(),
                        "cipher": (tls.cipher() or [None])[0],
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
                    }
        except ssl.SSLCertVerificationError as exc:
            return {"error": f"certificate verification failed: {exc.verify_message}"}
        except (OSError, ssl.SSLError) as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({i[4][0] for i in infos})


# ── configuration & guard ───────────────────────────────────────────────
@dataclass
class ActiveConfig:
    enabled: bool
    authorization: str | None
    scope_path: str | None
    allow_private: bool = False  # authorised local lab only
    scanner_types: tuple[str, ...] = DEFAULT_SCANNER_TYPES
    use_scanner: bool = True
    use_http: bool = True
    max_hosts: int = 5
    min_interval: float = 2.0
    timeout: float = 10.0
    max_redirects: int = 3
    dry_run: bool = False


def validate_active(cfg: ActiveConfig) -> Scope:
    """All three gates must pass: enable flag, authorization reference, scope file."""
    if not cfg.enabled:
        raise ActiveError("active mode requires the separate --enable-active flag")
    if not cfg.authorization or not AUTH_REF.match(cfg.authorization):
        raise ActiveError("active mode requires --authorization <ENGAGEMENT-REF> (3-64 chars: letters, digits, ._:/-)")
    if not cfg.scope_path:
        raise ActiveError("active mode requires --scope <file>")
    bad = [t for t in cfg.scanner_types if t not in SAFE_SCANNER_TYPES]
    if bad:
        why = "; ".join(f"{t}: {REFUSED_SCANNER_TYPES.get(t, 'not an allowed scan type')}" for t in bad)
        raise ActiveError(f"refused scanner type(s): {why}")
    if cfg.min_interval < 0.5:
        raise ActiveError("--active-interval must be >= 0.5 s")
    if not 1 <= cfg.max_hosts <= 25:
        raise ActiveError("--active-max-hosts must be between 1 and 25")
    return Scope.load(cfg.scope_path)


@dataclass
class ActiveAction:
    kind: str  # http | tls | scanner
    host: str
    detail: str
    status: str = "planned"
    reason: str = ""
    result: dict[str, Any] | None = None


class ActiveRunner:
    def __init__(
        self,
        cfg: ActiveConfig,
        scope: Scope,
        audit: AuditLog,
        *,
        client: OsirisClient | None = None,
        transport: Transport | None = None,
        resolver: Callable[[str], list[str]] = system_resolver,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = cfg
        self.scope = scope
        self.audit = audit
        self.client = client
        self.transport = transport or RequestsTransport()
        self.resolver = resolver
        self.sleep = sleep
        self.clock = clock
        self._last = -1e9
        self.actions: list[ActiveAction] = []
        self.observations: list[HttpObservation] = []
        self.cancelled = False
        self._redirects: dict[str, bool] = {}
        self._scanner_started = False

    # Every outbound active request passes through here.
    def check_host(self, host: str) -> tuple[bool, str, list[str]]:
        ip = parse_ip(host)
        if ip is not None:
            ok, why = self.scope.ip_allowed(str(ip))
            if not ok:
                return False, why, []
            allowed, cat = enrichable_ip(ip, self.cfg.allow_private)
            return (allowed, "in scope" if allowed else f"{cat} address requires --lab-mode", [str(ip)])
        ok, why = self.scope.host_allowed(host)
        if not ok:
            return False, why, []
        try:
            addrs = self.resolver(host)
        except OSError as exc:
            return False, f"DNS resolution failed: {exc}", []
        if not addrs:
            return False, "no addresses", []
        for a in addrs:
            ipa = parse_ip(a)
            if ipa is None:
                return False, f"resolver returned non-IP {a!r}", addrs
            if any(ipa in n for n in self.scope.excluded_networks):
                return False, f"resolves to excluded address {a}", addrs
            allowed, cat = enrichable_ip(ipa, self.cfg.allow_private)
            if not allowed:
                return False, f"resolves to {cat} address {a} (use --lab-mode only for an authorised local lab)", addrs
        return True, why, addrs

    def _pace(self) -> None:
        wait = self.cfg.min_interval - (self.clock() - self._last)
        if wait > 0:
            self.sleep(wait)
        self._last = self.clock()

    def plan(self, primary: str, discovered: list[str]) -> list[ActiveAction]:
        hosts: list[str] = []
        for h in [primary, *discovered]:
            if h not in hosts:
                hosts.append(h)
        planned_hosts = 0
        for h in hosts:
            ok, why = self.scope.ip_allowed(h) if parse_ip(h) else self.scope.host_allowed(h)
            if not ok:
                self.actions.append(ActiveAction("http", h, "all active checks", "out_of_scope", why))
                self.audit.write("scope_reject", host=h, reason=why)
                continue
            if planned_hosts >= self.cfg.max_hosts:
                self.actions.append(ActiveAction("http", h, "all active checks", "skipped", "--active-max-hosts limit"))
                continue
            planned_hosts += 1
            if self.cfg.use_http:
                self.actions.append(ActiveAction("http", h, f"GET https://{h}/ (no redirect following beyond scope)"))
                self.actions.append(ActiveAction("http", h, f"GET http://{h}/ (HTTPS redirect check)"))
                self.actions.append(ActiveAction("tls", h, f"TLS handshake {h}:443"))
            if self.cfg.use_scanner and self.client is not None:
                for t in self.cfg.scanner_types:
                    self.actions.append(ActiveAction("scanner", h, t))
        return self.actions

    def execute(self) -> None:
        self.audit.write(
            "active_start",
            scope=self.scope.to_dict(),
            dry_run=self.cfg.dry_run,
            planned=[asdict(a) for a in self.actions],
        )
        try:
            for a in self.actions:
                if a.status != "planned":
                    continue
                if self.cfg.dry_run:
                    a.status, a.reason = "dry_run", "not sent (--dry-run)"
                    continue
                ok, why, addrs = self.check_host(a.host)
                self.audit.write(
                    "scope_check", host=a.host, action=a.kind, detail=a.detail, allowed=ok, reason=why, addresses=addrs
                )
                if not ok:
                    a.status, a.reason = "blocked", why
                    continue
                self._pace()
                if a.kind == "http":
                    self._http(a)
                elif a.kind == "tls":
                    self._tls(a)
                elif a.kind == "scanner":
                    self._scanner(a)
        except KeyboardInterrupt:
            self.cancelled = True
            for a in self.actions:
                if a.status == "planned":
                    a.status, a.reason = "cancelled", "operator interrupt"
            self.audit.write("active_cancelled")
        self.audit.write("active_end", summary=self.summary())

    def _http(self, a: ActiveAction) -> None:
        scheme = "http" if a.detail.startswith("GET http://") else "https"
        url = f"{scheme}://{a.host}/"
        chain: list[str] = []
        try:
            for _hop in range(self.cfg.max_redirects + 1):
                self.audit.write("request", action="http", url=url)
                resp = self.transport.http_get(url, self.cfg.timeout)
                chain.append(f"{resp.status} {url}")
                if scheme == "http":
                    to_https = bool(
                        resp.location and resp.location.lower().startswith("https://") and 300 <= resp.status < 400
                    )
                    a.status, a.result = (
                        "done",
                        {"status": resp.status, "location": resp.location, "http_to_https": to_https},
                    )
                    self._redirects[a.host] = to_https
                    return
                if 300 <= resp.status < 400 and resp.location:
                    nxt = urljoin(url, resp.location)
                    nhost = urlsplit(nxt).hostname or ""
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        break
                    ok, why, _ = self.check_host(nhost)
                    self.audit.write("redirect_check", from_url=url, to_url=nxt, allowed=ok, reason=why)
                    if not ok:
                        chain.append(f"stopped: redirect to {nhost} ({why})")
                        break
                    self._pace()
                    url = nxt
                    continue
                break
            obs = HttpObservation(
                url=url,
                status=resp.status,
                headers=resp.headers,
                source="active-http",
                reference=f"audit:{a.host}",
                redirect_chain=chain,
            )
            self.observations.append(obs)
            a.status, a.result = "done", {"status": resp.status, "final_url": url, "chain": chain}
        except requests.RequestException as exc:
            a.status, a.reason = "failed", f"{type(exc).__name__}"
            self.audit.write("request_failed", action="http", url=url, error=type(exc).__name__)

    def _tls(self, a: ActiveAction) -> None:
        self.audit.write("request", action="tls", host=a.host, port=443)
        info = self.transport.tls_probe(a.host, 443, self.cfg.timeout)
        a.status = "failed" if info.get("error") and "verification" not in str(info.get("error")) else "done"
        a.result = info
        for obs in self.observations:
            if urlsplit(obs.url).hostname == a.host and obs.https:
                obs.tls = info

    def _scanner(self, a: ActiveAction) -> None:
        assert self.client is not None
        ep = reg.get("/api/scanner")
        if not self._scanner_started:
            # The scanner route's 5/min threshold applies to the counter it shares with the OSINT routes.
            self.client.budget.wait_idle("shared")
            self._scanner_started = True
        self.audit.write("request", action="scanner", host=a.host, scan_type=a.detail, base=self.client.base_url)
        res = self.client.get(ep, {"target": a.host, "type": a.detail}, purpose=f"active scanner:{a.detail}")
        a.status = "done" if res.ok else ("unavailable" if res.status == "unavailable" else "failed")
        a.reason = res.error or ""
        a.result = {
            "call": res.record.call_id if res.record else None,
            "status": res.status,
            "http": res.http_status,
            "data": res.data if res.ok else None,
        }

    def finalize_observations(self) -> list[HttpObservation]:
        for obs in self.observations:
            host = urlsplit(obs.url).hostname
            if host in self._redirects:
                obs.http_to_https = self._redirects[host]
        return self.observations

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for a in self.actions:
            out[a.status] = out.get(a.status, 0) + 1
        return out
