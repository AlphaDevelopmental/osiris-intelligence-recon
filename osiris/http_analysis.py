"""HTTP response / web-technology analysis.

The analysis functions are pure: they take an observation and return findings.
Where the observation comes from matters and is recorded as evidence:

* ``osiris-whois`` — headers OSIRIS's own server got from a HEAD request
  (``/api/osint/whois``). No traffic from this tool to the target, but only nine
  header names are reported, so absence is meaningful only for those names.
* ``user-supplied`` — a header capture the operator made themselves (--observed-headers).
* ``active-http`` — a request this tool sent in the scope-controlled active stage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from .models import Evidence, Finding

# Header names OSIRIS's whois route copies from the HEAD response.
OSIRIS_WHOIS_HEADERS = frozenset(
    {
        "server",
        "x-powered-by",
        "x-frame-options",
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    }
)

# php.net lifecycle, retrieved 2026-11-07 from
#   https://www.php.net/supported-versions.php and https://www.php.net/eol.php
PHP_LIFECYCLE_SOURCE = "https://www.php.net/supported-versions.php ; https://www.php.net/eol.php (retrieved 2026-11-07)"
PHP_BRANCHES: dict[str, dict[str, str]] = {
    "7.4": {"security_until": "2022-11-28", "last_release": "7.4.33"},
    "8.0": {"security_until": "2023-11-26", "last_release": "8.0.30"},
    "8.1": {"security_until": "2025-12-31", "last_release": "8.1.34"},
    "8.2": {"active_until": "2024-12-31", "security_until": "2026-12-31"},
    "8.3": {"active_until": "2025-12-31", "security_until": "2027-12-31"},
    "8.4": {"active_until": "2026-12-31", "security_until": "2028-12-31"},
    "8.5": {"active_until": "2027-12-31", "security_until": "2029-12-31"},
}

SESSION_COOKIE = re.compile(r"(?i)(sess|sid|auth|token|login|wordpress_logged_in|wp-settings|jwt)")


@dataclass
class HttpObservation:
    url: str
    status: int | None
    headers: dict[str, list[str]]  # lower-case name -> values
    source: str  # osiris-whois | user-supplied | active-http
    reference: str  # call id, file name or request id
    header_subset: frozenset[str] | None = None  # None = full header set observed
    redirect_chain: list[str] = field(default_factory=list)
    http_to_https: bool | None = None  # None = not tested
    tls: dict[str, Any] | None = None

    def first(self, name: str) -> str | None:
        vals = self.headers.get(name.lower())
        return vals[0] if vals else None

    def observed(self, name: str) -> bool:
        """True if presence/absence of `name` is knowable from this observation."""
        return self.header_subset is None or name.lower() in self.header_subset

    @property
    def https(self) -> bool:
        return self.url.lower().startswith("https://")


def parse_raw_headers(text: str) -> tuple[int | None, dict[str, list[str]]]:
    """Parse `curl -I` style output (status line optional, last response wins)."""
    status: int | None = None
    headers: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip("\r")
        if not line.strip():
            continue
        m = re.match(r"^HTTP/[\d.]+\s+(\d{3})", line)
        if m:
            status, headers = int(m.group(1)), {}
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers.setdefault(name.strip().lower(), []).append(value.strip())
    return status, headers


def php_lifecycle(version: str, on: date) -> dict[str, Any]:
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not m:
        return {"branch": None, "state": "unknown"}
    branch = f"{m.group(1)}.{m.group(2)}"
    info = PHP_BRANCHES.get(branch)
    if info is None:
        older = (int(m.group(1)), int(m.group(2))) < (7, 4)
        return {
            "branch": branch,
            "state": "eol" if older else "unknown",
            "detail": "predates 7.4; all such branches are end-of-life" if older else "branch not in lifecycle table",
        }
    sec = date.fromisoformat(info["security_until"])
    act = date.fromisoformat(info["active_until"]) if "active_until" in info else None
    if on > sec:
        state = "eol"
    elif act and on > act:
        state = "security-only"
    else:
        state = "active"
    return {"branch": branch, "state": state, **info}


def _ev(obs: HttpObservation, excerpt: str) -> Evidence:
    return Evidence(source=obs.source, reference=obs.reference, excerpt=excerpt)


def _f(
    obs: HttpObservation,
    title: str,
    observation: str,
    excerpt: str,
    *,
    confidence: str,
    impact: str,
    severity: str,
    justification: str,
    remediation: str,
    verification: str = "observed",
    category: str = "web",
) -> Finding:
    return Finding(
        id="",
        title=title,
        asset=obs.url,
        observation=observation,
        evidence=[_ev(obs, excerpt)],
        confidence=confidence,
        impact=impact,
        severity=severity,
        severity_justification=justification,
        remediation=remediation,
        verification=verification,
        category=category,
    )


def detect_technologies(obs: HttpObservation) -> list[dict[str, str]]:
    techs: list[dict[str, str]] = []
    server = obs.first("server")
    if server:
        for prod, ver in re.findall(r"([A-Za-z][\w.-]*)(?:/([\w.+-]+))?", server):
            techs.append({"product": prod, "version": ver or "", "source": "server"})
    for value in obs.headers.get("x-powered-by", []):
        for prod, ver in re.findall(r"([A-Za-z][\w.-]*)(?:/([\w.+-]+))?", value):
            techs.append({"product": prod, "version": ver or "", "source": "x-powered-by"})
    links = " ".join(obs.headers.get("link", []))
    if "api.w.org" in links or "/wp-json/" in links or obs.first("x-pingback"):
        techs.append({"product": "WordPress", "version": "", "source": "link/x-pingback"})
    return techs


def analyze(obs: HttpObservation, today: date | None = None) -> list[Finding]:
    today = today or datetime.now(timezone.utc).date()
    out: list[Finding] = []
    origin = {
        "osiris-whois": "OSIRIS server HEAD request (via /api/osint/whois)",
        "user-supplied": "operator-supplied header capture",
        "active-http": "authorised active HTTP request",
    }.get(obs.source, obs.source)

    # ── technology disclosure ────────────────────────────────────────
    server = obs.first("server")
    if server:
        versioned = bool(re.search(r"/\d", server))
        out.append(
            _f(
                obs,
                "Web server software disclosed in Server header",
                f"The Server header reports '{server}' ({origin}).",
                f"server: {server}",
                confidence="high",
                impact="Aids fingerprinting; no vulnerability is implied by the banner itself.",
                severity="low" if versioned else "informational",
                justification=(
                    "Banner includes a version number, narrowing exploit research."
                    if versioned
                    else "Product name only, no version; disclosure value is minimal."
                ),
                remediation="Reduce the banner (e.g. Apache `ServerTokens Prod`, `ServerSignature Off`).",
                category="information-disclosure",
            )
        )

    for value in obs.headers.get("x-powered-by", []):
        out.append(
            _f(
                obs,
                "Runtime disclosed in X-Powered-By header",
                f"X-Powered-By reports '{value}' ({origin}).",
                f"x-powered-by: {value}",
                confidence="high",
                impact="Discloses runtime and version to any client.",
                severity="low",
                justification="Exact runtime version is disclosed; no exploitable flaw confirmed.",
                remediation="Disable the header (PHP: `expose_php = Off` in php.ini).",
                category="information-disclosure",
            )
        )
        m = re.search(r"PHP/(\d+\.\d+(?:\.\d+)?)", value, re.I)
        if m:
            out.extend(_php_findings(obs, m.group(1), today))

    # ── WordPress / REST API indicators ─────────────────────────────
    links = obs.headers.get("link", [])
    rest = [v for v in links if "api.w.org" in v or "/wp-json/" in v]
    if rest:
        out.append(
            _f(
                obs,
                "WordPress REST API advertised",
                "A Link header advertises the WordPress REST API root, a strong WordPress indicator.",
                "link: " + rest[0],
                confidence="high",
                impact="Confirms the CMS. Some default REST routes (e.g. /wp-json/wp/v2/users) can disclose "
                "author usernames; this tool did not request them.",
                severity="informational",
                justification="Indicator only; REST API exposure is default WordPress behaviour and no specific "
                "weakness was tested.",
                remediation="Keep WordPress core, themes and plugins patched; restrict unauthenticated access to "
                "REST routes not needed publicly (e.g. user listing).",
                category="technology",
            )
        )
    if obs.first("x-pingback"):
        out.append(
            _f(
                obs,
                "XML-RPC pingback endpoint advertised",
                "X-Pingback header present.",
                "x-pingback: " + (obs.first("x-pingback") or ""),
                confidence="high",
                impact="xmlrpc.php is a common target for credential-guessing and pingback abuse.",
                severity="informational",
                justification="Presence only; abuse not tested.",
                remediation="Disable XML-RPC if unused, or restrict it at the web server.",
                category="technology",
            )
        )

    # ── security headers ────────────────────────────────────────────
    if obs.status is None or obs.status < 400:
        out.extend(_header_findings(obs, origin))

    # ── cookies ─────────────────────────────────────────────────────
    for raw in obs.headers.get("set-cookie", []):
        out.extend(_cookie_findings(obs, raw))

    # ── transport ───────────────────────────────────────────────────
    if obs.http_to_https is False:
        out.append(
            _f(
                obs,
                "HTTP does not redirect to HTTPS",
                "A plain-HTTP request was answered without a redirect to HTTPS.",
                "http_to_https=false",
                confidence="high",
                impact="Users following http:// links stay on an unencrypted connection.",
                severity="low",
                justification="Observed directly; exploitation requires a network-position attacker.",
                remediation="Redirect all HTTP requests to HTTPS (301) and enable HSTS.",
                category="transport",
            )
        )
    if obs.tls:
        out.extend(_tls_findings(obs, today))
    return out


def _php_findings(obs: HttpObservation, version: str, today: date) -> list[Finding]:
    lc = php_lifecycle(version, today)
    if lc["state"] == "eol":
        last = lc.get("last_release")
        final_note = (
            f" {version} is the final upstream release of the {lc['branch']} branch."
            if last == version
            else (f" The final upstream {lc['branch']} release is {last}." if last else "")
        )
        return [
            _f(
                obs,
                f"PHP {lc['branch']} branch is past upstream end-of-life",
                f"The disclosed version PHP {version} belongs to branch {lc['branch']}, whose upstream security "
                f"support ended {lc.get('security_until', 'before 7.4')}.{final_note} Distribution or hosting vendors "
                "sometimes ship backported fixes for EOL branches (e.g. extended-lifecycle builds); a banner cannot "
                "show whether such patches are installed.",
                f"x-powered-by: PHP/{version}; lifecycle: {PHP_LIFECYCLE_SOURCE}",
                confidence="medium",
                impact="Vulnerabilities in PHP disclosed after the EOL date receive no upstream fix; if no vendor "
                "backport is applied, the runtime accumulates unpatched flaws.",
                severity="medium",
                justification="Unsupported-software exposure (CWE-1104) on an internet-facing runtime, evidenced by "
                "the version banner and php.net lifecycle data. Not rated higher because no specific "
                "exploitable vulnerability was confirmed and vendor backports cannot be ruled out.",
                remediation=f"Upgrade to a supported PHP branch (8.3+ recommended as of {today.isoformat()}); if the "
                "host provides vendor-patched EOL builds, obtain written confirmation of the patch level. "
                "Test the application on the new branch first.",
                verification="unverified",
                category="vulnerable-software",
            )
        ]
    if lc["state"] == "security-only":
        return [
            _f(
                obs,
                f"PHP {lc['branch']} is in security-fixes-only support",
                f"PHP {version}: branch {lc['branch']} receives security fixes until {lc['security_until']}.",
                f"x-powered-by: PHP/{version}; lifecycle: {PHP_LIFECYCLE_SOURCE}",
                confidence="medium",
                impact="Supported for now; plan the upgrade before the security-support end date.",
                severity="informational",
                justification="Branch is still supported upstream.",
                remediation=f"Plan migration before {lc['security_until']}.",
                verification="observed",
                category="lifecycle",
            )
        ]
    return []


def _header_findings(obs: HttpObservation, origin: str) -> list[Finding]:
    out: list[Finding] = []
    note = (
        "" if obs.header_subset is None else " (OSIRIS reports this header name when present, so absence is meaningful)"
    )
    method_note = " Based on a HEAD response; GET responses can differ." if obs.source == "osiris-whois" else ""

    def missing(name: str, title: str, impact: str, severity: str, justification: str, remediation: str) -> None:
        if obs.observed(name) and not obs.first(name):
            out.append(
                _f(
                    obs,
                    title,
                    f"No {name} header in the response from {origin}{note}.{method_note}",
                    f"{name}: <absent>",
                    confidence="medium" if method_note else "high",
                    impact=impact,
                    severity=severity,
                    justification=justification,
                    remediation=remediation,
                    category="security-headers",
                )
            )

    if obs.https:
        missing(
            "strict-transport-security",
            "HSTS not enabled",
            "Browsers may make a first plain-HTTP request that a network attacker can intercept (SSL stripping).",
            "low",
            "Missing hardening control; exploitation needs an on-path attacker. Not a confirmed vulnerability.",
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` after confirming all "
            "subdomains serve HTTPS.",
        )
        hsts = obs.first("strict-transport-security")
        if hsts:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            if m and int(m.group(1)) < 15552000:
                out.append(
                    _f(
                        obs,
                        "HSTS max-age below 180 days",
                        f"HSTS max-age is {m.group(1)} seconds.",
                        f"strict-transport-security: {hsts}",
                        confidence="high",
                        impact="Shorter protection window after a visit.",
                        severity="informational",
                        justification="Hardening gap only.",
                        remediation="Use max-age >= 31536000.",
                        category="security-headers",
                    )
                )
    missing(
        "content-security-policy",
        "No Content-Security-Policy",
        "No browser-enforced restriction on script sources; XSS flaws, if any exist, are easier to exploit.",
        "informational",
        "Defence-in-depth control; its absence is not itself exploitable.",
        "Deploy a CSP (start with Content-Security-Policy-Report-Only to tune it).",
    )
    missing(
        "x-content-type-options",
        "X-Content-Type-Options not set",
        "Older browsers may MIME-sniff responses.",
        "informational",
        "Low practical risk on modern browsers; hardening only.",
        "Send `X-Content-Type-Options: nosniff`.",
    )
    missing(
        "referrer-policy",
        "Referrer-Policy not set",
        "Full URLs may leak in Referer headers on older browsers; modern browsers default to "
        "strict-origin-when-cross-origin.",
        "informational",
        "Browser defaults mitigate most cases.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).",
    )
    csp = obs.first("content-security-policy") or ""
    if obs.observed("x-frame-options") and not obs.first("x-frame-options") and "frame-ancestors" not in csp:
        out.append(
            _f(
                obs,
                "No clickjacking protection header",
                f"Neither X-Frame-Options nor CSP frame-ancestors present ({origin}).{method_note}",
                "x-frame-options: <absent>; csp frame-ancestors: <absent>",
                confidence="medium",
                impact="Pages can be framed by other sites; matters only where pages carry state-changing actions.",
                severity="informational",
                justification="Impact depends on application functionality, which was not assessed.",
                remediation="Send `Content-Security-Policy: frame-ancestors 'self'` (or X-Frame-Options: SAMEORIGIN).",
                category="security-headers",
            )
        )
    return out


def _cookie_findings(obs: HttpObservation, raw: str) -> list[Finding]:
    name = raw.split("=", 1)[0].strip()
    attrs = {
        p.strip().split("=", 1)[0].lower(): (p.split("=", 1)[1].strip() if "=" in p else "") for p in raw.split(";")[1:]
    }
    sensitive = bool(SESSION_COOKIE.search(name))
    problems = []
    if obs.https and "secure" not in attrs:
        problems.append("Secure")
    if "httponly" not in attrs:
        problems.append("HttpOnly")
    samesite = attrs.get("samesite", "")
    if not samesite:
        problems.append("SameSite")
    elif samesite.lower() == "none" and "secure" not in attrs:
        problems.append("SameSite=None without Secure")
    if not problems:
        return []
    sev = "low" if sensitive and ("Secure" in problems or "HttpOnly" in problems) else "informational"
    return [
        _f(
            obs,
            f"Cookie '{name}' missing attribute(s): {', '.join(problems)}",
            f"Set-Cookie for '{name}' lacks {', '.join(problems)}.",
            "set-cookie: " + _mask_cookie(raw),
            confidence="high",
            impact="Missing Secure allows transmission over HTTP; missing HttpOnly exposes the cookie to "
            "script (relevant only with an XSS flaw); missing SameSite relies on browser defaults (Lax).",
            severity=sev,
            justification=(
                "Name suggests a session/authentication cookie."
                if sensitive
                else "Cookie purpose unknown; treated as non-sensitive."
            ),
            remediation="Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies.",
            category="cookies",
        )
    ]


def observation_record(obs: HttpObservation) -> dict[str, Any]:
    """Serialisable copy of an observation with cookie values masked."""
    headers = {
        k: ([_mask_cookie(v) for v in vals] if k == "set-cookie" else list(vals)) for k, vals in obs.headers.items()
    }
    return {
        "url": obs.url,
        "status": obs.status,
        "headers": headers,
        "source": obs.source,
        "reference": obs.reference,
        "header_subset": sorted(obs.header_subset) if obs.header_subset else None,
        "redirect_chain": obs.redirect_chain,
        "http_to_https": obs.http_to_https,
        "tls": obs.tls,
    }


def _mask_cookie(raw: str) -> str:
    name, _, rest = raw.partition("=")
    value, sep, attrs = rest.partition(";")
    return f"{name}=<{len(value)} chars>{sep}{attrs}"


def _tls_findings(obs: HttpObservation, today: date) -> list[Finding]:
    tls = obs.tls or {}
    out: list[Finding] = []
    if tls.get("error"):
        out.append(
            _f(
                obs,
                "TLS handshake / certificate validation failed",
                f"TLS error: {tls['error']}",
                str(tls["error"])[:200],
                confidence="medium",
                impact="Clients may see certificate warnings or fail to connect.",
                severity="medium",
                justification="Validation failure observed with the system trust store; cause not determined.",
                remediation="Install a valid certificate chain covering the hostname.",
                category="transport",
            )
        )
        return out
    not_after = tls.get("not_after")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").date()
        except ValueError:
            expiry = None
        if expiry:
            days = (expiry - today).days
            if days < 0:
                out.append(
                    _f(
                        obs,
                        "TLS certificate expired",
                        f"Certificate expired {expiry}.",
                        f"notAfter={not_after}",
                        confidence="high",
                        impact="Browsers block or warn.",
                        severity="medium",
                        justification="Directly observed.",
                        remediation="Renew the certificate.",
                        category="transport",
                    )
                )
            elif days <= 14:
                out.append(
                    _f(
                        obs,
                        "TLS certificate expires within 14 days",
                        f"Certificate expires {expiry} ({days} days).",
                        f"notAfter={not_after}",
                        confidence="high",
                        impact="Outage risk if renewal fails.",
                        severity="low",
                        justification="Directly observed; automated renewal may already be in place.",
                        remediation="Confirm automated renewal.",
                        category="transport",
                    )
                )
    return out
