"""Verified registry of the 71 operations published in the OSIRIS API catalog.

Source of truth, in order:
  1. Route handlers in https://github.com/simplifaisoul/osiris  (src/app/api/**/route.ts)
  2. The docs catalog that renders https://osirisai.live/docs   (src/app/docs/apiCatalog.ts)
Upstream commit inspected: d974885468b0e29b8863253ded120a3dfd894275 (2026-11-05).

Where the docs and the handler disagree, parameters follow the handler and the
difference is recorded in `docs_discrepancy`. Live verification results are kept
separately in docs/live_verification.json and are never inferred from this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

UPSTREAM_COMMIT = "d974885468b0e29b8863253ded120a3dfd894275"
UPSTREAM_REPO = "https://github.com/simplifaisoul/osiris"

# Categories
TARGET = "target-osint"  # takes a subject the target can supply
GLOBAL = "global-feed"  # same data for every caller; not target specific
SYSTEM = "system"
CONTEXT = "requires-context"  # needs coordinates / ids / URLs a target cannot supply
STREAM = "stream"  # Server-Sent Events, unbounded
STATEFUL = "state-changing"  # POST/DELETE with side effects or cost
AI = "ai"  # POST to model-backed routes; needs a body and often a model key
ACTIVE = "active"  # traffic is sent to the target by a scanner backend
CALLER = "caller-specific"  # answers about the caller, not a target

# Target contact: does the *target* receive traffic because of this call?
NONE = "none"
INDIRECT = "indirect"  # the OSIRIS server itself contacts the target (e.g. HEAD request)
ACTIVE_CONTACT = "active"

# Shared rate-limit buckets as implemented in src/lib/ssrf-guard.ts:isRateLimited.
# Most OSINT routes call isRateLimited(clientIp, N) with the *same* key, so they
# share one fixed 60 s window per client address per server instance; each route
# compares that shared count against its own threshold N.
RATE_BUCKETS: dict[str, tuple[int, float]] = {
    "shared": (18, 60.0),  # upstream threshold 20 (5 for scanner); 18 leaves headroom
    "portscan": (14, 60.0),  # upstream 15/min, separate key
    "sweep": (4, 60.0),  # upstream 5/min, its own map
    "polite": (30, 60.0),  # routes without a server-side limit; be a good citizen
    # /api/scanner compares the *shared* counter with 5; ActiveRunner drains "shared" first.
    "scanner": (4, 60.0),
}


@dataclass(frozen=True)
class Param:
    name: str
    required: bool
    desc: str


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    group: str
    summary: str
    category: str
    params: tuple[Param, ...] = ()
    inputs: tuple[str, ...] = ()  # target kinds the endpoint can be fed
    contact: str = NONE
    rate_bucket: str | None = None
    rate_limit: str = "none in handler"
    auth: str = "none"
    server_config: tuple[str, ...] = ()
    modes: frozenset[str] = field(default_factory=frozenset)
    default_params: tuple[tuple[str, str], ...] = ()  # sent when collected as a global feed
    min_timeout: float = 0.0  # seconds; the handler's own upstream timeout plus headroom
    response_keys: tuple[str, ...] = ()
    docs_discrepancy: str = ""
    notes: str = ""

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def source_file(self) -> str:
        p = self.path.replace("{id}", "[id]")
        return f"src/app{p}/route.ts"


RECON = frozenset({"recon", "intelligence", "all", "active"})
INTEL = frozenset({"intelligence", "all", "active"})
ALL = frozenset({"all"})
NOMODE: frozenset[str] = frozenset()

_SHARED = "shared fixed window, threshold 20/min per client IP"

ENDPOINTS: tuple[Endpoint, ...] = (
    # ── system ──────────────────────────────────────────────────────────
    Endpoint(
        "GET",
        "/api/health",
        "system",
        "Liveness probe (does not check upstream feeds).",
        SYSTEM,
        modes=ALL,
        response_keys=("status", "platform", "version", "uptime_seconds", "timestamp"),
        docs_discrepancy="Docs say `status` is `operational` and list `uptime`/`endpoints`; the "
        "deployment returned `status: serving` and `uptime_seconds` on 2026-11-07.",
    ),
    Endpoint(
        "GET",
        "/api/stats",
        "system",
        "Aggregate counters across heavy feeds.",
        SYSTEM,
        modes=ALL,
        response_keys=("stats", "timestamp"),
    ),
    # ── aviation & space ────────────────────────────────────────────────
    Endpoint("GET", "/api/flights", "aviation", "Live ADS-B aircraft.", GLOBAL),
    Endpoint("GET", "/api/satellites", "aviation", "Tracked orbital objects.", GLOBAL),
    Endpoint("GET", "/api/space-weather", "aviation", "NOAA SWPC geomagnetic conditions.", GLOBAL),
    # ── earth & environment ─────────────────────────────────────────────
    Endpoint("GET", "/api/earthquakes", "environment", "USGS M2.5+ events, trailing day.", GLOBAL),
    Endpoint(
        "GET", "/api/fires", "environment", "NASA FIRMS hotspots.", GLOBAL, server_config=("FIRMS_API_KEY (optional)",)
    ),
    Endpoint("GET", "/api/weather", "environment", "NASA EONET natural events.", GLOBAL),
    Endpoint("GET", "/api/air-quality", "environment", "Ground-station air quality.", GLOBAL),
    Endpoint("GET", "/api/radar", "environment", "GPS interference / navigation outages.", GLOBAL),
    Endpoint(
        "GET",
        "/api/sentinel",
        "environment",
        "Sentinel imagery scenes near a point.",
        CONTEXT,
        params=(
            Param("lat", True, "latitude"),
            Param("lng", True, "longitude"),
            Param("radius", False, "km"),
            Param("days", False, "look-back days"),
        ),
    ),
    # ── geopolitical ────────────────────────────────────────────────────
    Endpoint("GET", "/api/conflicts", "geopolitical", "Curated conflict zones with headlines.", GLOBAL),
    Endpoint("GET", "/api/frontlines", "geopolitical", "Frontline geometry.", GLOBAL),
    Endpoint("GET", "/api/gdelt", "geopolitical", "Geocoded GDELT events.", GLOBAL),
    Endpoint("GET", "/api/country-risk", "geopolitical", "Editorial country risk + market sessions.", GLOBAL),
    Endpoint(
        "GET",
        "/api/region-dossier",
        "geopolitical",
        "Composite dossier for a map point.",
        CONTEXT,
        params=(Param("lat", True, "latitude"), Param("lng", True, "longitude")),
    ),
    # ── media & markets ─────────────────────────────────────────────────
    Endpoint("GET", "/api/news", "media", "Telegram OSINT posts.", GLOBAL),
    Endpoint("GET", "/api/live-news", "media", "24/7 broadcast streams list.", GLOBAL),
    Endpoint("GET", "/api/markets", "media", "Defence equities and commodities.", GLOBAL),
    Endpoint("GET", "/api/crypto", "media", "Ticker spot prices.", GLOBAL),
    Endpoint("GET", "/api/scm-suppliers", "media", "Supply-chain supplier risk.", GLOBAL),
    # ── surveillance & infrastructure ───────────────────────────────────
    Endpoint(
        "GET",
        "/api/cctv",
        "infrastructure",
        "Public camera catalogue (> 3 MB unfiltered).",
        GLOBAL,
        params=(
            Param("region", False, "provider region"),
            Param("lat", False, "latitude"),
            Param("lng", False, "longitude"),
            Param("radius", False, "km"),
        ),
    ),
    Endpoint(
        "GET",
        "/api/cctv/stream-status",
        "infrastructure",
        "Server probes a camera stream URL.",
        CONTEXT,
        params=(Param("url", True, "stream URL"),),
        contact=INDIRECT,
        notes="The OSIRIS server fetches the supplied URL; never fed target data.",
    ),
    Endpoint(
        "GET",
        "/api/cctv/proxy",
        "infrastructure",
        "Allow-listed camera stream proxy.",
        CONTEXT,
        params=(Param("url", True, "allow-listed stream URL"),),
    ),
    Endpoint(
        "GET",
        "/api/cctv/frame",
        "infrastructure",
        "Still frame for a catalogue camera.",
        CONTEXT,
        params=(Param("id", True, "camera id from /api/cctv"),),
        rate_limit="90/min (cctv-frame key)",
    ),
    Endpoint("GET", "/api/infrastructure", "infrastructure", "Strategic infrastructure sites.", GLOBAL),
    Endpoint(
        "GET",
        "/api/maritime",
        "infrastructure",
        "Ports, chokepoints, vessels.",
        GLOBAL,
        server_config=("AIS_API_KEY (optional)",),
    ),
    Endpoint(
        "GET",
        "/api/transit",
        "infrastructure",
        "GTFS-Realtime vehicles / feed coverage.",
        GLOBAL,
        params=(Param("bbox", False, "w,s,e,n"), Param("coverage", False, "1 = feed coverage")),
        default_params=(("coverage", "1"),),
        rate_limit="60/min (transit key)",
        docs_discrepancy="Docs mark both parameters optional; without either the deployment answered 400 "
        "`bbox is required` (2026-11-07). Collected with coverage=1.",
    ),
    Endpoint(
        "GET",
        "/api/arcgis",
        "infrastructure",
        "Configured ArcGIS feature service query.",
        CONTEXT,
        params=(
            Param("q", True, "keyword (or `service`)"),
            Param("service", False, "service URL"),
            Param("bbox", False, "bbox"),
        ),
        rate_bucket="shared",
        rate_limit=_SHARED.replace("20", "30"),
        docs_discrepancy="Docs mark all parameters optional; the deployment answered 400 `Provide ?q=keyword "
        "or ?service=URL` without them (2026-11-07).",
    ),
    Endpoint(
        "GET",
        "/api/proxy-tiles",
        "infrastructure",
        "Basemap tile proxy.",
        CONTEXT,
        params=(Param("url", True, "https tile URL on *.basemaps.cartocdn.com"),),
    ),
    Endpoint(
        "GET",
        "/api/geo",
        "infrastructure",
        "Geolocates the *calling client* by IP.",
        CALLER,
        notes="Reveals the operator's own location; never called automatically.",
    ),
    # ── cyber ───────────────────────────────────────────────────────────
    Endpoint(
        "GET",
        "/api/cyber-threats",
        "cyber",
        "Recent CVE disclosures (CISA KEV et al.).",
        GLOBAL,
        modes=INTEL,
        response_keys=("threats", "stats"),
        notes="Used for correlation: KEV vendor/product matched against technology observed on the target.",
    ),
    Endpoint(
        "GET",
        "/api/cyber-attacks",
        "cyber",
        "Botnet C2 listings (Feodo Tracker, TweetFeed).",
        GLOBAL,
        modes=INTEL,
        params=(Param("etag", False, "conditional fetch"),),
        response_keys=("indicators", "total", "online", "fetched_at", "source"),
        notes="Used for correlation: discovered IPs matched against listed C2 addresses.",
    ),
    Endpoint(
        "GET",
        "/api/malware",
        "cyber",
        "Malware C2 servers (ViriBack, C2IntelFeeds).",
        GLOBAL,
        modes=INTEL,
        response_keys=("threats", "total", "last_poll", "source", "timestamp"),
        notes="Used for correlation: discovered IPs matched against listed C2 addresses.",
    ),
    Endpoint("GET", "/api/malware/stream", "cyber", "SSE stream of malware detections.", STREAM),
    # ── OSINT toolkit ───────────────────────────────────────────────────
    Endpoint(
        "GET",
        "/api/osint/dns",
        "osint",
        "A/AAAA/MX/NS/TXT/CNAME/SOA via Google DoH.",
        TARGET,
        params=(Param("domain", True, "domain name"),),
        inputs=("domain",),
        rate_bucket="shared",
        rate_limit=_SHARED,
        modes=RECON,
        response_keys=("domain", "records", "summary", "timestamp"),
        docs_discrepancy="Docs omit CNAME. `summary.ip_addresses` is built from the A answer set only "
        "(no AAAA) and, because answers are not filtered by type, can include CNAME "
        "targets; this client re-parses `records` by RR type instead.",
    ),
    Endpoint(
        "GET",
        "/api/osint/whois",
        "osint",
        "RDAP registration + HTTP header sample + OFAC cross-check.",
        TARGET,
        params=(Param("domain", True, "domain name"),),
        inputs=("domain",),
        contact=INDIRECT,
        rate_bucket="shared",
        rate_limit=_SHARED,
        modes=RECON,
        response_keys=("domain", "rdap", "registration", "expiration", "http", "security_score", "sanctions_match"),
        docs_discrepancy="Docs describe registration data only. The handler also sends a HEAD request to "
        "https://<domain> from the OSIRIS server and returns 9 selected response headers "
        "plus a heuristic `security_score`.",
    ),
    Endpoint(
        "GET",
        "/api/osint/certs",
        "osint",
        "Certificate Transparency search via crt.sh.",
        TARGET,
        params=(Param("domain", True, "apex domain"),),
        inputs=("domain",),
        rate_bucket="shared",
        rate_limit=_SHARED,
        modes=RECON,
        response_keys=("domain", "certificates", "subdomains", "total_certs", "unique_subdomains"),
        docs_discrepancy='On crt.sh failure the handler returns HTTP 200 with `error: "crt.sh unavailable"` '
        "and no `subdomains` key; the subdomain filter uses `endsWith(domain)` without a "
        "label boundary, so this client re-filters.",
    ),
    Endpoint(
        "GET",
        "/api/osint/ip",
        "osint",
        "ip-api geolocation/ASN + OFAC cross-check.",
        TARGET,
        params=(Param("ip", True, "IPv4 or IPv6"),),
        inputs=("ipv4", "ipv6"),
        rate_bucket="shared",
        rate_limit=_SHARED,
        modes=RECON,
        response_keys=("ip", "geo", "reputation", "sanctions_match", "timestamp"),
        notes="`reputation.risk_level` is derived only from ip-api proxy/hosting flags.",
    ),
    Endpoint(
        "GET",
        "/api/osint/shodan",
        "osint",
        "Shodan InternetDB record (ports, CPEs, vulns).",
        TARGET,
        params=(Param("ip", True, "address"),),
        inputs=("ipv4", "ipv6"),
        rate_bucket="polite",
        modes=RECON,
        response_keys=("ip", "ports", "cpes", "hostnames", "tags", "vulns"),
        docs_discrepancy="Docs promise banners; the handler proxies keyless InternetDB, which has no banners.",
    ),
    Endpoint(
        "GET",
        "/api/osint/portscan",
        "osint",
        "Shodan host record (or InternetDB fallback).",
        TARGET,
        params=(Param("target", True, "IP or hostname"),),
        inputs=("ipv4", "ipv6", "domain"),
        rate_bucket="portscan",
        rate_limit="15/min (portscan key)",
        modes=INTEL,
        server_config=("SHODAN_API_KEY (optional)",),
        response_keys=("target", "ip", "source", "ports", "hostnames", "domains", "cpes", "vulns", "note"),
        docs_discrepancy="Despite the name this is a lookup of Shodan's existing index, not a scan; "
        "no packets are sent to the target. Private/reserved targets are refused (400).",
    ),
    Endpoint(
        "GET",
        "/api/osint/bgp",
        "osint",
        "ASN/route owner via ip-api + RIPEstat.",
        TARGET,
        params=(Param("query", True, "IPv4 address or ASN (AS123)"),),
        inputs=("ipv4", "asn"),
        rate_bucket="shared",
        rate_limit=_SHARED,
        modes=RECON,
        response_keys=("query", "type", "ip", "asn", "prefixes", "peers"),
        docs_discrepancy="Docs accept a prefix; the handler rejects prefixes and IPv6 (400). `prefixes` "
        "and `peers` are always empty. Previous client sent `ip=` (wrong).",
    ),
    Endpoint(
        "GET",
        "/api/osint/mac",
        "osint",
        "MAC/OUI vendor lookup.",
        TARGET,
        params=(Param("mac", True, "MAC or OUI"),),
        inputs=("mac",),
        rate_bucket="polite",
        modes=ALL,
    ),
    Endpoint(
        "GET",
        "/api/osint/phone",
        "osint",
        "E.164 phone validation/classification.",
        TARGET,
        params=(Param("number", True, "E.164 number"),),
        inputs=("phone",),
        rate_bucket="polite",
        modes=ALL,
        docs_discrepancy="Previous client sent `phone=`; the handler reads `number`.",
    ),
    Endpoint(
        "GET",
        "/api/osint/github",
        "osint",
        "Public GitHub profile metadata.",
        TARGET,
        params=(Param("user", True, "GitHub login"),),
        inputs=("github_user",),
        rate_bucket="polite",
        modes=ALL,
        docs_discrepancy="Previous client sent `username=`; the handler reads `user`.",
    ),
    Endpoint(
        "GET",
        "/api/osint/leaks",
        "osint",
        "XposedOrNot breach analytics for an email.",
        TARGET,
        params=(Param("email", True, "email address"),),
        inputs=("email",),
        rate_bucket="polite",
        modes=ALL,
        notes="Personal data. Only run when the email itself is the authorised target.",
    ),
    Endpoint(
        "GET",
        "/api/osint/hudsonrock",
        "osint",
        "Hudson Rock infostealer exposure.",
        TARGET,
        params=(
            Param("query", True, "email, domain, username or phone"),
            Param("type", False, "email|domain|username|phone"),
        ),
        inputs=("domain", "email", "phone"),
        min_timeout=45.0,  # the handler itself waits up to 25 s for Hudson Rock
        rate_bucket="polite",
        modes=INTEL,
        response_keys=("query", "type", "compromised", "totalStealers", "employees", "users"),
        docs_discrepancy="Previous client sent `domain=`, which the handler rejects with "
        "400 `Missing query parameter` — the cause of the observed Hudson Rock failure.",
    ),
    Endpoint(
        "GET",
        "/api/osint/cve",
        "osint",
        "CVE record (MITRE CVE API, CIRCL fallback).",
        TARGET,
        params=(Param("cve", True, "CVE-YYYY-NNNN"),),
        inputs=("cve",),
        rate_bucket="shared",
        rate_limit=_SHARED.replace("20", "30"),
        modes=INTEL,
        response_keys=("id", "description", "cvss", "severity", "published", "references", "source"),
        docs_discrepancy="Docs say NVD; the handler queries MITRE's CVE API then CIRCL. Previous client "
        "sent `id=` (wrong).",
    ),
    Endpoint(
        "GET",
        "/api/osint/sanctions",
        "osint",
        "OFAC SDN search (OpenSanctions mirror).",
        TARGET,
        params=(
            Param("query", True, "name, >= 4 chars"),
            Param("schema", False, "Person|Organization|..."),
            Param("limit", False, "1-100"),
        ),
        inputs=("org_name",),
        rate_bucket="shared",
        rate_limit=_SHARED,
        modes=ALL,
        notes="Names are not inferred from domains; supply --org-name. /api/osint/whois already "
        "cross-checks RDAP registrant names.",
    ),
    Endpoint(
        "GET",
        "/api/osint/threats",
        "osint",
        "AlienVault OTX reputation + Tor exit check.",
        TARGET,
        params=(Param("query", False, "IPv4 or domain"),),
        inputs=("ipv4", "domain"),
        rate_bucket="shared",
        rate_limit=_SHARED,
        modes=INTEL,
        response_keys=("timestamp", "pulses", "tor_exit_node", "otx", "threat_level"),
        docs_discrepancy="Previous client sent `indicator=`, which the handler ignores — it silently "
        "returned the global pulse feed with `threat_level: UNKNOWN`. Docs mention file "
        "hashes; the handler treats every non-IPv4 value (incl. IPv6) as a domain.",
    ),
    Endpoint(
        "GET",
        "/api/osint/sweep",
        "osint",
        "Geolocation of one IPv4 (no sweep in current source).",
        TARGET,
        params=(Param("ip", True, "public IPv4"), Param("cidr", False, "integer prefix length 24-32")),
        inputs=("ipv4",),
        rate_bucket="sweep",
        rate_limit="5/min (own map)",
        modes=ALL,
        response_keys=("center", "target_ip", "cidr"),
        docs_discrepancy="Docs: 'sweeps an address or CIDR for reachable hosts', `ip` optional, cidr "
        "example `192.0.2.0/24`. Handler: `ip` required, `cidr` must be an integer "
        "24-32, and it only geolocates `ip` via ip-api — no host is contacted. Treated "
        "as passive; re-verify if upstream changes.",
    ),
    # ── recon scanner ───────────────────────────────────────────────────
    Endpoint(
        "GET",
        "/api/scanner",
        "scanner",
        "Delegates a scan to the OSIRIS scanner backend.",
        ACTIVE,
        params=(
            Param("target", True, "host, domain or address"),
            Param("type", False, "quick|ssl|headers|rdns|subdomains|tech|whois|geoloc|vuln (default quick)"),
        ),
        inputs=("domain", "ipv4", "ipv6"),
        contact=ACTIVE_CONTACT,
        rate_bucket="scanner",
        rate_limit="shared window, threshold 5/min",
        server_config=("SCANNER_URL", "SCANNER_KEY"),
        modes=frozenset({"active"}),
        docs_discrepancy="Docs mark `type` required; handler defaults it to `quick`. The scanner backend "
        "is not in the upstream repo. 503 = not configured; the public deployment answered 400 `Missing "
        "target parameter` to a target-less probe on 2026-11-07, i.e. a backend IS configured there.",
    ),
    # ── entity graph ────────────────────────────────────────────────────
    Endpoint(
        "GET",
        "/api/entity/expand",
        "entity",
        "Graph expansion via the osiris-intel service.",
        TARGET,
        params=(
            Param("type", True, "aircraft|vessel|company|person|ip|country"),
            Param("id", True, "identifier, 2-200 chars"),
        ),
        inputs=("ipv4", "ipv6"),
        rate_bucket="shared",
        rate_limit=_SHARED.replace("20", "30"),
        modes=INTEL,
        server_config=("INTEL_URL",),
        response_keys=("nodes", "links"),
        notes="type=ip resolves ip-api + RIPEstat prefix data. Previous client never sent `type`.",
    ),
    # ── AI analysis ─────────────────────────────────────────────────────
    Endpoint(
        "POST",
        "/api/ai/analyze",
        "ai",
        "Model correlation over an IntelligenceContext body.",
        AI,
        rate_limit="5/min",
        server_config=("GEMINI key on server",),
    ),
    Endpoint(
        "POST",
        "/api/ai/briefing",
        "ai",
        "Model daily-briefing over an IntelligenceContext body.",
        AI,
        rate_limit="5/min",
    ),
    Endpoint(
        "POST",
        "/api/ai/overview",
        "ai",
        "Model read-out for Alerts/Markets panels.",
        AI,
        rate_bucket="shared",
        rate_limit=_SHARED,
    ),
    # ── OI ──────────────────────────────────────────────────────────────
    Endpoint("GET", "/api/oi", "oi", "OI service description.", SYSTEM, modes=ALL),
    Endpoint("POST", "/api/oi/models", "oi", "Lists models for a caller-supplied model key.", AI, auth="X-OI-Key"),
    Endpoint("POST", "/api/oi/runs", "oi", "Starts a paid prediction run.", STATEFUL, auth="X-OI-Key"),
    Endpoint(
        "GET",
        "/api/oi/runs/{id}",
        "oi",
        "Prediction run summary.",
        CONTEXT,
        params=(Param("wait", False, "seconds <= 55"), Param("view", False, "full")),
    ),
    Endpoint(
        "GET", "/api/oi/runs/{id}/events", "oi", "SSE stream of a run.", STREAM, params=(Param("after", False, "seq"),)
    ),
    Endpoint("GET", "/api/oi/trending", "oi", "Polymarket questions.", GLOBAL),
    Endpoint("POST", "/api/oi/assist", "oi", "One OI Assist conversation step.", AI, auth="X-OI-Key"),
    Endpoint("POST", "/api/oi/runs/{id}/ask", "oi", "Question a run's agents.", AI, auth="X-OI-Key"),
    Endpoint("POST", "/api/oi/runs/{id}/inject", "oi", "Inject an event into a run.", STATEFUL, auth="X-OI-Run-Token"),
    Endpoint("DELETE", "/api/oi/runs/{id}", "oi", "Cancel a run.", STATEFUL, auth="X-OI-Run-Token"),
    Endpoint(
        "POST",
        "/api/mcp",
        "oi",
        "MCP JSON-RPC server (Streamable HTTP).",
        AI,
        auth="X-OI-Key for oi_* tools",
        docs_discrepancy="Handler also exports GET and DELETE.",
    ),
    # ── Polybolos SDK ───────────────────────────────────────────────────
    Endpoint(
        "POST",
        "/api/sdk/ingest",
        "sdk",
        "Push entities into the shared map.",
        STATEFUL,
        auth="SDK_INGEST_KEY (fail-closed)",
    ),
    Endpoint("GET", "/api/sdk/ingest", "sdk", "External entity count + ingest log.", GLOBAL),
    Endpoint("GET", "/api/sdk/stream", "sdk", "SSE stream of normalised entities.", STREAM),
    # ── webhooks ────────────────────────────────────────────────────────
    Endpoint(
        "POST",
        "/api/github-webhook",
        "webhook",
        "GitHub event receiver (signature verified).",
        STATEFUL,
        auth="GitHub HMAC signature",
    ),
)

# Routes present in upstream source but absent from the published catalog.
# They are documented, not registered, so the 71-operation contract stays intact.
UNDOCUMENTED_ROUTES: tuple[str, ...] = (
    "/api/aircraft",
    "/api/cctv/resolve",
    "/api/cctv/texas/snapshot",
    "/api/chain/daily",
    "/api/cloudflare-radar",
    "/api/directions",
    "/api/flight-route",
    "/api/gdelt-events",
    "/api/geosearch",
    "/api/geosearch/shared",
    "/api/markets/history",
    "/api/oi/identify",
    "/api/osint/crypto",
    "/api/osint/fingerprint",
    "/api/osint/username",
    "/api/rain",
    "/api/satellites/orbit",
    "/api/wind",
)

BY_KEY: dict[str, Endpoint] = {e.key: e for e in ENDPOINTS}


def get(path: str, method: str = "GET") -> Endpoint:
    return BY_KEY[f"{method} {path}"]


def default_disposition(ep: Endpoint, mode: str, include_global: bool) -> tuple[str, str] | None:
    """Static reason an endpoint will not run in `mode`, or None if the pipeline may use it.

    Returns (status, reason) using the statuses in osiris.models.
    """
    if ep.category == STREAM:
        return "skipped", "Server-Sent Events stream; unbounded, not consumed by a batch collector."
    if ep.category == STATEFUL:
        return "skipped", f"State-changing {ep.method}; never invoked automatically (auth: {ep.auth})."
    if ep.category == AI:
        return "skipped", f"Model-backed {ep.method} requiring a request body ({ep.auth}); not target recon."
    if ep.category == CALLER:
        return "skipped", "Describes the calling client, not the target; would disclose the operator's location."
    if ep.category == CONTEXT:
        needed = ", ".join(p.name for p in ep.params if p.required) or "a run id"
        return "incompatible", f"Requires {needed}, which cannot be derived from the target."
    if ep.category == ACTIVE and mode != "active":
        return "skipped", "Active scan; only available in --mode active with scope, authorization and --enable-active."
    if ep.category == GLOBAL and mode not in ep.modes:
        if mode == "all" and include_global:
            return None
        hint = "use --mode all --include-global" if mode != "all" else "add --include-global"
        return "skipped", f"Global feed, not target-specific ({hint})."
    if ep.category == SYSTEM and mode not in ep.modes:
        return "skipped", "Platform status endpoint; collected in --mode all only."
    if ep.category == TARGET and mode not in ep.modes:
        return "skipped", f"Not part of --mode {mode} (runs in: {', '.join(sorted(ep.modes)) or 'none'})."
    return None
