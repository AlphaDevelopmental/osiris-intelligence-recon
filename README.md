# OSIRIS Intelligence Recon

Scope-aware reconnaissance and threat-intelligence collection over the
[OSIRIS](https://osirisai.live) API: domain → DNS → certificate transparency → subdomains →
IPs → IP intelligence / Shodan index / BGP-ASN → threat feeds → correlated findings → reports.

> **Independent community project.** This tool uses the public OSIRIS API. It is not an official
> OSIRIS product and is not affiliated with or endorsed by the OSIRIS authors. OSIRIS is
> © 2026 simplifaisoul, MIT-licensed: <https://github.com/simplifaisoul/osiris>. Endpoint
> definitions were derived by reading that source; no OSIRIS code is included.

> **Use responsibly.** Run it only against assets you own or are authorized to assess. A lookup
> that succeeds — or returns nothing — is not proof that a target is secure or vulnerable.

## Features

* **Verified registry of all 71 documented OSIRIS operations**, with parameters taken from the
  route handlers rather than the docs — see [docs/ENDPOINT_REGISTRY.md](docs/ENDPOINT_REGISTRY.md).
  Several earlier assumptions were wrong (e.g. Hudson Rock needs `query`/`type`, not `domain`; BGP
  needs `query`; threats ignored `indicator` and silently returned a generic answer).
* **Automatic, bounded enrichment** — IPv4/IPv6 addresses extracted from the actual DNS JSON
  (parsed by RR type, so CNAME answers are not mistaken for IPs) flow into IP, Shodan-index, BGP,
  OTX and entity-graph lookups. Depth, subdomain, IP, ASN and CVE limits all have hard ceilings.
* **Scope discipline** — first-party vs third-party classification, label-boundary domain matching,
  no expansion into mail/DNS providers, CNAME targets, co-hosted tenants or ASNs; non-public
  addresses are never enriched unless `--lab-mode` is set; every asset records its source,
  parent, depth and first-seen time.
* **HTTP / web-technology analysis** — server and PHP version disclosure, PHP lifecycle against
  php.net data (upstream EOL distinguished from vendor backports), WordPress/REST indicators,
  HSTS/CSP/XCTO/Referrer-Policy/frame protection, cookie attributes, HTTPS redirect, TLS metadata.
  Sources: OSIRIS's own HEAD request (no traffic from you), a header capture you supply, or the
  authorized active stage.
* **Robust API handling** — shared rate budget mirroring the upstream limiter, retries with
  exponential backoff and `Retry-After`, no retries for 400/401/403/404, distinct handling for
  timeouts, DNS failures, empty/non-JSON/oversized bodies, streams and degraded 2xx responses;
  secrets redacted from logs and reports.
* **Every endpoint accounted for** — each of the 71 operations is reported as `executed`,
  `skipped`, `unavailable`, `incompatible`, `failed` or `planned`, with a reason.
* **Gated active mode** — `--enable-active` + `--authorization` + `--scope`, scope re-checked
  before every request and redirect hop, sequential and paced, dry-run, Ctrl-C safe, JSONL audit log.
* **Reports** — `report.json`, `report.html`, `report.md`, `assets.csv`, `endpoints.json`;
  findings ranked by severity with evidence, justification, confidence and verification status.

## Installation

```bash
git clone https://github.com/AlphaDevelopmental/osiris-intelligence-recon.git
cd osiris-intelligence-recon
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # runtime: requests only
pip install -r requirements-dev.txt      # tests and linting
```

Python 3.10+. No API key is needed for the public OSIRIS routes used. See `.env.example`
for optional settings (`OSIRIS_BASE_URL`, `OSIRIS_AUTH_HEADER` for a self-hosted deployment).

## Usage

```bash
python3 osiris_recon.py --list-endpoints                         # the 71-operation registry
python3 osiris_recon.py --target example.com --mode recon --dry-run  # plan only, no requests

# 1. Passive reconnaissance with bounded enrichment
python3 osiris_recon.py --target example.com --mode recon

# 2. Threat intelligence (adds OTX, Hudson Rock, Shodan host, entity graph, C2/KEV correlation, CVEs)
python3 osiris_recon.py --target https://www.example.com/ --mode intelligence

# 3. Everything compatible, optionally with global context feeds
python3 osiris_recon.py --target example.com --mode all --include-global --org-name "Example Ltd"

# Analyse headers you captured yourself (no extra traffic)
curl -sI https://example.com/ > headers.txt
python3 osiris_recon.py --target example.com --observed-headers headers.txt

# 4. Authorized active reconnaissance (see docs/ACTIVE_RECON_GUIDE.md)
python3 osiris_recon.py --target lab.example.com --mode active --enable-active \
  --scope scope.txt --authorization ENGAGEMENT-001 --dry-run
```

Other targets: IPv4/IPv6 (`8.8.8.8`), `AS15169`, `CVE-2021-44228`, email (`--mode all` →
breach + infostealer lookups; the mail domain is *not* expanded), E.164 phone, MAC.

Useful options: `--max-depth` (0–3), `--max-subdomains`, `--max-ips`, `--max-asns`, `--max-cves`,
`--strict-passive` (skip `osint/whois`, which makes the OSIRIS server send a HEAD request to the
target), `--lab-mode`, `--out-dir`, `--formats json,html,md,csv`, `--log-format json`, `-v/-q`.

Reports are written to `reports/<target>/` (git-ignored).

## Modes and endpoints

| Mode | Target-specific endpoints |
|---|---|
| `recon` | osint/dns, osint/certs, osint/whois, osint/ip, osint/shodan, osint/bgp |
| `intelligence` | recon + osint/threats, osint/portscan, osint/hudsonrock, entity/expand, osint/cve, cyber-attacks/malware/cyber-threats (for correlation) |
| `all` | intelligence + health, stats, oi, osint/sweep, and type-specific routes (leaks, mac, phone, github, sanctions); `--include-global` adds every parameterless global feed |
| `active` | intelligence + scope-controlled HTTP/TLS checks and `/api/scanner` |

Streams, POST/DELETE routes, AI/OI model calls, caller geolocation and routes needing
coordinates/ids are never invoked automatically; the report explains each.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). In short: `registry` (what exists) →
`api_client` (how to call it safely) → `discovery`/`enrichment` (what to call, within scope) →
`intelligence`/`correlation`/`http_analysis` (what it means) → `reporting`.

## Testing

```bash
pytest                      # offline: all third-party APIs are mocked
ruff check . && ruff format --check .
python tools/verify_endpoints.py --out docs/live_verification.json   # optional, live, ~3 min
python tools/build_registry_doc.py
```

## Limitations

* OSIRIS proxies third-party services (Google DoH, crt.sh, ip-api, InternetDB, OTX, Hudson Rock,
  RIPEstat…). When one of them fails, OSIRIS often still answers 200 with fields missing; the tool
  flags these as degraded but cannot recover the data.
* Most OSINT routes share one ~20/min counter per client IP, so larger scopes take minutes.
* `osint/certs` returns at most 200 certificates' names; crt.sh is frequently unavailable.
* `osint/dns` cannot query `_dmarc` names (upstream validation), so DMARC is not assessed.
* `osint/bgp` and `osint/threats` handle IPv4 only (IPv6 is treated as a domain by threats).
* Shodan-index ports/CVEs are third-party, possibly stale and version-inferred — always
  `unverified`. KEV matches are by product name only.
* The public deployment has a scanner backend configured (a target-less probe returned 400, not
  503), but the backend's code and per-type behaviour are unpublished, so scanner jobs are active
  traffic of unknown depth. They only run in gated active mode; `--no-scanner` disables them.
* Header analysis via `osint/whois` sees only nine header names from a HEAD request.
* The registry reflects upstream commit `d974885`; re-run `tools/verify_endpoints.py` after
  upstream changes.

## License

MIT — see [LICENSE](LICENSE), which also carries the upstream OSIRIS notice.
