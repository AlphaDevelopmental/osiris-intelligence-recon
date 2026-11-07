# Architecture

```
osiris_recon.py            entry point → osiris.cli.main
osiris/
  registry.py              71 operations, verified params, category, target contact, rate bucket, modes
  api_client.py            read-only HTTP client: rate budgets, retries/backoff, error classes, size limits, redaction
  targets.py               input parsing (domain/URL/IP/email/CVE/ASN/phone/MAC), IP classification, scope boundary
  discovery.py             OSIRIS DNS + CT parsers, deduplicated asset inventory with provenance
  enrichment.py            pipeline + ExecutionTracker (every endpoint gets a final status and reason)
  intelligence.py          C2/KEV feed matching, Shodan-index findings
  correlation.py           finding builders (C2, Hudson Rock, OTX, SPF, sanctions), ranking and IDs
  http_analysis.py         header/cookie/TLS analysis, PHP lifecycle (php.net data)
  active.py                scope file, authorization gate, audit log, paced active runner
  reporting.py             JSON / HTML / Markdown / CSV / endpoints.json
tools/
  verify_endpoints.py      live verification probes → docs/live_verification.json
  build_registry_doc.py    renders docs/ENDPOINT_REGISTRY.md
```

## Data flow

```
target ──parse_target──▶ Target(kind, value)
                           │
     ┌─────────────────────┴───────────── domain ────────────────────────────┐
     │ osint/dns(root) ─▶ A/AAAA/CNAME/MX/NS/SPF (parsed by RR type)          │
     │ osint/whois(root) ─▶ RDAP + OSIRIS-side HEAD headers ─▶ http_analysis  │
     │ osint/certs(root) ─▶ subdomains (label-boundary filtered)              │
     │ BFS over first-party hosts (max depth / max subdomains) ─▶ osint/dns   │
     └─────────────────────┬──────────────────────────────────────────────────┘
                           ▼
          AssetInventory: value, kind, relation, sources, first_seen, parent, depth
                           │  public (or --lab-mode private) IPs only, ≤ --max-ips
                           ▼
     osint/ip · osint/shodan · osint/bgp(IPv4) ─▶ ASNs ─▶ osint/bgp(ASN) ≤ --max-asns
     [intelligence] osint/threats · osint/portscan · entity/expand(type=ip)
                    osint/threats(domain) · osint/hudsonrock(query,type)
                    cyber-attacks + malware feeds ─▶ C2 match on target IPs
                    cyber-threats ─▶ KEV ids + product-name match on observed tech
                    osint/cve for index-associated CVEs ≤ --max-cves
     [all]          health · stats · oi · sweep · type-specific (email/mac/phone/github/sanctions)
                    --include-global: every parameterless global feed (summarised, not stored)
     [active]       scope-checked HTTP/TLS + OSIRIS /api/scanner jobs
                           ▼
            correlation.finalize ─▶ ranked findings (OSR-001…) ─▶ reporting
```

## Relations

| Relation | Meaning | Enriched? |
|---|---|---|
| `target` | the input | yes |
| `first_party` | the target domain's subdomains (label boundary) | resolved via DNS |
| `hosting` | an address a first-party name resolves to; tenancy unknown | yes (public only) |
| `third_party` | MX/NS providers, out-of-domain CNAME targets, ASNs | recorded only |
| `referenced` | SPF `ip4:`/`include:` terms | recorded only |

Third-party assets are never expanded: no DNS on provider hosts, no reverse lookups of co-hosted
tenants (only a count of index hostnames is kept), no prefix expansion of ASNs.

## Execution statuses

Every registered endpoint ends as one of `executed`, `skipped`, `unavailable`, `incompatible`,
`failed` or `planned` (dry run), with an explanation. Static reasons come from
`registry.default_disposition` (category × mode × target kind); dynamic ones (limits reached,
no public IP found) are attached by the pipeline; call outcomes come from `api_client`.

## Error handling

| Condition | Class | Retried |
|---|---|---|
| 400 / 422 | `invalid_request` | no |
| 401 / 402 / 403 | `auth_error` | no |
| 404 | `not_found` | no |
| 429 | `rate_limited` | yes — bucket paused for `Retry-After` (default 60 s) |
| 500 / 502 / 504 | `upstream_error` | yes, exponential backoff + jitter (cap 30 s) |
| 503 "not configured" | `unavailable` | no |
| 503 other | `unavailable` | yes |
| timeout / connection / DNS failure | `timeout` / `network_error` | yes |
| empty, non-JSON, oversized body | `empty_response` / `invalid_json` / `oversized` | no |
| `text/event-stream` | `stream_refused` | no |
| 2xx with `error` in body | `success` + `degraded` | no |

Streams, POST/DELETE routes and (outside active mode) the scanner are refused by the client
itself, so a registry or pipeline bug cannot trigger them.
