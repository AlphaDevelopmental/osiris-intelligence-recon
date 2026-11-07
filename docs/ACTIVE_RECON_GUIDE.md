# Active Reconnaissance Guide

Active mode sends traffic to the target. Use it **only** with written authorization from the
asset owner, and only against the assets that authorization names.

## What active mode does

1. Runs the passive pipeline (same as `--mode intelligence`).
2. Plans active checks for the primary target and any discovered first-party hosts that the
   scope file allows (at most `--active-max-hosts`, default 5).
3. For each in-scope host, sequentially and at least `--active-interval` seconds apart (default 2 s):
   * `GET https://host/` — headers, cookies; redirects followed only to in-scope hosts (≤ 3 hops);
     at most 64 KiB of body is read.
   * `GET http://host/` — checks for an HTTPS redirect.
   * TLS handshake on 443 — protocol, cipher, issuer, validity, SANs.
   * OSIRIS `/api/scanner` jobs (`--scanner-types`, default `headers,ssl,tech`) — the scanner
     backend, not this machine, contacts the target.
4. Analyses the responses (`osiris/http_analysis.py`) and adds findings.

It does **not** brute force, guess credentials, fuzz, test for denial of service or exploit
anything. Scanner type `vuln` is refused because the backend's behaviour is not published.

## Gates (all required, checked before any network request)

| Gate | Flag |
|---|---|
| mode | `--mode active` |
| separate confirmation | `--enable-active` |
| authorization reference | `--authorization ENGAGEMENT-001` (3–64 chars) |
| scope file | `--scope scope.txt` (must exist and be non-empty) |
| primary target in scope | checked against the scope file |

Then, **before every request and every redirect hop**:

* the host or address must match the scope (exclusions win; `*.x` does not include `x`);
* a hostname is resolved and every address must be public — private addresses need `--lab-mode`;
  loopback, link-local, multicast and reserved addresses are always refused;
* addresses in an excluded network block the request even if the hostname is in scope.

## Scope file

```text
lab.example.com          # exact host
*.lab.example.com        # subdomains only
192.0.2.10               # single address
192.0.2.0/28             # CIDR
!payments.lab.example.com  # exclusion
```

## Scanner availability

The handler checks `SCANNER_KEY` before reading parameters, so a request **without** a target is
a safe configuration probe: 503 = not configured, 400 `Missing target parameter` = configured.
On 2026-11-07 the public deployment at osirisai.live answered **400 — a scanner backend is
configured there**, which means any request with a target makes that backend scan it. Treat
`/api/scanner` on the public deployment as genuinely active. The backend's code is not in the
upstream repository, so what each scan type sends is not documented; this tool defaults to
`headers,ssl,tech` and refuses `vuln`. Use `--active-base https://your-osiris.example` to send
jobs to a deployment you operate instead, or `--no-scanner` to skip them. If a deployment answers
503, the endpoint is reported `unavailable`. The scanner route shares the per-IP rate counter with
the OSINT routes (threshold 5/min), so it may answer 429 right after the passive stage.

## Dry run, cancellation, audit

* `--dry-run` sends **nothing** (neither passive nor active) and lists the plan in the report.
* Ctrl-C stops after the current request; unsent actions are marked `cancelled` and partial
  reports are written (exit code 130).
* Every decision and request is appended to `reports/<target>/active_audit.jsonl` with a
  timestamp and the authorization reference. Keep it with your engagement records — it is
  git-ignored on purpose.

## Example

```bash
python3 osiris_recon.py --target lab.example.com --mode active --enable-active \
  --scope scope.txt --authorization ENGAGEMENT-001 --dry-run
python3 osiris_recon.py --target lab.example.com --mode active --enable-active \
  --scope scope.txt --authorization ENGAGEMENT-001 --scanner-types headers,ssl
```

See `examples/local_lab.md` for an isolated lab setup.
