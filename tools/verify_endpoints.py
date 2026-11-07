#!/usr/bin/env python3
"""Live verification of registry entries against an OSIRIS deployment.

Uses only the documentation's own example inputs or neutral public values
(example.com, 8.8.8.8, AS15169, CVE-2021-44228). Never calls POST/DELETE routes,
the scanner with a target, the sweep route, the caller-geolocation route, or
routes that take personal data. Stores status codes and top-level keys only.

    python tools/verify_endpoints.py --out docs/live_verification.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from osiris import USER_AGENT  # noqa: E402
from osiris import registry as reg  # noqa: E402
from osiris.api_client import OsirisClient  # noqa: E402

PROBES: dict[str, list[dict[str, str]]] = {
    "GET /api/osint/dns": [{"domain": "example.com"}],
    "GET /api/osint/whois": [{"domain": "example.com"}],
    "GET /api/osint/certs": [{"domain": "example.com"}],
    "GET /api/osint/ip": [{"ip": "8.8.8.8"}, {"ip": "2001:4860:4860::8888"}],
    "GET /api/osint/shodan": [{"ip": "8.8.8.8"}],
    "GET /api/osint/portscan": [{"target": "8.8.8.8"}],
    "GET /api/osint/bgp": [{"query": "8.8.8.8"}, {"query": "AS15169"}],
    "GET /api/osint/mac": [{"mac": "00:1A:2B:3C:4D:5E"}],
    "GET /api/osint/phone": [{"number": "+442071234567"}],
    "GET /api/osint/github": [{"user": "torvalds"}],
    "GET /api/osint/hudsonrock": [{"query": "example.com", "type": "domain"}],
    "GET /api/osint/cve": [{"cve": "CVE-2021-44228"}],
    "GET /api/osint/sanctions": [{"query": "Rosoboronexport", "limit": "3"}],
    "GET /api/osint/threats": [{"query": "8.8.8.8"}, {"query": "example.com"}],
    "GET /api/entity/expand": [{"type": "ip", "id": "8.8.8.8"}],
    "GET /api/sentinel": [{"lat": "51.5072", "lng": "-0.1276"}],
    "GET /api/region-dossier": [{"lat": "48.3794", "lng": "31.1656"}],
}

# The previous client's parameter names, replayed to evidence each documented discrepancy.
LEGACY_PROBES: dict[str, dict[str, str]] = {
    "GET /api/osint/hudsonrock": {"domain": "example.com"},
    "GET /api/osint/bgp": {"ip": "8.8.8.8"},
    "GET /api/osint/threats": {"indicator": "8.8.8.8"},
    "GET /api/osint/cve": {"id": "CVE-2021-44228"},
    "GET /api/osint/github": {"username": "torvalds"},
    "GET /api/osint/phone": {"phone": "+442071234567"},
}

NOT_PROBED: dict[str, str] = {
    "GET /api/osint/leaks": "takes a personal email address; not exercised with real data",
    "GET /api/osint/sweep": "docs describe host sweeping; not called against third-party space (source-verified only)",
    "GET /api/geo": "would record the operator's own location",
    "GET /api/cctv/stream-status": "makes the OSIRIS server fetch an arbitrary URL",
    "GET /api/cctv/proxy": "requires an allow-listed camera stream URL",
    "GET /api/cctv/frame": "requires a camera id",
    "GET /api/proxy-tiles": "requires a tile URL",
    "GET /api/oi/runs/{id}": "requires a run id from a paid POST /api/oi/runs",
}


def keys_of(data: object) -> list[str]:
    return sorted(data.keys()) if isinstance(data, dict) else [type(data).__name__]


def probe_stream(base: str, path: str, timeout: float) -> dict[str, object]:
    try:
        with requests.get(base + path, stream=True, timeout=timeout, headers={"User-Agent": USER_AGENT}) as r:
            first = next(r.iter_content(512), b"")
            return {
                "http": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "first_bytes": len(first),
                "status": "success" if r.ok else "http_error",
            }
    except requests.RequestException as exc:
        return {"status": "network_error", "error": type(exc).__name__}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://osirisai.live")
    ap.add_argument("--out", default="docs/live_verification.json")
    ap.add_argument("--timeout", type=float, default=30)
    args = ap.parse_args()
    client = OsirisClient(args.base, timeout=args.timeout, max_retries=1, max_bytes=3_000_000)
    results: dict[str, dict[str, object]] = {}

    def run(ep: reg.Endpoint, params: dict[str, str] | None, label: str) -> dict[str, object]:
        res = client.get(ep, params, purpose="verification")
        row: dict[str, object] = {
            "probe": label,
            "params": params or {},
            "status": res.status,
            "http": res.http_status,
            "degraded": res.degraded,
        }
        if res.ok:
            row["keys"] = keys_of(res.data)
            missing = [k for k in ep.response_keys if k not in row["keys"]]
            if missing:
                row["documented_keys_missing"] = missing
        if res.error:
            row["error"] = res.error[:200]
        print(f"{res.status:15} {res.http_status or '-':>4} {ep.key} {params or ''}", file=sys.stderr)
        return row

    for ep in reg.ENDPOINTS:
        entry: dict[str, object] = {"probes": []}
        if ep.key in NOT_PROBED:
            entry["not_probed"] = NOT_PROBED[ep.key]
        elif ep.category == reg.STREAM and "{id}" not in ep.path:
            entry["probes"].append({"probe": "stream-open", **probe_stream(client.base_url, ep.path, args.timeout)})
        elif ep.key == "GET /api/scanner":
            # No target is supplied: the handler checks configuration before reading parameters.
            entry["probes"].append(_scanner_probe(client, ep))
        elif ep.method != "GET" or "{id}" in ep.path:
            entry["not_probed"] = f"{ep.method} {ep.category}: not invoked by policy"
        elif ep.key in PROBES:
            for params in PROBES[ep.key]:
                entry["probes"].append(run(ep, params, "documented-params"))
        elif not any(p.required for p in ep.params):
            entry["probes"].append(run(ep, None, "no-params"))
        else:
            entry["not_probed"] = "requires parameters with no neutral example"
        if ep.key in LEGACY_PROBES:
            loose = reg.Endpoint(ep.method, ep.path, ep.group, ep.summary, ep.category, rate_bucket=ep.rate_bucket)
            entry["legacy_param_probe"] = run(loose, LEGACY_PROBES[ep.key], "previous-client-params")
        results[ep.key] = entry

    doc = {
        "verified_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "base": client.base_url,
        "upstream_commit_reviewed": reg.UPSTREAM_COMMIT,
        "results": results,
    }
    Path(args.out).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


def _scanner_probe(client: OsirisClient, ep: reg.Endpoint) -> dict[str, object]:
    with requests.get(client.base_url + ep.path, timeout=20, headers={"User-Agent": USER_AGENT}) as r:
        try:
            body = r.json()
        except ValueError:
            body = {}
        return {
            "probe": "config-check-without-target",
            "http": r.status_code,
            "status": "unavailable"
            if r.status_code == 503
            else ("invalid_request" if r.status_code == 400 else "other"),
            "error": str(body.get("error", ""))[:120],
        }


if __name__ == "__main__":
    sys.exit(main())
