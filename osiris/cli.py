"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from . import registry as reg
from .active import DEFAULT_SCANNER_TYPES, ActiveConfig, ActiveError, ActiveRunner, AuditLog, validate_active
from .api_client import OsirisClient
from .enrichment import MODES, ReconConfig, ReconPipeline
from .http_analysis import analyze, detect_technologies, observation_record
from .models import FIRST_PARTY, PLANNED, SKIPPED, TARGET, UNAVAILABLE
from .reporting import build_report, safe_dirname, write_reports
from .targets import TargetError, parse_target

log = logging.getLogger("osiris")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="seconds"),
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }
        )


def setup_logging(verbose: int, fmt: str) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter("%(levelname)-7s %(message)s"))
    root = logging.getLogger("osiris")
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose > 1 else logging.INFO if verbose else logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osiris_recon.py",
        description="Scope-aware reconnaissance and intelligence collection over the OSIRIS API "
        "(independent community tool, not an official OSIRIS product).",
    )
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--target", help="domain, URL, IPv4/IPv6, email, CVE, ASN (AS123), E.164 phone or MAC")
    p.add_argument("--mode", choices=MODES, default="recon")
    p.add_argument("--list-endpoints", action="store_true", help="print the 71-operation registry and exit")
    p.add_argument("--json", action="store_true", help="with --list-endpoints: JSON output")
    p.add_argument("--base", default=os.environ.get("OSIRIS_BASE_URL", "https://osirisai.live"))
    p.add_argument("--dry-run", action="store_true", help="plan only; send no requests at all")
    p.add_argument("--out-dir", help="report directory (default: reports/<target>)")
    p.add_argument("--formats", default="json,html,md,csv")
    g = p.add_argument_group("discovery limits")
    g.add_argument("--max-depth", type=int, default=1, help="0 = no subdomain discovery (hard cap 3)")
    g.add_argument("--max-subdomains", type=int, default=15)
    g.add_argument("--max-ips", type=int, default=8)
    g.add_argument("--max-asns", type=int, default=5)
    g.add_argument("--max-cves", type=int, default=10)
    g.add_argument(
        "--lab-mode",
        action="store_true",
        help="authorised local lab only: allow RFC1918/ULA addresses in enrichment and active checks",
    )
    g.add_argument(
        "--strict-passive",
        action="store_true",
        help="skip routes that make the OSIRIS server contact the target (osint/whois HEAD request)",
    )
    i = p.add_argument_group("extra inputs")
    i.add_argument(
        "--include-global",
        "--context",
        action="store_true",
        dest="include_global",
        help="--mode all: also collect global context feeds (not target-specific)",
    )
    i.add_argument("--org-name", help="organisation name for the OFAC SDN search (--mode all)")
    i.add_argument("--github-user", help="GitHub account to look up (--mode all)")
    i.add_argument("--observed-headers", help="file with HTTP response headers you captured (e.g. curl -I output)")
    h = p.add_argument_group("HTTP client")
    h.add_argument("--timeout", type=float, default=25.0)
    h.add_argument("--retries", type=int, default=3)
    h.add_argument("--max-bytes", type=int, default=5_000_000)
    a = p.add_argument_group("active mode (authorised engagements only)")
    a.add_argument(
        "--enable-active", action="store_true", help="required, separate confirmation flag for --mode active"
    )
    a.add_argument("--authorization", help="engagement / written-authorization reference")
    a.add_argument("--scope", help="scope file: hosts, *.wildcards, IPs, CIDRs; '!' prefix excludes")
    a.add_argument("--active-base", help="OSIRIS deployment with a configured scanner (default: --base)")
    a.add_argument("--scanner-types", default=",".join(DEFAULT_SCANNER_TYPES))
    a.add_argument("--no-scanner", action="store_true", help="skip OSIRIS /api/scanner jobs")
    a.add_argument("--no-http", action="store_true", help="skip direct HTTP/TLS checks")
    a.add_argument("--active-max-hosts", type=int, default=5)
    a.add_argument("--active-interval", type=float, default=2.0, help="seconds between active requests")
    p.add_argument("-v", "--verbose", action="count", default=1)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--log-format", choices=("text", "json"), default="text")
    return p


def list_endpoints(as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                [{**asdict(e), "key": e.key, "modes": sorted(e.modes)} for e in reg.ENDPOINTS], indent=2, default=list
            )
        )
        return
    for n, e in enumerate(reg.ENDPOINTS, 1):
        print(
            f"{n:02} {e.method:6} {e.path:30} {e.category:16} contact={e.contact:8} "
            f"params={','.join(p.name + ('*' if p.required else '') for p in e.params) or '-'}"
        )
    print(f"Registered operations: {len(reg.ENDPOINTS)} (upstream {reg.UPSTREAM_COMMIT[:7]})")


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    setup_logging(0 if args.quiet else args.verbose, args.log_format)

    if args.list_endpoints:
        list_endpoints(args.json)
        return 0
    if not args.target:
        p.error("--target is required unless --list-endpoints")
    try:
        target = parse_target(args.target)
    except TargetError as exc:
        p.error(str(exc))

    observed = None
    if args.observed_headers:
        observed = Path(args.observed_headers).read_text(encoding="utf-8", errors="replace")

    active_cfg = scope = None
    if args.mode == "active":
        active_cfg = ActiveConfig(
            enabled=args.enable_active,
            authorization=args.authorization,
            scope_path=args.scope,
            allow_private=args.lab_mode,
            scanner_types=tuple(t for t in args.scanner_types.split(",") if t),
            use_scanner=not args.no_scanner,
            use_http=not args.no_http,
            max_hosts=args.active_max_hosts,
            min_interval=args.active_interval,
            dry_run=args.dry_run,
        )
        try:
            scope = validate_active(active_cfg)
            if target.kind not in ("domain", "ipv4", "ipv6"):
                raise ActiveError("active mode target must be a domain or IP address")
            ok, why = scope.ip_allowed(target.value) if target.is_ip else scope.host_allowed(target.value)
            if not ok:
                raise ActiveError(f"target {target.value} is not in scope ({why}); refusing to start")
        except ActiveError as exc:
            log.error("ACTIVE MODE REFUSED: %s", exc)
            return 2
    elif args.enable_active or args.scope or args.authorization:
        log.warning("--enable-active/--scope/--authorization only apply to --mode active; ignored")

    try:
        cfg = ReconConfig(
            mode=args.mode,
            include_global=args.include_global,
            max_depth=args.max_depth,
            max_subdomains=args.max_subdomains,
            max_ips=args.max_ips,
            max_asns=args.max_asns,
            max_cves=args.max_cves,
            allow_private=args.lab_mode,
            strict_passive=args.strict_passive,
            org_name=args.org_name,
            github_user=args.github_user,
            observed_headers=observed,
            observed_headers_name=Path(args.observed_headers).name if args.observed_headers else "",
            dry_run=args.dry_run,
        )
        client = OsirisClient(args.base, timeout=args.timeout, max_retries=args.retries, max_bytes=args.max_bytes)
    except ValueError as exc:
        p.error(str(exc))

    out_dir = Path(args.out_dir) if args.out_dir else Path("reports") / safe_dirname(target.value)
    pipeline = ReconPipeline(client, cfg, target)
    log.info(
        "target=%s kind=%s mode=%s base=%s%s",
        target.value,
        target.kind,
        cfg.mode,
        client.base_url,
        " (dry-run)" if cfg.dry_run else "",
    )
    state = pipeline.run()

    if active_cfg and scope and not state.cancelled:
        run_active(pipeline, active_cfg, scope, args, out_dir)

    state = pipeline.finish()
    report = build_report(state, client.base_url)
    written = write_reports(report, out_dir, tuple(f.strip() for f in args.formats.split(",") if f.strip()))
    print(
        json.dumps(
            {
                "target": target.value,
                "mode": cfg.mode,
                "dry_run": cfg.dry_run,
                "endpoint_status": report["summary"]["endpoint_status"],
                "findings_by_severity": report["summary"]["findings_by_severity"],
                "assets": report["summary"]["assets"],
                "reports": written,
            },
            indent=2,
        )
    )
    return 130 if state.cancelled else 0


def run_active(pipeline: ReconPipeline, acfg: ActiveConfig, scope, args, out_dir: Path) -> None:
    state, target = pipeline.state, pipeline.target
    audit = AuditLog(None if acfg.dry_run else out_dir / "active_audit.jsonl", acfg.authorization or "")
    scanner_client = None
    if acfg.use_scanner:
        scanner_client = OsirisClient(
            args.active_base or args.base,
            timeout=max(args.timeout, 95.0),
            max_retries=0,
            max_bytes=args.max_bytes,
            active_enabled=True,
            budget=pipeline.client.budget,
        )
    runner = ActiveRunner(acfg, scope, audit, client=scanner_client)
    discovered = [a.value for a in pipeline.inv.hosts(relations=(TARGET, FIRST_PARTY)) if a.value != target.value]
    runner.plan(target.value, discovered)
    log.warning(
        "ACTIVE stage: authorization=%s scope=%s actions=%d%s",
        acfg.authorization,
        scope.source,
        len(runner.actions),
        " (dry-run, nothing sent)" if acfg.dry_run else "",
    )
    runner.execute()
    for obs in runner.finalize_observations():
        state.findings.extend(analyze(obs, pipeline.cfg.today))
        for t in detect_technologies(obs):
            if t not in state.technologies:
                state.technologies.append(t)
        state.http_observations.append(observation_record(obs))
    ep = reg.get("/api/scanner")
    ex = pipeline.tracker.execs[ep.key]
    if scanner_client:
        ex.calls.extend(c for c in scanner_client.calls if c.endpoint == ep.key)
    if not ex.calls:
        if acfg.dry_run:
            ex.status, ex.reason = PLANNED, f"Would run scan types {', '.join(acfg.scanner_types)} on in-scope hosts."
        elif not acfg.use_scanner:
            ex.status, ex.reason = SKIPPED, "--no-scanner"
        else:
            ex.status, ex.reason = SKIPPED, "No in-scope host passed the pre-request scope check."
    elif all(c.status == "unavailable" for c in ex.calls):
        ex.status, ex.reason = (
            UNAVAILABLE,
            (
                "Scanner backend not configured on this deployment "
                "(SCANNER_URL/SCANNER_KEY); use --active-base with a self-hosted instance."
            ),
        )
    state.active = {
        "authorization": acfg.authorization,
        "scope": scope.to_dict(),
        "audit_log": str(audit.path) if audit.path else None,
        "dry_run": acfg.dry_run,
        "cancelled": runner.cancelled,
        "summary": runner.summary(),
        "actions": [asdict(a) for a in runner.actions],
        "safeguards": [
            "scope check before every request and redirect hop",
            "private/link-local/loopback targets blocked unless --lab-mode",
            f"min {acfg.min_interval}s between requests, sequential (concurrency 1)",
            "no brute force, credential attacks, DoS testing or exploitation",
            "scanner type 'vuln' refused",
        ],
    }
    if runner.cancelled:
        state.cancelled = True


if __name__ == "__main__":
    sys.exit(main())
