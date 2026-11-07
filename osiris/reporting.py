"""Report generation: JSON, HTML, Markdown, CSV asset inventory, endpoint summary."""

from __future__ import annotations

import csv
import html
import json
import re
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import USER_AGENT, __version__
from .enrichment import ScanState
from .models import ENDPOINT_STATUSES, SEVERITIES
from .registry import UPSTREAM_COMMIT, UPSTREAM_REPO

DISCLAIMER = (
    "Independent community tool using the public OSIRIS API (osirisai.live); not an official OSIRIS product. "
    "API lookups succeeding or returning no data is not proof that a target is secure or vulnerable. Findings "
    "marked 'unverified' rest on third-party data and must be confirmed before action."
)


def safe_dirname(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return name[:100] or "target"


def build_report(state: ScanState, base_url: str) -> dict[str, Any]:
    endpoints = [e.to_dict() for e in state.endpoints]
    status_counts = Counter(e["status"] for e in endpoints)
    sev_counts = Counter(f.severity for f in state.findings)
    assets = state.inventory.to_list() if state.inventory else []
    cfg = asdict(state.config)
    cfg.pop("observed_headers", None)
    cfg["today"] = str(cfg.get("today")) if cfg.get("today") else None
    return {
        "tool": {
            "name": "osiris-intelligence-recon",
            "version": __version__,
            "user_agent": USER_AGENT,
            "upstream": UPSTREAM_REPO,
            "upstream_commit_reviewed": UPSTREAM_COMMIT,
            "disclaimer": DISCLAIMER,
        },
        "target": {"input": state.target.raw, "kind": state.target.kind, "value": state.target.value},
        "mode": state.config.mode,
        "osiris_base_url": base_url,
        "started_at": state.started_at,
        "completed_at": state.completed_at,
        "cancelled": state.cancelled,
        "config": cfg,
        "summary": {
            "registered_endpoints": len(endpoints),
            "endpoint_status": {s: status_counts.get(s, 0) for s in ENDPOINT_STATUSES},
            "api_calls": sum(e["call_count"] for e in endpoints),
            "assets": len(assets),
            "assets_by_relation": dict(Counter(a["relation"] for a in assets)),
            "findings": len(state.findings),
            "findings_by_severity": {s: sev_counts.get(s, 0) for s in SEVERITIES},
        },
        "findings": [f.to_dict() for f in state.findings],
        "assets": assets,
        "technologies": state.technologies,
        "http_observations": state.http_observations,
        "intelligence": state.intel,
        "active": state.active,
        "notes": state.notes,
        "endpoints": endpoints,
        "raw_responses": state.raw,
    }


def write_reports(
    report: dict[str, Any], out_dir: Path, formats: tuple[str, ...] = ("json", "html", "md", "csv")
) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    if "json" in formats:
        p = out_dir / "report.json"
        p.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        written["json"] = str(p)
    p = out_dir / "endpoints.json"
    p.write_text(
        json.dumps(
            {"summary": report["summary"]["endpoint_status"], "endpoints": report["endpoints"]},
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )
    written["endpoints"] = str(p)
    if "csv" in formats:
        p = out_dir / "assets.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["value", "kind", "relation", "depth", "parent", "enriched", "first_seen", "sources", "notes"])
            for a in report["assets"]:
                w.writerow(
                    [
                        _csv_safe(a["value"]),
                        a["kind"],
                        a["relation"],
                        a["depth"],
                        _csv_safe(a["parent"] or ""),
                        a["enriched"],
                        a["first_seen"],
                        _csv_safe("; ".join(a["sources"])),
                        _csv_safe("; ".join(a["notes"])),
                    ]
                )
        written["csv"] = str(p)
    if "md" in formats:
        p = out_dir / "report.md"
        p.write_text(render_markdown(report), encoding="utf-8")
        written["md"] = str(p)
    if "html" in formats:
        p = out_dir / "report.html"
        p.write_text(render_html(report), encoding="utf-8")
        written["html"] = str(p)
    return written


def _csv_safe(value: str) -> str:
    """Neutralise spreadsheet formula injection from attacker-influenced values (CT names, banners)."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def _md(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(r: dict[str, Any]) -> str:
    s = r["summary"]
    lines = [
        f"# OSIRIS Recon Report — {_md(r['target']['value'])}",
        "",
        f"> {DISCLAIMER}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Target | `{_md(r['target']['value'])}` ({r['target']['kind']}) |",
        f"| Mode | {r['mode']} |",
        f"| Started | {r['started_at']} |",
        f"| Completed | {r['completed_at']} |",
        f"| OSIRIS base | {r['osiris_base_url']} |",
        f"| API calls | {s['api_calls']} |",
        f"| Assets | {s['assets']} |",
        f"| Findings | {s['findings']} |",
        "",
        "## Endpoint execution",
        "",
        "| Status | Count |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in s["endpoint_status"].items()],
        "",
        "## Findings by severity",
        "",
    ]
    if r.get("cancelled"):
        lines.insert(4, "> **Run was cancelled — results are partial.**\n")
    for sev in SEVERITIES:
        group = [f for f in r["findings"] if f["severity"] == sev]
        if not group:
            continue
        lines += [f"### {sev.title()} ({len(group)})", ""]
        for f in group:
            lines += [
                f"#### {f['id']} — {_md(f['title'])}",
                "",
                f"- **Asset:** `{_md(f['asset'])}`",
                f"- **Observation:** {_md(f['observation'])}",
                f"- **Confidence:** {f['confidence']} · **Verification:** {f['verification']}",
                f"- **Severity justification:** {_md(f['severity_justification'])}",
                f"- **Potential impact:** {_md(f['impact'])}",
                f"- **Remediation:** {_md(f['remediation'])}",
                "- **Evidence:**",
                *[f"  - `{_md(e['source'])}` ref `{_md(e['reference'])}` — {_md(e['excerpt'])}" for e in f["evidence"]],
                "",
            ]
    if not r["findings"]:
        lines += ["No findings were produced. This does not mean the target is secure.", ""]
    lines += [
        "## Asset inventory",
        "",
        "| Asset | Kind | Relation | Depth | Sources | Notes |",
        "|---|---|---|---|---|---|",
    ]
    for a in r["assets"]:
        lines.append(
            f"| `{_md(a['value'])}` | {a['kind']} | {a['relation']} | {a['depth']} | "
            f"{_md(', '.join(a['sources']))} | {_md('; '.join(a['notes']))} |"
        )
    if r.get("notes"):
        lines += ["", "## Notes and limitations", "", *[f"- {_md(n)}" for n in r["notes"]]]
    if r.get("active"):
        act = r["active"]
        lines += [
            "",
            "## Active stage",
            "",
            f"- Authorization: `{_md(act.get('authorization'))}`",
            f"- Scope file: `{_md(act.get('scope', {}).get('source'))}`",
            f"- Audit log: `{_md(act.get('audit_log'))}`",
            f"- Summary: {act.get('summary')}",
            "",
            "| Kind | Host | Detail | Status | Reason |",
            "|---|---|---|---|---|",
            *[
                f"| {a['kind']} | `{_md(a['host'])}` | {_md(a['detail'])} | {a['status']} | {_md(a['reason'])} |"
                for a in act.get("actions", [])
            ],
        ]
    lines += ["", "## Endpoint details", "", "| Endpoint | Status | Calls | Explanation |", "|---|---|---|---|"]
    for e in r["endpoints"]:
        lines.append(f"| `{e['key']}` | {e['status']} | {e['call_count']} | {_md(e['reason'])} |")
    return "\n".join(lines) + "\n"


_SEV_COLOR = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#c2410c",
    "low": "#a16207",
    "informational": "#475569",
}
_STATUS_COLOR = {
    "executed": "#15803d",
    "failed": "#b91c1c",
    "unavailable": "#c2410c",
    "incompatible": "#64748b",
    "skipped": "#64748b",
    "planned": "#1d4ed8",
}


def render_html(r: dict[str, Any]) -> str:
    e = html.escape
    s = r["summary"]
    parts = [
        f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>OSIRIS Recon — {e(r["target"]["value"])}</title>
<style>
:root{{--bg:#f8fafc;--fg:#0f172a;--card:#fff;--muted:#64748b;--line:#e2e8f0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0b1120;--fg:#e2e8f0;--card:#111827;--muted:#94a3b8;--line:#1f2937}}}}
body{{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:16px;max-width:1200px;margin:auto}}
h1{{font-size:22px}} h2{{margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:4px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:10px 0}}
.badge{{display:inline-block;color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;font-weight:600}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border-bottom:1px solid var(--line);padding:5px 6px;text-align:left;vertical-align:top}}
code{{font-size:12px;word-break:break-all}} .muted{{color:var(--muted)}} .grid{{display:flex;flex-wrap:wrap;gap:10px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 14px;min-width:110px}}
.stat b{{display:block;font-size:20px}} .wrap{{overflow-x:auto}}
</style></head><body>
<h1>OSIRIS Recon Report — <code>{e(r["target"]["value"])}</code></h1>
<p class="muted">{e(DISCLAIMER)}</p>
<div class="grid">
<div class="stat">Mode<b>{e(r["mode"])}</b></div>
<div class="stat">API calls<b>{s["api_calls"]}</b></div>
<div class="stat">Assets<b>{s["assets"]}</b></div>
<div class="stat">Findings<b>{s["findings"]}</b></div>
</div>
<p class="muted">Started {e(str(r["started_at"]))} · Completed {e(str(r["completed_at"]))} · Base {e(r["osiris_base_url"])}
{" · <b>CANCELLED – partial results</b>" if r.get("cancelled") else ""}</p>
<h2>Endpoint execution summary</h2><div class="grid">"""
    ]
    for k, v in s["endpoint_status"].items():
        parts.append(f'<div class="stat">{e(k)}<b style="color:{_STATUS_COLOR.get(k, "inherit")}">{v}</b></div>')
    parts.append("</div><h2>Findings by severity</h2>")
    if not r["findings"]:
        parts.append("<p>No findings were produced. This does not mean the target is secure.</p>")
    for f in r["findings"]:
        ev = "".join(
            f"<li><code>{e(x['source'])}</code> ref <code>{e(x['reference'])}</code> — {e(x['excerpt'])}</li>"
            for x in f["evidence"]
        )
        parts.append(f"""<div class="card"><span class="badge" style="background:{_SEV_COLOR.get(f["severity"], "#475569")}">{e(f["severity"].upper())}</span>
<b> {e(f["id"])} — {e(f["title"])}</b><br><span class="muted">Asset</span> <code>{e(f["asset"])}</code> ·
<span class="muted">Confidence</span> {e(f["confidence"])} · <span class="muted">Verification</span> {e(f["verification"])}
<p>{e(f["observation"])}</p><p><b>Impact:</b> {e(f["impact"])}</p>
<p><b>Severity justification:</b> {e(f["severity_justification"])}</p>
<p><b>Remediation:</b> {e(f["remediation"])}</p><b>Evidence</b><ul>{ev}</ul></div>""")
    parts.append(
        '<h2>Asset inventory</h2><div class="wrap"><table><tr><th>Asset</th><th>Kind</th><th>Relation</th>'
        "<th>Depth</th><th>Sources</th><th>First seen</th><th>Notes</th></tr>"
    )
    for a in r["assets"]:
        parts.append(
            f"<tr><td><code>{e(a['value'])}</code></td><td>{e(a['kind'])}</td><td>{e(a['relation'])}</td>"
            f"<td>{a['depth']}</td><td>{e(', '.join(a['sources']))}</td><td>{e(a['first_seen'])}</td>"
            f"<td>{e('; '.join(a['notes']))}</td></tr>"
        )
    parts.append("</table></div>")
    if r.get("notes"):
        parts.append("<h2>Notes and limitations</h2><ul>" + "".join(f"<li>{e(n)}</li>" for n in r["notes"]) + "</ul>")
    if r.get("active"):
        act = r["active"]
        parts.append(
            f"<h2>Active stage</h2><p>Authorization <code>{e(str(act.get('authorization')))}</code> · "
            f"audit log <code>{e(str(act.get('audit_log')))}</code></p><div class='wrap'><table>"
            "<tr><th>Kind</th><th>Host</th><th>Detail</th><th>Status</th><th>Reason</th></tr>"
        )
        for a in act.get("actions", []):
            parts.append(
                f"<tr><td>{e(a['kind'])}</td><td><code>{e(a['host'])}</code></td><td>{e(a['detail'])}</td>"
                f"<td>{e(a['status'])}</td><td>{e(a['reason'])}</td></tr>"
            )
        parts.append("</table></div>")
    parts.append(
        '<h2>Endpoint details</h2><div class="wrap"><table><tr><th>Endpoint</th><th>Status</th><th>Calls</th>'
        "<th>Explanation</th></tr>"
    )
    for x in r["endpoints"]:
        parts.append(
            f"<tr><td><code>{e(x['key'])}</code></td><td style='color:{_STATUS_COLOR.get(x['status'], 'inherit')}'>"
            f"{e(x['status'])}</td><td>{x['call_count']}</td><td>{e(x['reason'])}</td></tr>"
        )
    parts.append("</table></div></body></html>")
    return "\n".join(parts)
