import csv
import json
from datetime import date

from conftest import make_client, osiris_routes

from osiris.enrichment import ReconConfig, ReconPipeline
from osiris.models import Evidence, Finding
from osiris.reporting import build_report, render_html, safe_dirname, write_reports
from osiris.targets import parse_target


def make_report(mode="intelligence"):
    client, _ = make_client(osiris_routes())
    pipe = ReconPipeline(client, ReconConfig(mode=mode, today=date(2026, 11, 7)), parse_target("example.com"))
    pipe.run()
    pipe.state.findings.append(
        Finding(
            id="",
            title="<script>alert(1)</script>",
            asset='=HYPERLINK("x")',
            observation="<b>x</b>",
            evidence=[Evidence("test", "ref", "<img src=x onerror=alert(1)>")],
            confidence="low",
            impact="i",
            severity="informational",
            severity_justification="j",
            remediation="r",
            verification="unverified",
        )
    )
    pipe.state.inventory.add("=cmd|' /C calc'!A0", "hostname", "third_party", "test")
    return build_report(pipe.finish(), "https://osiris.test")


def test_all_formats_written(tmp_path):
    report = make_report()
    written = write_reports(report, tmp_path)
    assert set(written) == {"json", "endpoints", "csv", "md", "html"}
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["started_at"] and data["completed_at"]
    assert data["summary"]["registered_endpoints"] == 71
    eps = json.loads((tmp_path / "endpoints.json").read_text())
    assert len(eps["endpoints"]) == 71 and all(e["reason"] for e in eps["endpoints"])
    md = (tmp_path / "report.md").read_text()
    assert "## Endpoint execution" in md and "Started" in md and "Remediation" in md
    assert "not proof" in md


def test_findings_grouped_and_ordered_by_severity():
    report = make_report()
    order = ["critical", "high", "medium", "low", "informational"]
    sev = [order.index(f["severity"]) for f in report["findings"]]
    assert sev == sorted(sev)
    assert [f["id"] for f in report["findings"]][:2] == ["OSR-001", "OSR-002"]
    assert all(f["evidence"] for f in report["findings"])


def test_html_escapes_untrusted_values():
    html = render_html(make_report())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x" not in html


def test_csv_neutralises_formula_injection(tmp_path):
    write_reports(make_report(), tmp_path, ("csv",))
    rows = list(csv.DictReader((tmp_path / "assets.csv").open()))
    evil = [r for r in rows if "cmd" in r["value"]]
    assert evil and evil[0]["value"].startswith("'=")
    assert {"value", "kind", "relation", "first_seen", "sources"} <= set(rows[0])


def test_report_omits_observed_header_text_and_config_secrets():
    client, _ = make_client(osiris_routes())
    pipe = ReconPipeline(client, ReconConfig(observed_headers="set-cookie: s=SECRETVALUE"), parse_target("example.com"))
    pipe.run()
    report = build_report(pipe.finish(), "https://osiris.test")
    assert "SECRETVALUE" not in json.dumps(report)


def test_safe_dirname():
    assert safe_dirname("../../etc/passwd") == "etc_passwd"
    assert safe_dirname("2001:db8::1") == "2001_db8_1"
    assert safe_dirname("") == "target"
