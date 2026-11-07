import json
from typing import Any

import pytest
import requests
from conftest import FakeResponse, make_client

from osiris.active import ActiveConfig, ActiveError, ActiveRunner, AuditLog, HttpResponse, Scope, validate_active
from osiris.cli import main


class FakeTransport:
    def __init__(
        self,
        responses: dict[str, HttpResponse] | None = None,
        tls: dict[str, Any] | None = None,
        raise_on: str | None = None,
        interrupt_on: str | None = None,
    ):
        self.responses = responses or {}
        self.tls = tls or {"protocol": "TLSv1.3", "not_after": "Jan  1 00:00:00 2030 GMT"}
        self.requests: list[str] = []
        self.raise_on = raise_on
        self.interrupt_on = interrupt_on

    def http_get(self, url: str, timeout: float) -> HttpResponse:
        self.requests.append(url)
        if self.interrupt_on and self.interrupt_on in url:
            raise KeyboardInterrupt
        if self.raise_on and self.raise_on in url:
            raise requests.ConnectionError("boom")
        return self.responses.get(url, HttpResponse(200, {"server": ["nginx"]}, None))

    def tls_probe(self, host: str, port: int, timeout: float) -> dict[str, Any]:
        self.requests.append(f"tls://{host}:{port}")
        return self.tls


def resolver(table: dict[str, list[str]]):
    def resolve(host: str) -> list[str]:
        if host not in table:
            raise OSError("NXDOMAIN")
        return table[host]

    return resolve


PUBLIC = {
    "lab.example.com": ["93.184.215.14"],
    "www.lab.example.com": ["93.184.215.14"],
    "other.example.net": ["93.184.215.99"],
    "internal.lab.example.com": ["10.0.0.5"],
}


def runner(scope_text: str, transport=None, client=None, **cfg) -> tuple[ActiveRunner, FakeTransport, AuditLog]:
    t = transport or FakeTransport()
    audit = AuditLog(None, "ENG-001")
    acfg = ActiveConfig(
        enabled=True, authorization="ENG-001", scope_path="x", min_interval=0.5, use_scanner=client is not None, **cfg
    )
    r = ActiveRunner(
        acfg,
        Scope.parse(scope_text),
        audit,
        client=client,
        transport=t,
        resolver=resolver(PUBLIC),
        sleep=lambda s: None,
    )
    return r, t, audit


# ── gates ────────────────────────────────────────────────────────────────
def test_requires_enable_flag(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("lab.example.com\n")
    with pytest.raises(ActiveError, match="--enable-active"):
        validate_active(ActiveConfig(enabled=False, authorization="ENG-001", scope_path=str(scope)))


@pytest.mark.parametrize("auth", [None, "", "x", "bad ref with spaces", "a" * 80])
def test_requires_valid_authorization(tmp_path, auth):
    scope = tmp_path / "scope.txt"
    scope.write_text("lab.example.com\n")
    with pytest.raises(ActiveError, match="authorization"):
        validate_active(ActiveConfig(enabled=True, authorization=auth, scope_path=str(scope)))


def test_requires_scope_file(tmp_path):
    with pytest.raises(ActiveError, match="--scope"):
        validate_active(ActiveConfig(enabled=True, authorization="ENG-001", scope_path=None))
    with pytest.raises(ActiveError, match="not found"):
        validate_active(ActiveConfig(enabled=True, authorization="ENG-001", scope_path=str(tmp_path / "nope")))
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n")
    with pytest.raises(ActiveError, match="no entries"):
        validate_active(ActiveConfig(enabled=True, authorization="ENG-001", scope_path=str(empty)))


def test_refuses_vuln_scanner_type(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("lab.example.com\n")
    with pytest.raises(ActiveError, match="vuln"):
        validate_active(
            ActiveConfig(
                enabled=True, authorization="ENG-001", scope_path=str(scope), scanner_types=("headers", "vuln")
            )
        )


def test_cli_refuses_active_without_flag_before_any_network(tmp_path, monkeypatch, capsys):
    scope = tmp_path / "scope.txt"
    scope.write_text("lab.example.com\n")

    def boom(*a, **k):
        raise AssertionError("network client must not be created")

    monkeypatch.setattr("osiris.cli.OsirisClient", boom)
    assert (
        main(
            [
                "--target",
                "lab.example.com",
                "--mode",
                "active",
                "--scope",
                str(scope),
                "--authorization",
                "ENG-001",
                "-q",
            ]
        )
        == 2
    )
    assert (
        main(
            [
                "--target",
                "other.example.net",
                "--mode",
                "active",
                "--scope",
                str(scope),
                "--authorization",
                "ENG-001",
                "--enable-active",
                "-q",
            ]
        )
        == 2
    )  # target out of scope


# ── scope semantics ──────────────────────────────────────────────────────
def test_scope_parsing_and_matching():
    s = Scope.parse(
        "lab.example.com\n*.lab.example.com\n!admin.lab.example.com\n198.51.100.0/24\n!198.51.100.9\n# comment\n"
    )
    assert s.host_allowed("lab.example.com")[0]
    assert s.host_allowed("www.lab.example.com")[0]
    assert not s.host_allowed("admin.lab.example.com")[0]
    assert not s.host_allowed("evillab.example.com")[0]
    assert not s.host_allowed("example.com")[0]
    assert s.ip_allowed("198.51.100.20")[0]
    assert not s.ip_allowed("198.51.100.9")[0]
    assert not s.ip_allowed("203.0.113.1")[0]
    wildcard_only = Scope.parse("*.lab.example.com")
    assert not wildcard_only.host_allowed("lab.example.com")[0]  # wildcard excludes the apex


def test_scope_rejects_bad_lines():
    with pytest.raises(ActiveError, match="line 2"):
        Scope.parse("lab.example.com\nnot a host!\n")


# ── enforcement ──────────────────────────────────────────────────────────
def test_out_of_scope_hosts_never_contacted():
    r, t, audit = runner("lab.example.com\n")
    r.plan("lab.example.com", ["other.example.net", "www.lab.example.com"])
    r.execute()
    assert all("other.example.net" not in u and "www.lab.example.com" not in u for u in t.requests)
    rejected = [a for a in r.actions if a.status == "out_of_scope"]
    assert {a.host for a in rejected} == {"other.example.net", "www.lab.example.com"}
    assert any(e["event"] == "scope_reject" for e in audit.entries)


def test_scope_check_runs_again_before_each_request():
    r, t, _ = runner("lab.example.com\n")
    r.plan("lab.example.com", [])
    r.scope = Scope.parse("unrelated.example.org\n")  # scope changes after planning
    r.execute()
    assert t.requests == []
    assert all(a.status == "blocked" for a in r.actions)


def test_hostname_resolving_to_private_address_blocked_unless_lab():
    r, t, _ = runner("*.lab.example.com\n")
    r.plan("internal.lab.example.com", [])
    r.execute()
    assert t.requests == []
    assert "private" in r.actions[0].reason
    r, t, _ = runner("*.lab.example.com\n", allow_private=True)
    r.plan("internal.lab.example.com", [])
    r.execute()
    assert "https://internal.lab.example.com/" in t.requests


def test_redirect_to_out_of_scope_host_not_followed():
    t = FakeTransport(
        {
            "https://lab.example.com/": HttpResponse(
                302, {"location": ["https://other.example.net/"]}, "https://other.example.net/"
            )
        }
    )
    r, t, audit = runner("lab.example.com\n", transport=t)
    r.plan("lab.example.com", [])
    r.execute()
    assert "https://other.example.net/" not in t.requests
    assert any(e["event"] == "redirect_check" and not e["allowed"] for e in audit.entries)


def test_http_to_https_detection_and_observations():
    t = FakeTransport(
        {
            "http://lab.example.com/": HttpResponse(301, {}, "https://lab.example.com/"),
            "https://lab.example.com/": HttpResponse(200, {"server": ["Apache"], "x-powered-by": ["PHP/8.1.34"]}, None),
        }
    )
    r, t, _ = runner("lab.example.com\n", transport=t)
    r.plan("lab.example.com", [])
    r.execute()
    obs = r.finalize_observations()
    assert len(obs) == 1 and obs[0].http_to_https is True and obs[0].tls["protocol"] == "TLSv1.3"
    assert obs[0].source == "active-http"


def test_dry_run_sends_nothing():
    r, t, audit = runner("lab.example.com\n", dry_run=True)
    r.plan("lab.example.com", [])
    r.execute()
    assert t.requests == []
    assert {a.status for a in r.actions} == {"dry_run"}


def test_cancellation_stops_safely():
    t = FakeTransport(interrupt_on="http://")
    r, t, audit = runner("lab.example.com\n", transport=t)
    r.plan("lab.example.com", [])
    r.execute()
    assert r.cancelled
    assert "tls://lab.example.com:443" not in t.requests
    assert any(a.status == "cancelled" for a in r.actions)
    assert audit.entries[-1]["event"] == "active_end"


def test_max_hosts_and_rate_limit_pacing():
    sleeps: list[float] = []
    t = FakeTransport()
    audit = AuditLog(None, "ENG-001")
    clock = [0.0]
    acfg = ActiveConfig(
        enabled=True, authorization="ENG-001", scope_path="x", min_interval=2.0, max_hosts=1, use_scanner=False
    )
    r = ActiveRunner(
        acfg,
        Scope.parse("*.lab.example.com\nlab.example.com"),
        audit,
        transport=t,
        resolver=resolver(PUBLIC),
        sleep=lambda s: (sleeps.append(s), clock.__setitem__(0, clock[0] + s)),
        clock=lambda: clock[0],
    )
    r.plan("lab.example.com", ["www.lab.example.com"])
    r.execute()
    assert any(a.status == "skipped" and a.host == "www.lab.example.com" for a in r.actions)
    assert len(sleeps) >= 2 and all(s <= 2.0 for s in sleeps)


def test_scanner_uses_osiris_api_only_for_in_scope_hosts():
    client, session = make_client(
        {"/api/scanner": FakeResponse(503, {"error": "Scanner not configured"})}, active_enabled=True
    )
    r, t, _ = runner("lab.example.com\n", client=client, scanner_types=("headers",), use_http=False)
    r.plan("lab.example.com", ["other.example.net"])
    r.execute()
    assert session.calls_to("/api/scanner") == [{"target": "lab.example.com", "type": "headers"}]
    assert [a.status for a in r.actions if a.kind == "scanner"] == ["unavailable"]


def test_audit_log_written(tmp_path):
    log = tmp_path / "audit.jsonl"
    audit = AuditLog(log, "ENG-001")
    r = ActiveRunner(
        ActiveConfig(enabled=True, authorization="ENG-001", scope_path="x", use_scanner=False),
        Scope.parse("lab.example.com"),
        audit,
        transport=FakeTransport(),
        resolver=resolver(PUBLIC),
        sleep=lambda s: None,
    )
    r.plan("lab.example.com", [])
    r.execute()
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert lines[0]["event"] == "active_start" and all(x["authorization"] == "ENG-001" for x in lines)
    assert any(x["event"] == "request" for x in lines)


def test_scanner_waits_for_shared_window_and_has_own_budget():
    from osiris import registry as reg
    from osiris.api_client import RateBudget

    clock = [100.0]
    slept: list[float] = []

    def sleep(s):
        slept.append(s)
        clock[0] += s

    budget = RateBudget(clock=lambda: clock[0], sleep=sleep)
    for _ in range(10):
        budget.acquire("shared")  # passive stage just made 10 shared-counter calls
    client, session = make_client({"/api/scanner": {"ok": True}}, active_enabled=True)
    client.budget = budget
    r, t, _ = runner("lab.example.com\n", client=client, scanner_types=("headers", "ssl"), use_http=False)
    r.plan("lab.example.com", [])
    r.execute()
    assert slept and slept[0] >= 60.0
    assert len(session.calls_to("/api/scanner")) == 2
    assert reg.get("/api/scanner").rate_bucket == "scanner"
