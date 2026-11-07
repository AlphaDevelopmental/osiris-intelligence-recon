import pytest

from osiris import registry as reg
from osiris.enrichment import MODES


def test_registry_has_71_unique_operations():
    assert len(reg.ENDPOINTS) == 71
    assert len({e.key for e in reg.ENDPOINTS}) == 71


@pytest.mark.parametrize(
    "path,params",
    [
        ("/api/osint/hudsonrock", {"query", "type"}),
        ("/api/osint/bgp", {"query"}),
        ("/api/osint/threats", {"query"}),
        ("/api/osint/cve", {"cve"}),
        ("/api/osint/github", {"user"}),
        ("/api/osint/phone", {"number"}),
        ("/api/osint/portscan", {"target"}),
        ("/api/osint/sweep", {"ip", "cidr"}),
        ("/api/entity/expand", {"type", "id"}),
        ("/api/scanner", {"target", "type"}),
    ],
)
def test_parameters_match_upstream_handlers(path, params):
    assert {p.name for p in reg.get(path).params} == params


def test_only_scanner_is_active_contact():
    assert [e.path for e in reg.ENDPOINTS if e.contact == reg.ACTIVE_CONTACT] == ["/api/scanner"]
    assert reg.get("/api/osint/whois").contact == reg.INDIRECT


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("include_global", [False, True])
def test_every_endpoint_has_a_disposition(mode, include_global):
    for ep in reg.ENDPOINTS:
        disp = reg.default_disposition(ep, mode, include_global)
        if disp is not None:
            status, reason = disp
            assert status in ("skipped", "incompatible") and reason


def test_streams_and_writes_never_selected():
    for ep in reg.ENDPOINTS:
        if ep.category in (reg.STREAM, reg.STATEFUL, reg.AI, reg.CALLER, reg.CONTEXT):
            for mode in MODES:
                assert reg.default_disposition(ep, mode, True) is not None


def test_scanner_only_in_active_mode():
    sc = reg.get("/api/scanner")
    assert reg.default_disposition(sc, "active", False) is None
    for mode in ("recon", "intelligence", "all"):
        assert reg.default_disposition(sc, mode, True)[0] == "skipped"
