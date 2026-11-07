from datetime import date

from conftest import make_client, osiris_routes

from osiris.enrichment import ReconConfig, ReconPipeline
from osiris.models import ENDPOINT_STATUSES, HOSTING, THIRD_PARTY
from osiris.targets import parse_target


def run(target: str, routes=None, **cfg):
    client, session = make_client(routes or osiris_routes())
    pipe = ReconPipeline(client, ReconConfig(today=date(2026, 11, 7), **cfg), parse_target(target))
    pipe.run()
    return pipe.finish(), session, pipe


def statuses(state):
    return {e.key: e.status for e in state.endpoints}


def test_dns_ips_flow_into_ip_intelligence():
    state, session, pipe = run("example.com")
    ip_calls = {p["ip"] for p in session.calls_to("/api/osint/ip")}
    assert "93.184.215.14" in ip_calls  # from the root A record
    assert "2606:2800:21f:cb07:6820:80da:af6b:8b2c" in ip_calls  # IPv6 too
    assert "93.184.215.20" in ip_calls  # from a CT-discovered subdomain
    assert {p["ip"] for p in session.calls_to("/api/osint/shodan")} == ip_calls
    assert {p["query"] for p in session.calls_to("/api/osint/bgp")} >= {"93.184.215.14", "AS64500"}
    # IPv6 is never sent to the IPv4-only BGP route
    assert not any(":" in p["query"] and not p["query"].startswith("AS") for p in session.calls_to("/api/osint/bgp"))
    a = pipe.inv.get("ipv4", "93.184.215.14")
    assert a.relation == HOSTING and a.enriched and a.sources[0].startswith("dns:C")


def test_private_and_out_of_scope_assets_not_enriched():
    state, session, pipe = run("example.com")
    assert "10.1.2.3" not in {p["ip"] for p in session.calls_to("/api/osint/ip")}
    resolved = {p["domain"] for p in session.calls_to("/api/osint/dns")}
    assert "evilexample.com" not in resolved
    assert "mx1.mailhost.example.net" not in resolved  # third-party MX recorded, not resolved
    assert "a.iana-servers.net" not in resolved
    assert "mail.example.com" in resolved  # first-party MX is resolved
    assert pipe.inv.get("mail_host", "mx1.mailhost.example.net").relation == THIRD_PARTY
    assert "198.51.100.7" not in {p["ip"] for p in session.calls_to("/api/osint/ip")}  # SPF reference only


def test_lab_mode_allows_private_addresses():
    state, session, _ = run("example.com", allow_private=True)
    assert "10.1.2.3" in {p["ip"] for p in session.calls_to("/api/osint/ip")}


def test_discovery_limits_are_enforced():
    state, session, _ = run("example.com", max_subdomains=1, max_ips=1)
    assert len(session.calls_to("/api/osint/dns")) == 2  # root + 1
    assert len(session.calls_to("/api/osint/ip")) == 1
    assert any("discovery limits" in n for n in state.notes)
    assert any("--max-ips" in n for n in state.notes)


def test_max_depth_zero_disables_ct():
    state, session, _ = run("example.com", max_depth=0)
    assert session.calls_to("/api/osint/certs") == []
    assert statuses(state)["GET /api/osint/certs"] == "skipped"


def test_every_endpoint_reported_with_reason():
    for mode in ("recon", "intelligence", "all"):
        state, _, _ = run("example.com", mode=mode)
        assert len(state.endpoints) == 71
        for e in state.endpoints:
            assert e.status in ENDPOINT_STATUSES and e.reason, (mode, e.key)


def test_recon_mode_endpoint_selection():
    s = statuses(run("example.com", mode="recon")[0])
    for k in (
        "GET /api/osint/dns",
        "GET /api/osint/certs",
        "GET /api/osint/whois",
        "GET /api/osint/ip",
        "GET /api/osint/shodan",
        "GET /api/osint/bgp",
    ):
        assert s[k] == "executed", k
    assert s["GET /api/osint/hudsonrock"] == "skipped"
    assert s["GET /api/scanner"] == "skipped"
    assert s["GET /api/flights"] == "skipped"
    assert s["GET /api/sentinel"] == "incompatible"


def test_intelligence_mode_uses_correct_hudsonrock_params_and_correlates():
    state, session, pipe = run("example.com", mode="intelligence")
    assert session.calls_to("/api/osint/hudsonrock") == [{"query": "example.com", "type": "domain"}]
    assert {"query": "example.com"} in session.calls_to("/api/osint/threats")
    titles = {f.title for f in state.findings}
    assert "Target address listed in a malware C2 feed" in titles  # 93.184.215.20 in feed fixture
    assert "Infostealer infections associated with the domain (Hudson Rock)" in titles
    hr = next(f for f in state.findings if "Hudson Rock" in f.title)
    assert "reports 4 " in hr.observation and "37218725" not in hr.observation + hr.evidence[0].excerpt
    assert "https://portal.example.com" in hr.observation and hr.severity == "high"
    assert state.intel["hudsonrock"]["total"] == 4
    portal = pipe.inv.get("hostname", "portal.example.com")
    assert portal.sources[0].startswith("hudsonrock:") and portal.enriched
    # late-found host is resolved and its address enriched like any other subdomain
    assert {"domain": "portal.example.com"} in session.calls_to("/api/osint/dns")
    assert "93.184.215.30" in {p["ip"] for p in session.calls_to("/api/osint/ip")}
    assert pipe.inv.get("ipv4", "93.184.215.30").parent == "portal.example.com"
    assert pipe.inv.get("hostname", "sso.thirdparty.example.net") is None  # out-of-domain URL not added
    c2 = next(f for f in state.findings if "C2" in f.title)
    assert c2.asset == "93.184.215.20" and c2.verification == "unverified"
    assert "203.0.113.200" not in {f.asset for f in state.findings}
    cves = {p["cve"] for p in session.calls_to("/api/osint/cve")}
    assert "CVE-2021-44228" in cves
    idx = next(f for f in state.findings if f.title.startswith("Index associates"))
    assert idx.severity == "medium" and "KEV" in idx.severity_justification


def cdn_routes():
    """portal.example.com sits behind Cloudflare: one IPv4 (ASN-detectable) and one IPv6 (no ASN data)."""
    from conftest import IP_INFO

    routes = osiris_routes()
    base_dns = routes["/api/osint/dns"]
    edge4, edge6 = "104.16.0.1", "2606:4700::6810:1"

    def dns(p):
        if p.get("domain") == "portal.example.com":
            return {"domain": "portal.example.com", "summary": {"ip_addresses": [edge4, edge6]}}
        return base_dns(p)

    def ip(p):
        if p["ip"] == edge4:
            return {**IP_INFO, "ip": edge4, "geo": {**IP_INFO["geo"], "as_number": "AS13335 Cloudflare, Inc."}}
        if p["ip"] == edge6:
            return {**IP_INFO, "ip": edge6, "geo": {"country": "United States"}}
        return {**IP_INFO, "ip": p["ip"]}

    def bgp(p):
        if p.get("query") == edge4:
            return {"query": edge4, "type": "ip", "ip": {"asn": {"asn": 13335, "name": "Cloudflare, Inc."}}}
        return routes_bgp(p)

    routes_bgp = routes["/api/osint/bgp"]
    routes.update({"/api/osint/dns": dns, "/api/osint/ip": ip, "/api/osint/bgp": bgp})
    return routes, edge4, edge6


def test_cdn_edge_addresses_are_not_attributed_to_the_target():
    routes, edge4, edge6 = cdn_routes()
    state, session, pipe = run("example.com", routes=routes, mode="intelligence")
    # both edge addresses were still looked up
    assert {edge4, edge6} <= {p["ip"] for p in session.calls_to("/api/osint/ip")}
    assert pipe.cdn_edges[edge4]["detected_by"] == "ASN"
    assert pipe.cdn_edges[edge6]["detected_by"].startswith("inferred from a sibling address")
    assert pipe.cdn_edges[edge4]["otx_pulses"] == 2
    # no OTX or index (open port / CVE) findings for the shared edge
    assert not [f for f in state.findings if f.asset in (edge4, edge6)]
    cdn = [f for f in state.findings if f.title == "Host(s) served through the Cloudflare CDN"]
    assert len(cdn) == 1 and cdn[0].asset == "portal.example.com" and cdn[0].severity == "informational"
    assert f"{edge4}: 2 OTX pulse(s)" in cdn[0].observation
    assert "CDN edge address (Cloudflare" in pipe.inv.get("ipv4", edge4).notes[0]
    assert state.intel["ips"][edge4]["cdn"].startswith("Cloudflare (AS13335")
    # a non-CDN address keeps its normal findings
    assert any(f.asset == "93.184.215.14" and "open threat intelligence" in f.title for f in state.findings)


def test_whois_headers_feed_http_analysis_without_target_contact():
    state, session, _ = run("example.com")
    php = next(f for f in state.findings if "end-of-life" in f.title)
    assert php.severity == "medium" and php.verification == "unverified"
    assert php.evidence[0].source == "osiris-whois"
    assert state.intel["whois"]["osiris_security_score"]["grade"] == "F"
    assert "reference only" in state.intel["whois"]["osiris_security_score_note"]


def test_strict_passive_skips_whois():
    state, session, _ = run("example.com", strict_passive=True)
    assert session.calls_to("/api/osint/whois") == []
    assert statuses(state)["GET /api/osint/whois"] == "skipped"


def test_ip_target_marks_domain_endpoints_incompatible():
    state, session, _ = run("93.184.215.14", mode="intelligence")
    s = statuses(state)
    assert s["GET /api/osint/dns"] == "incompatible"
    assert s["GET /api/osint/ip"] == "executed"
    assert session.calls_to("/api/osint/dns") == []


def test_email_target_never_expands_to_mail_domain():
    state, session, _ = run("someone@example.com", mode="all")
    assert session.calls_to("/api/osint/dns") == []
    assert statuses(state)["GET /api/osint/dns"] == "incompatible"


def test_failed_endpoint_explained():
    routes = osiris_routes()
    from conftest import FakeResponse

    routes["/api/osint/certs"] = FakeResponse(500, {"error": "Lookup failed"})
    client, _ = make_client(routes, max_retries=0)
    pipe = ReconPipeline(client, ReconConfig(), parse_target("example.com"))
    pipe.run()
    state = pipe.finish()
    e = next(x for x in state.endpoints if x.key == "GET /api/osint/certs")
    assert e.status == "failed" and "upstream_error" in e.reason and "Lookup failed" in e.reason


def test_dry_run_sends_nothing():
    client, session = make_client(osiris_routes())
    pipe = ReconPipeline(client, ReconConfig(dry_run=True, mode="intelligence"), parse_target("example.com"))
    pipe.run()
    state = pipe.finish()
    assert session.requests == []
    assert statuses(state)["GET /api/osint/dns"] == "planned"


def test_observed_headers_file(tmp_path):
    raw = (
        "HTTP/2 200\nserver: Apache\nx-powered-by: PHP/8.1.34\n"
        'link: <https://example.com/wp-json/>; rel="https://api.w.org/"\ncontent-type: text/html; charset=UTF-8\n'
    )
    state, _, _ = run("example.com", observed_headers=raw, observed_headers_name="headers.txt")
    user = [f for f in state.findings if any(e.source == "user-supplied" for e in f.evidence)]
    titles = {f.title for f in user}
    assert "WordPress REST API advertised" in titles
    assert "HSTS not enabled" in titles
