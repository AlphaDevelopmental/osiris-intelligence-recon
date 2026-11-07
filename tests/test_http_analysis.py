from datetime import date

import pytest

from osiris.http_analysis import (
    OSIRIS_WHOIS_HEADERS,
    HttpObservation,
    analyze,
    detect_technologies,
    parse_raw_headers,
    php_lifecycle,
)

TODAY = date(2026, 11, 7)
OBSERVED = """HTTP/2 200
server: Apache
x-powered-by: PHP/8.1.34
link: <https://example.com/wp-json/>; rel="https://api.w.org/"
content-type: text/html; charset=UTF-8
"""


def obs(text=OBSERVED, source="user-supplied", subset=None, url="https://example.com/"):
    status, headers = parse_raw_headers(text)
    return HttpObservation(url=url, status=status, headers=headers, source=source, reference="t", header_subset=subset)


def by_title(findings):
    return {f.title: f for f in findings}


def test_parse_raw_headers_last_response_wins():
    status, headers = parse_raw_headers("HTTP/1.1 301 Moved\nLocation: https://x/\n\nHTTP/2 200\nServer: nginx\n")
    assert status == 200 and headers == {"server": ["nginx"]}


def test_observed_header_set_findings():
    f = by_title(analyze(obs(), TODAY))
    assert f["Web server software disclosed in Server header"].severity == "informational"  # no version
    assert f["Runtime disclosed in X-Powered-By header"].severity == "low"
    php = f["PHP 8.1 branch is past upstream end-of-life"]
    assert php.severity == "medium" and php.verification == "unverified" and php.confidence == "medium"
    assert "final upstream release" in php.observation and "backport" in php.observation
    assert "php.net" in php.evidence[0].excerpt
    assert f["WordPress REST API advertised"].severity == "informational"
    assert f["HSTS not enabled"].severity == "low"
    for t in ("No Content-Security-Policy", "X-Content-Type-Options not set", "Referrer-Policy not set"):
        assert f[t].severity == "informational"
    # every finding is fully structured
    for x in f.values():
        assert all(
            [
                x.title,
                x.asset,
                x.observation,
                x.evidence,
                x.confidence,
                x.impact,
                x.severity,
                x.severity_justification,
                x.remediation,
                x.verification,
            ]
        )


def test_versioned_server_banner_is_low():
    f = by_title(analyze(obs("HTTP/1.1 200\nServer: Apache/2.4.41 (Ubuntu)\n"), TODAY))
    assert f["Web server software disclosed in Server header"].severity == "low"


def test_osiris_subset_does_not_invent_missing_headers():
    subset_obs = obs("HTTP/2 200\nserver: Apache\n", source="osiris-whois", subset=OSIRIS_WHOIS_HEADERS)
    subset_obs.headers.pop("link", None)
    titles = {x.title for x in analyze(subset_obs, TODAY)}
    assert "WordPress REST API advertised" not in titles
    assert "HSTS not enabled" in titles  # HSTS *is* in the subset OSIRIS reports
    hsts = next(x for x in analyze(subset_obs, TODAY) if x.title == "HSTS not enabled")
    assert hsts.confidence == "medium" and "HEAD" in hsts.observation


def test_present_headers_not_flagged_and_weak_hsts():
    text = (
        "HTTP/2 200\nstrict-transport-security: max-age=300\ncontent-security-policy: default-src 'self'; "
        "frame-ancestors 'none'\nx-content-type-options: nosniff\nreferrer-policy: no-referrer\n"
    )
    titles = {x.title for x in analyze(obs(text), TODAY)}
    assert "HSTS not enabled" not in titles and "No clickjacking protection header" not in titles
    assert "HSTS max-age below 180 days" in titles


def test_hsts_not_expected_over_plain_http():
    titles = {x.title for x in analyze(obs("HTTP/1.1 200\n", url="http://example.com/"), TODAY)}
    assert "HSTS not enabled" not in titles


def test_cookie_attributes():
    text = "HTTP/2 200\nset-cookie: PHPSESSID=abc123; path=/\nset-cookie: pref=1; Secure; HttpOnly; SameSite=Lax\n"
    findings = analyze(obs(text), TODAY)
    cookie = [x for x in findings if x.category == "cookies"]
    assert len(cookie) == 1
    c = cookie[0]
    assert "PHPSESSID" in c.title and c.severity == "low"
    assert "abc123" not in c.evidence[0].excerpt  # cookie value masked


def test_http_redirect_and_tls_findings():
    o = obs("HTTP/2 200\n")
    o.http_to_https = False
    o.tls = {"not_after": "Nov  1 00:00:00 2026 GMT"}
    titles = {x.title for x in analyze(o, TODAY)}
    assert "HTTP does not redirect to HTTPS" in titles and "TLS certificate expired" in titles


@pytest.mark.parametrize(
    "version,state",
    [
        ("8.1.34", "eol"),
        ("7.4.33", "eol"),
        ("5.6.40", "eol"),
        ("8.2.20", "security-only"),
        ("8.3.10", "security-only"),
        ("8.4.1", "active"),
        ("8.5.0", "active"),
        ("9.0.0", "unknown"),
    ],
)
def test_php_lifecycle(version, state):
    assert php_lifecycle(version, TODAY)["state"] == state


def test_supported_php_produces_no_eol_finding():
    titles = {x.title for x in analyze(obs("HTTP/2 200\nx-powered-by: PHP/8.4.1\n"), TODAY)}
    assert not any("end-of-life" in t for t in titles)


def test_detect_technologies():
    techs = detect_technologies(obs())
    products = {t["product"] for t in techs}
    assert {"Apache", "PHP", "WordPress"} <= products
