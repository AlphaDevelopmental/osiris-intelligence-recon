import ipaddress

import pytest

from osiris.targets import TargetError, enrichable_ip, in_domain, normalize_hostname, parse_ip, parse_target


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  sub.Example.com  ", "sub.example.com"),
        ("*.example.com", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_domain_normalization(raw, expected):
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw", ["", "localhost", "-bad.example.com", "a..example.com", "exa mple.com", "x" * 64 + ".com", "1.2.3"]
)
def test_invalid_hostnames(raw):
    with pytest.raises(TargetError):
        normalize_hostname(raw)


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("https://Example.com:8443/path?q=1", "domain", "example.com"),
        ("http://www.example.com", "domain", "www.example.com"),
        ("example.com:443", "domain", "example.com"),
        ("https://[2001:db8::1]:443/", "ipv6", "2001:db8::1"),
        ("http://93.184.215.14/x", "ipv4", "93.184.215.14"),
    ],
)
def test_url_normalization(raw, kind, value):
    t = parse_target(raw)
    assert (t.kind, t.value) == (kind, value)


def test_url_rejects_other_schemes():
    with pytest.raises(TargetError):
        parse_target("ftp://example.com/")


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("8.8.8.8", "ipv4", "8.8.8.8"),
        ("2001:4860:4860::8888", "ipv6", "2001:4860:4860::8888"),
        ("[2001:4860:4860:0:0:0:0:8888]", "ipv6", "2001:4860:4860::8888"),
        ("::ffff:8.8.8.8", "ipv4", "8.8.8.8"),
        ("fe80::1%eth0", "ipv6", "fe80::1"),
        ("cve-2021-44228", "cve", "CVE-2021-44228"),
        ("as15169", "asn", "AS15169"),
        ("User@Example.COM", "email", "User@example.com"),
        ("+442071234567", "phone", "+442071234567"),
        ("00-1A-2B-3C-4D-5E", "mac", "00:1a:2b:3c:4d:5e"),
    ],
)
def test_target_classification(raw, kind, value):
    t = parse_target(raw)
    assert (t.kind, t.value) == (kind, value)


def test_ipv4_ipv6_parsing():
    assert parse_ip("not-an-ip") is None
    assert parse_ip("1.2.3.4").version == 4
    assert parse_ip("[::1]").version == 6


@pytest.mark.parametrize(
    "ip,public_ok,lab_ok",
    [
        ("8.8.8.8", True, True),
        ("2001:4860:4860::8888", True, True),
        ("127.0.0.1", False, False),  # loopback
        ("::1", False, False),
        ("169.254.169.254", False, False),  # link-local / cloud metadata
        ("fe80::1", False, False),
        ("224.0.0.1", False, False),  # multicast
        ("ff02::1", False, False),
        ("0.0.0.0", False, False),
        ("10.1.2.3", False, True),  # RFC1918 only in lab mode
        ("192.168.1.1", False, True),
        ("fd00::1", False, True),  # ULA
        ("192.0.2.1", False, True),  # documentation (is_private in Python) — never public
        ("100.64.0.1", False, False),  # CGNAT: not global, not private
        ("240.0.0.1", False, False),  # reserved
    ],
)
def test_enrichable_ip(ip, public_ok, lab_ok):
    addr = ipaddress.ip_address(ip)
    assert enrichable_ip(addr, allow_private=False)[0] is public_ok
    assert enrichable_ip(addr, allow_private=True)[0] is lab_ok


def test_in_domain_label_boundary():
    assert in_domain("a.example.com", "example.com")
    assert in_domain("example.com.", "example.com")
    assert not in_domain("evilexample.com", "example.com")
    assert not in_domain("example.com.evil.net", "example.com")
