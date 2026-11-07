from conftest import CERTS, DNS_ROOT, DNS_WWW

from osiris.discovery import AssetInventory, parse_certs, parse_dns
from osiris.models import FIRST_PARTY, HOSTING, TARGET, THIRD_PARTY


def test_parse_dns_minimal_summary_structure():
    # Exactly the structure observed in the field: only summary.ip_addresses.
    parsed = parse_dns({"domain": "example.org", "summary": {"ip_addresses": ["93.184.215.14"]}})
    assert parsed.ipv4 == ["93.184.215.14"]
    assert parsed.ipv6 == []


def test_parse_dns_full_response():
    p = parse_dns(DNS_ROOT)
    assert p.ipv4 == ["93.184.215.14"]
    assert p.ipv6 == ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"]
    assert p.mx == ["mx1.mailhost.example.net", "mail.example.com"]
    assert p.ns == ["a.iana-servers.net"]
    assert p.spf_ips == ["198.51.100.7"]
    assert p.spf_includes == ["spf.mailhost.example.net"]


def test_parse_dns_cname_inside_a_bucket_is_not_an_ip():
    p = parse_dns(DNS_WWW)
    assert p.ipv4 == ["93.184.215.20"]
    assert p.cnames == ["cdn.example.com"]


def test_parse_dns_tolerates_unexpected_schema():
    p = parse_dns({"records": "garbage", "summary": {"ip_addresses": [None, 5, "999.1.1.1", "1.1.1.1"]}})
    assert p.ipv4 == ["1.1.1.1"]
    assert parse_dns({}).ipv4 == []


def test_parse_dns_deduplicates():
    payload = {
        "records": {"A": [{"type": 1, "data": "1.1.1.1"}, {"type": 1, "data": "1.1.1.1"}]},
        "summary": {"ip_addresses": ["1.1.1.1"]},
    }
    assert parse_dns(payload).ipv4 == ["1.1.1.1"]


def test_parse_certs_scope_boundary():
    ct = parse_certs(CERTS, "example.com")
    assert "www.example.com" in ct.subdomains
    assert "api.example.com" in ct.subdomains
    assert "evilexample.com" not in ct.subdomains
    assert "evilexample.com" in ct.rejected
    assert all("@" not in s for s in ct.subdomains)
    assert ct.subdomains.count("www.example.com") == 1


def test_parse_certs_degraded_response():
    ct = parse_certs({"domain": "example.com", "certificates": [], "error": "crt.sh unavailable"}, "example.com")
    assert ct.subdomains == [] and ct.error == "crt.sh unavailable"


def test_inventory_dedup_relation_and_private_exclusion():
    inv = AssetInventory("example.com")
    inv.add("example.com", "domain", TARGET, "input")
    inv.add_ip("93.184.215.14", HOSTING, "dns:C1", "example.com", 1)
    inv.add_ip("93.184.215.14", HOSTING, "dns:C2", "www.example.com", 2)
    inv.add_ip("10.0.0.5", HOSTING, "dns:C3", "intranet.example.com", 2)
    inv.add_ip("127.0.0.1", HOSTING, "dns:C4", "lo.example.com", 2)
    assert [a.value for a in inv.ips()] == ["93.184.215.14"]
    a = inv.get("ipv4", "93.184.215.14")
    assert a.sources == ["dns:C1", "dns:C2"] and a.depth == 1
    assert "excluded" in inv.get("ipv4", "10.0.0.5").notes[0]
    assert inv.relation_for_host("www.example.com") == FIRST_PARTY
    assert inv.relation_for_host("mail.provider.net") == THIRD_PARTY
    lab = AssetInventory("example.com", allow_private=True)
    lab.add_ip("10.0.0.5", HOSTING, "dns", None, 1)
    assert [a.value for a in lab.ips()] == ["10.0.0.5"]


def test_inventory_ipv6_and_timestamps():
    inv = AssetInventory(None)
    a = inv.add_ip("2001:4860:4860::8888", TARGET, "input", None, 0)
    assert a.kind == "ipv6" and a.first_seen
