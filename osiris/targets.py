"""Target parsing, normalisation and address classification."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_ASN = re.compile(r"^AS(\d{1,10})$", re.I)
_EMAIL = re.compile(r"^[^@\s]+@([^@\s]+)$")
_PHONE = re.compile(r"^\+\d{7,15}$")
_MAC = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)


class TargetError(ValueError):
    """Raised for input that cannot be normalised into a supported target."""


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str  # domain | ipv4 | ipv6 | email | cve | asn | phone | mac
    value: str

    @property
    def is_ip(self) -> bool:
        return self.kind in ("ipv4", "ipv6")

    @property
    def domain(self) -> str | None:
        if self.kind == "domain":
            return self.value
        if self.kind == "email":
            return self.value.split("@", 1)[1]
        return None


def normalize_hostname(value: str) -> str:
    """Lower-case, strip a trailing dot and IDNA-encode; raise TargetError if invalid."""
    host = value.strip().rstrip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    if not host or len(host) > 253:
        raise TargetError(f"invalid hostname: {value!r}")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError(f"invalid hostname: {value!r}") from exc
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise TargetError(f"invalid hostname: {value!r}")
    if labels[-1].isdigit():
        raise TargetError(f"invalid hostname: {value!r}")
    return host


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP literal (brackets and IPv6 zone ids tolerated); None if not an IP."""
    v = value.strip().strip("[]")
    if "%" in v:
        v = v.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable unicast addresses."""
    return bool(
        ip.is_global
        and not ip.is_multicast
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def ip_category(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    if not ip.is_global:
        return "non-global"
    return "public"


def enrichable_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool = False) -> tuple[bool, str]:
    """Decide whether an address may be sent to IP-intelligence endpoints.

    Loopback, link-local, multicast, unspecified and reserved space is never
    enriched. RFC1918/ULA space is enriched only in explicit local-lab mode.
    """
    cat = ip_category(ip)
    if cat == "public":
        return True, cat
    if cat == "private" and allow_private:
        return True, cat
    return False, cat


def parse_target(raw: str) -> Target:
    """Classify and normalise a domain, URL, IP, email, CVE, ASN, phone or MAC."""
    if raw is None or not raw.strip():
        raise TargetError("empty target")
    text = raw.strip()

    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme.lower() not in ("http", "https"):
            raise TargetError(f"unsupported URL scheme: {parts.scheme}")
        if not parts.hostname:
            raise TargetError(f"URL has no host: {raw!r}")
        text = parts.hostname

    ip = parse_ip(text)
    if ip is not None:
        return Target(raw, f"ipv{ip.version}", str(ip))
    if _CVE.match(text):
        return Target(raw, "cve", text.upper())
    m = _ASN.match(text)
    if m:
        return Target(raw, "asn", f"AS{int(m.group(1))}")
    m = _EMAIL.match(text)
    if m:
        local = text.split("@", 1)[0]
        return Target(raw, "email", f"{local}@{normalize_hostname(m.group(1))}")
    if _PHONE.match(text):
        return Target(raw, "phone", text)
    if _MAC.match(text):
        return Target(raw, "mac", text.lower().replace("-", ":"))
    # host:port without a scheme
    if text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        text = text.rsplit(":", 1)[0]
    return Target(raw, "domain", normalize_hostname(text))


def in_domain(host: str, root: str) -> bool:
    """True if `host` is `root` or a subdomain of it (label-boundary safe)."""
    host = host.rstrip(".").lower()
    root = root.rstrip(".").lower()
    return host == root or host.endswith("." + root)
