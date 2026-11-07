"""Shared data structures: assets, findings, endpoint execution records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Relation of an asset to the engagement target.
TARGET = "target"
FIRST_PARTY = "first_party"  # the target domain or one of its subdomains
HOSTING = "hosting"  # an address a first-party name resolves to; tenancy unknown
THIRD_PARTY = "third_party"  # mail/DNS providers, CNAME targets outside scope, etc.
REFERENCED = "referenced"  # mentioned in a record (e.g. SPF) but not resolved from the target


@dataclass
class Asset:
    value: str
    kind: str  # domain | hostname | ipv4 | ipv6 | asn | mail_host | nameserver | cidr
    relation: str
    sources: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=utcnow)
    parent: str | None = None
    depth: int = 0
    enriched: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SEVERITIES = ("critical", "high", "medium", "low", "informational")


@dataclass
class Evidence:
    source: str  # e.g. "GET /api/osint/whois" or "active:http"
    reference: str  # call id / URL (without secrets) / file
    excerpt: str
    observed_at: str = field(default_factory=utcnow)


@dataclass
class Finding:
    id: str
    title: str
    asset: str
    observation: str
    evidence: list[Evidence]
    confidence: str  # high | medium | low
    impact: str
    severity: str
    severity_justification: str
    remediation: str
    verification: str  # unverified | observed | confirmed
    category: str = "general"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CallRecord:
    call_id: str
    endpoint: str
    params: dict[str, str]
    status: str  # see api_client.STATUS_*
    http_status: int | None
    attempts: int
    elapsed_ms: int
    started_at: str
    error: str | None = None
    degraded: bool = False  # 2xx but upstream reported a partial failure
    purpose: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Final per-endpoint statuses required in every report.
EXECUTED = "executed"
SKIPPED = "skipped"
UNAVAILABLE = "unavailable"
INCOMPATIBLE = "incompatible"
FAILED = "failed"
PLANNED = "planned"
ENDPOINT_STATUSES = (EXECUTED, SKIPPED, UNAVAILABLE, INCOMPATIBLE, FAILED, PLANNED)


@dataclass
class EndpointExecution:
    key: str
    method: str
    path: str
    group: str
    status: str
    reason: str
    calls: list[CallRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["call_count"] = len(self.calls)
        return d
