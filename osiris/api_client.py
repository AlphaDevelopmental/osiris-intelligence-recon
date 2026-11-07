"""HTTP client for the OSIRIS API: rate budgets, retries, error classification."""

from __future__ import annotations

import itertools
import json
import logging
import os
import random
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit

import requests

from . import USER_AGENT
from .models import CallRecord, utcnow
from .registry import ACTIVE, AI, RATE_BUCKETS, STATEFUL, STREAM, Endpoint

log = logging.getLogger("osiris.api")

# Result statuses
STATUS_SUCCESS = "success"
STATUS_INVALID = "invalid_request"  # 400/422 – do not retry
STATUS_AUTH = "auth_error"  # 401/403 – do not retry
STATUS_NOT_FOUND = "not_found"  # 404
STATUS_RATE_LIMITED = "rate_limited"  # 429 after retries exhausted
STATUS_UNAVAILABLE = "unavailable"  # 503 / feature not configured
STATUS_UPSTREAM = "upstream_error"  # 5xx
STATUS_TIMEOUT = "timeout"
STATUS_NETWORK = "network_error"  # DNS failure, refused connection, TLS failure
STATUS_EMPTY = "empty_response"
STATUS_BAD_JSON = "invalid_json"
STATUS_OVERSIZED = "oversized"
STATUS_STREAM = "stream_refused"
STATUS_REFUSED = "refused"  # client-side policy refused to send

RETRYABLE_HTTP = {429, 500, 502, 504}
_SECRET_PARAM = re.compile(r"(?i)(key|token|secret|password|passwd|auth|signature|sig)")


def redact_params(params: dict[str, Any]) -> dict[str, str]:
    return {k: ("[REDACTED]" if _SECRET_PARAM.search(k) else str(v)) for k, v in params.items()}


def redact_text(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s and len(s) >= 4:
            text = text.replace(s, "[REDACTED]")
    return text


class RateBudget:
    """Sliding-window limiter per bucket. Thread-safe; clock/sleep injectable for tests."""

    def __init__(
        self,
        buckets: dict[str, tuple[int, float]] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.buckets = dict(RATE_BUCKETS if buckets is None else buckets)
        self.clock = clock
        self.sleep = sleep
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def acquire(self, bucket: str | None) -> float:
        """Block until a slot is free; returns seconds waited."""
        if not bucket or bucket not in self.buckets:
            return 0.0
        limit, window = self.buckets[bucket]
        waited = 0.0
        while True:
            with self._lock:
                now = self.clock()
                q = self._events.setdefault(bucket, deque())
                while q and now - q[0] >= window:
                    q.popleft()
                if len(q) < limit:
                    q.append(now)
                    return waited
                delay = window - (now - q[0]) + 0.05
            log.info("rate budget '%s' full (%d/%.0fs); waiting %.1fs", bucket, limit, window, delay)
            self.sleep(delay)
            waited += delay

    def wait_idle(self, bucket: str) -> float:
        """Block until no call from `bucket` remains inside its window."""
        if bucket not in self.buckets:
            return 0.0
        _, window = self.buckets[bucket]
        with self._lock:
            q = self._events.get(bucket) or deque()
            delay = (window - (self.clock() - q[-1]) + 0.5) if q else 0.0
        if delay > 0:
            log.info("waiting %.0fs for the shared OSIRIS rate window to clear", delay)
            self.sleep(delay)
            return delay
        return 0.0

    def penalize(self, bucket: str | None, seconds: float) -> None:
        """After a server 429, treat the bucket as full for `seconds`."""
        if not bucket or bucket not in self.buckets:
            return
        limit, window = self.buckets[bucket]
        with self._lock:
            now = self.clock()
            stamp = now - window + seconds
            self._events[bucket] = deque([stamp] * limit)


@dataclass
class ApiResult:
    status: str
    http_status: int | None = None
    data: Any = None
    error: str | None = None
    attempts: int = 0
    elapsed_ms: int = 0
    url: str = ""
    degraded: bool = False
    record: CallRecord | None = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return self.status == STATUS_SUCCESS


class OsirisClient:
    """Read-only client. Refuses streams and state-changing methods by design."""

    def __init__(
        self,
        base_url: str = "https://osirisai.live",
        *,
        timeout: float = 25.0,
        max_retries: int = 3,
        backoff_base: float = 1.5,
        backoff_cap: float = 30.0,
        max_bytes: int = 5_000_000,
        budget: RateBudget | None = None,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
        extra_headers: dict[str, str] | None = None,
        active_enabled: bool = False,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.path not in ("", "/"):
            raise ValueError(f"invalid OSIRIS base URL: {base_url!r}")
        self.base_url = f"{parts.scheme}://{parts.netloc}"
        self.active_enabled = active_enabled
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self.max_bytes = max_bytes
        self.budget = budget or RateBudget(sleep=sleep)
        self.sleep = sleep
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
        self._secrets: list[str] = []
        headers = dict(extra_headers or {})
        # Optional header for self-hosted deployments behind an authenticating proxy.
        # The public OSIRIS API needs no credential for the GET routes used here.
        raw = os.environ.get("OSIRIS_AUTH_HEADER", "").strip()
        if raw and ":" in raw:
            name, value = raw.split(":", 1)
            headers[name.strip()] = value.strip()
        for v in headers.values():
            self._secrets.append(v)
        self.session.headers.update(headers)
        self._ids = itertools.count(1)
        self.calls: list[CallRecord] = []

    # ── helpers ──────────────────────────────────────────────────────
    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(max(retry_after, 0.0), self.backoff_cap)
        base = min(self.backoff_base * (2 ** (attempt - 1)), self.backoff_cap)
        return base + random.uniform(0, base * 0.25)

    @staticmethod
    def _retry_after(resp: requests.Response) -> float | None:
        value = resp.headers.get("Retry-After")
        if value and value.strip().isdigit():
            return float(value.strip())
        return None

    def _read_body(self, resp: requests.Response) -> tuple[bytes, bool]:
        declared = resp.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            return b"", True
        chunks: list[bytes] = []
        size = 0
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > self.max_bytes:
                return b"", True
            chunks.append(chunk)
        return b"".join(chunks), False

    @staticmethod
    def _error_text(data: Any, body: bytes) -> str:
        if isinstance(data, dict):
            parts = [str(data[k]) for k in ("error", "detail", "message", "hint") if data.get(k)]
            if parts:
                return " — ".join(parts)[:500]
        return body[:300].decode("utf-8", "replace")

    @staticmethod
    def classify_http(code: int, data: Any) -> str:
        if 200 <= code < 300:
            return STATUS_SUCCESS
        if code in (400, 422):
            return STATUS_INVALID
        if code in (401, 402, 403):
            return STATUS_AUTH
        if code == 404:
            return STATUS_NOT_FOUND
        if code == 429:
            return STATUS_RATE_LIMITED
        if code == 503:
            return STATUS_UNAVAILABLE
        return STATUS_UPSTREAM

    # ── main entry ───────────────────────────────────────────────────
    def get(self, ep: Endpoint, params: dict[str, str] | None = None, purpose: str = "") -> ApiResult:
        params = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        call_id = f"C{next(self._ids):04d}"
        started = utcnow()
        t0 = time.monotonic()

        def finish(res: ApiResult) -> ApiResult:
            res.elapsed_ms = int((time.monotonic() - t0) * 1000)
            rec = CallRecord(
                call_id=call_id,
                endpoint=ep.key,
                params=redact_params(params),
                status=res.status,
                http_status=res.http_status,
                attempts=res.attempts,
                elapsed_ms=res.elapsed_ms,
                started_at=started,
                error=redact_text(res.error, self._secrets) if res.error else None,
                degraded=res.degraded,
                purpose=purpose,
            )
            res.record = rec
            self.calls.append(rec)
            log.info(
                "%s %-6s %-28s %s %s",
                call_id,
                res.status,
                ep.path,
                res.http_status or "-",
                json.dumps(rec.params) if rec.params else "",
            )
            return res

        if ep.method != "GET" or ep.category in (STATEFUL, AI):
            return finish(
                ApiResult(STATUS_REFUSED, error=f"{ep.method} {ep.category} endpoint refused by client policy")
            )
        if ep.category == STREAM:
            return finish(ApiResult(STATUS_STREAM, error="streaming endpoint refused (unbounded)"))
        if ep.category == ACTIVE and not self.active_enabled:
            return finish(ApiResult(STATUS_REFUSED, error="active endpoint refused: active mode not enabled"))
        missing = [p.name for p in ep.params if p.required and p.name not in params]
        if missing or "{id}" in ep.path:
            return finish(
                ApiResult(STATUS_INVALID, error=f"missing required parameter(s): {', '.join(missing) or 'id'}")
            )

        url = self.base_url + ep.path
        shown_url = url + ("?" + urlencode(redact_params(params)) if params else "")
        timeout = max(self.timeout, ep.min_timeout)
        attempt = 0
        timeouts = 0
        last: ApiResult = ApiResult(STATUS_NETWORK, error="not attempted")
        while attempt <= self.max_retries:
            attempt += 1
            self.budget.acquire(ep.rate_bucket)
            retry_after: float | None = None
            try:
                with self.session.get(url, params=params, timeout=timeout, stream=True) as resp:
                    ctype = resp.headers.get("Content-Type", "")
                    if "text/event-stream" in ctype:
                        return finish(
                            ApiResult(
                                STATUS_STREAM,
                                resp.status_code,
                                error="server answered with an event stream",
                                attempts=attempt,
                                url=shown_url,
                            )
                        )
                    body, oversized = self._read_body(resp)
                    code = resp.status_code
                    retry_after = self._retry_after(resp)
            except requests.Timeout as exc:
                timeouts += 1
                last = ApiResult(
                    STATUS_TIMEOUT,
                    error=f"timeout after {timeout}s: {type(exc).__name__}",
                    attempts=attempt,
                    url=shown_url,
                )
            except requests.ConnectionError as exc:
                msg = str(exc)
                kind = (
                    "DNS resolution failed"
                    if ("NameResolution" in msg or "getaddrinfo" in msg)
                    else "connection failed"
                )
                last = ApiResult(STATUS_NETWORK, error=f"{kind}: {type(exc).__name__}", attempts=attempt, url=shown_url)
            except requests.RequestException as exc:
                return finish(
                    ApiResult(
                        STATUS_NETWORK, error=f"request error: {type(exc).__name__}", attempts=attempt, url=shown_url
                    )
                )
            else:
                if oversized:
                    return finish(
                        ApiResult(
                            STATUS_OVERSIZED,
                            code,
                            error=f"response exceeds {self.max_bytes} bytes",
                            attempts=attempt,
                            url=shown_url,
                        )
                    )
                data: Any = None
                if body.strip():
                    try:
                        data = json.loads(body)
                    except (ValueError, UnicodeDecodeError):
                        data = None
                status = self.classify_http(code, data)
                if status == STATUS_SUCCESS:
                    if not body.strip():
                        return finish(
                            ApiResult(STATUS_EMPTY, code, error="empty response body", attempts=attempt, url=shown_url)
                        )
                    if data is None:
                        return finish(
                            ApiResult(
                                STATUS_BAD_JSON,
                                code,
                                error="response is not JSON: " + body[:120].decode("utf-8", "replace"),
                                attempts=attempt,
                                url=shown_url,
                            )
                        )
                    degraded = isinstance(data, dict) and bool(data.get("error"))
                    return finish(
                        ApiResult(
                            STATUS_SUCCESS,
                            code,
                            data=data,
                            attempts=attempt,
                            url=shown_url,
                            degraded=degraded,
                            error=self._error_text(data, body) if degraded else None,
                        )
                    )
                last = ApiResult(
                    status, code, data=data, error=self._error_text(data, body), attempts=attempt, url=shown_url
                )
                if code == 429:
                    self.budget.penalize(ep.rate_bucket, retry_after or 60.0)
                # 503 "not configured" is permanent for this deployment.
                if code == 503 and "not configured" in (last.error or "").lower():
                    return finish(last)
                if code not in RETRYABLE_HTTP and code != 503:
                    return finish(last)
            if attempt > self.max_retries or timeouts >= 2:
                break  # a slow upstream is retried once, not hammered
            if last.status == STATUS_RATE_LIMITED and ep.rate_bucket in self.budget.buckets:
                log.warning("%s rate limited by server; budget paused", ep.path)
                continue  # RateBudget.acquire now blocks for the penalty window
            delay = self._backoff(attempt, retry_after)
            log.warning("%s attempt %d failed (%s); retrying in %.1fs", ep.path, attempt, last.status, delay)
            self.sleep(delay)
        return finish(last)
