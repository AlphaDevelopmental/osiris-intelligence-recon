import pytest
import requests
from conftest import FakeResponse, make_client

from osiris import registry as reg
from osiris.api_client import OsirisClient, RateBudget

DNS = reg.get("/api/osint/dns")


def seq(*responses):
    it = iter(responses)
    return lambda p: next(it)


def test_success_and_record():
    client, session = make_client({"/api/osint/dns": {"domain": "example.com"}})
    res = client.get(DNS, {"domain": "example.com"})
    assert res.ok and res.data["domain"] == "example.com" and res.attempts == 1
    assert res.record.status == "success" and res.record.params == {"domain": "example.com"}


@pytest.mark.parametrize(
    "code,status",
    [(400, "invalid_request"), (401, "auth_error"), (403, "auth_error"), (404, "not_found"), (422, "invalid_request")],
)
def test_non_retryable_errors(code, status):
    client, session = make_client({"/api/osint/dns": FakeResponse(code, {"error": "nope"})})
    res = client.get(DNS, {"domain": "example.com"})
    assert res.status == status and res.attempts == 1 and res.error == "nope"
    assert len(session.requests) == 1


def test_retry_on_500_then_success(no_sleep):
    client, session = make_client({"/api/osint/dns": seq(FakeResponse(500, {"error": "x"}), {"ok": 1})}, no_sleep)
    res = client.get(DNS, {"domain": "example.com"})
    assert res.ok and res.attempts == 2 and len(no_sleep) == 1


def test_exponential_backoff_and_give_up(no_sleep):
    client, session = make_client(
        {"/api/osint/dns": FakeResponse(502, {"error": "bad gateway"})}, no_sleep, max_retries=3
    )
    res = client.get(DNS, {"domain": "example.com"})
    assert res.status == "upstream_error" and res.attempts == 4
    assert len(no_sleep) == 3 and no_sleep[0] < no_sleep[1] < no_sleep[2]


def test_429_honours_retry_after_via_budget():
    clock = [0.0]
    slept: list[float] = []

    def sleep(s):
        slept.append(s)
        clock[0] += s

    budget = RateBudget({"shared": (18, 60.0)}, clock=lambda: clock[0], sleep=sleep)
    from conftest import FakeSession

    session = FakeSession(
        {
            "/api/osint/dns": seq(
                FakeResponse(
                    429, {"error": "Rate limit exceeded"}, {"Retry-After": "7", "Content-Type": "application/json"}
                ),
                {"ok": True},
            )
        }
    )
    client = OsirisClient("https://osiris.test", session=session, budget=budget, sleep=sleep)
    res = client.get(DNS, {"domain": "example.com"})
    assert res.ok and res.attempts == 2
    assert 6.9 < sum(slept) < 8  # waited the Retry-After window, not more


def test_429_exhausted_reports_rate_limited(no_sleep):
    client, _ = make_client(
        {"/api/osint/dns": FakeResponse(429, {"error": "Rate limit exceeded"})}, no_sleep, max_retries=1
    )
    assert client.get(DNS, {"domain": "example.com"}).status == "rate_limited"


def test_503_not_configured_is_not_retried():
    scanner = reg.get("/api/scanner")
    client, session = make_client(
        {"/api/scanner": FakeResponse(503, {"error": "Scanner not configured"})}, active_enabled=True
    )
    res = client.get(scanner, {"target": "example.com", "type": "headers"})
    assert res.status == "unavailable" and len(session.requests) == 1


def test_503_transient_is_retried(no_sleep):
    client, session = make_client({"/api/osint/dns": seq(FakeResponse(503, {"error": "busy"}), {"ok": 1})}, no_sleep)
    assert client.get(DNS, {"domain": "example.com"}).ok and len(session.requests) == 2


def test_timeout_and_dns_failure(no_sleep):
    client, _ = make_client({"/api/osint/dns": lambda p: requests.Timeout("slow")}, no_sleep, max_retries=1)
    res = client.get(DNS, {"domain": "example.com"})
    assert res.status == "timeout" and res.attempts == 2
    err = requests.ConnectionError("HTTPSConnectionPool: NameResolutionError(getaddrinfo failed)")
    client, _ = make_client({"/api/osint/dns": lambda p: err}, no_sleep, max_retries=0)
    res = client.get(DNS, {"domain": "example.com"})
    assert res.status == "network_error" and "DNS resolution failed" in res.error


def test_empty_invalid_and_oversized_bodies():
    client, _ = make_client({"/api/osint/dns": FakeResponse(200, raw=b"")})
    assert client.get(DNS, {"domain": "a.com"}).status == "empty_response"
    client, _ = make_client({"/api/osint/dns": FakeResponse(200, raw=b"<html>oops</html>")})
    assert client.get(DNS, {"domain": "a.com"}).status == "invalid_json"
    client, _ = make_client({"/api/osint/dns": FakeResponse(200, raw=b"[" + b"1," * 5000 + b"1]")}, max_bytes=1000)
    assert client.get(DNS, {"domain": "a.com"}).status == "oversized"
    client, _ = make_client(
        {"/api/osint/dns": FakeResponse(200, {"a": 1}, {"Content-Length": "99999999"})}, max_bytes=1000
    )
    assert client.get(DNS, {"domain": "a.com"}).status == "oversized"


def test_degraded_2xx_body_is_flagged():
    client, _ = make_client(
        {"/api/osint/certs": {"domain": "a.com", "certificates": [], "error": "crt.sh unavailable"}}
    )
    res = client.get(reg.get("/api/osint/certs"), {"domain": "a.com"})
    assert res.ok and res.degraded and "crt.sh" in res.error


def test_event_stream_response_refused():
    client, _ = make_client(
        {"/api/osint/dns": FakeResponse(200, raw=b"data: x\n\n", headers={"Content-Type": "text/event-stream"})}
    )
    assert client.get(DNS, {"domain": "a.com"}).status == "stream_refused"


@pytest.mark.parametrize(
    "key", ["GET /api/malware/stream", "POST /api/ai/analyze", "DELETE /api/oi/runs/{id}", "POST /api/sdk/ingest"]
)
def test_policy_refuses_streams_and_state_changing(key):
    client, session = make_client({})
    res = client.get(reg.BY_KEY[key], {})
    assert res.status in ("stream_refused", "refused") and session.requests == []


def test_active_endpoint_refused_unless_enabled():
    client, session = make_client({"/api/scanner": {"ok": 1}})
    res = client.get(reg.get("/api/scanner"), {"target": "example.com"})
    assert res.status == "refused" and session.requests == []


def test_missing_required_parameter_not_sent():
    client, session = make_client({})
    res = client.get(reg.get("/api/osint/hudsonrock"), {"type": "domain"})
    assert res.status == "invalid_request" and "query" in res.error and session.requests == []


def test_secrets_are_redacted(monkeypatch):
    monkeypatch.setenv("OSIRIS_AUTH_HEADER", "X-Proxy-Auth: supersecretvalue123")
    client, session = make_client(
        {"/api/osint/dns": FakeResponse(500, {"error": "echo supersecretvalue123"})}, max_retries=0
    )
    res = client.get(DNS, {"domain": "a.com", "api_key": "abcd1234"})
    assert res.record.params["api_key"] == "[REDACTED]"
    assert "supersecretvalue123" not in res.record.error
    assert session.headers["X-Proxy-Auth"] == "supersecretvalue123"


def test_rate_budget_blocks_when_full():
    clock = [0.0]
    slept = []

    def sleep(s):
        slept.append(s)
        clock[0] += s

    b = RateBudget({"x": (2, 10.0)}, clock=lambda: clock[0], sleep=sleep)
    b.acquire("x")
    b.acquire("x")
    assert slept == []
    b.acquire("x")
    assert len(slept) == 1 and 9.9 < slept[0] < 10.2


def test_invalid_base_url():
    with pytest.raises(ValueError):
        OsirisClient("ftp://osiris")
    with pytest.raises(ValueError):
        OsirisClient("https://osiris.test/api")


def test_timeouts_retried_once_and_slow_endpoints_get_longer_timeout(no_sleep):
    seen = []

    def slow(p):
        return requests.Timeout("slow")

    client, session = make_client({"/api/osint/hudsonrock": slow}, no_sleep, max_retries=3, timeout=10)
    orig = session.get

    def spy(url, params=None, timeout=None, stream=False, **kw):
        seen.append(timeout)
        return orig(url, params=params, timeout=timeout, stream=stream)

    session.get = spy
    res = client.get(reg.get("/api/osint/hudsonrock"), {"query": "example.com", "type": "domain"})
    assert res.status == "timeout" and res.attempts == 2
    assert seen == [45.0, 45.0]
