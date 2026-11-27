"""MihomoClient tests: error mapping + delay parsing.

``httpx.Client`` is monkeypatched with a fake — no network is used.
The key property: connection errors are distinguishable from HTTP
errors (``connection_error`` True + ``status`` None vs. the status
code carried on the exception).
"""

import httpx
import pytest

from app import mihomo_client as mc
from app.mihomo_client import MihomoClient, MihomoError


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = "" if payload is None else str(payload)
        self.reason_phrase = "Error" if status_code >= 400 else "OK"

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON")
        return self._payload


class FakeStreamResponse:
    def __init__(self, status_code, lines):
        self.status_code = status_code
        self._lines = lines

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_lines(self):
        yield from self._lines


class FakeHTTPXClient:
    """Stand-in for httpx.Client, driven by ``behavior``."""

    behavior = None  # set per test: ("ok", payload) | ("http", status)
                   # | ("connect", None) | ("timeout", None)

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        kind, payload = self.behavior
        if kind == "connect":
            raise httpx.ConnectError(
                "refused", request=httpx.Request(method, url)
            )
        if kind == "timeout":
            raise httpx.ConnectTimeout(
                "timed out", request=httpx.Request(method, url)
            )
        if kind == "http":
            return FakeResponse(payload, None)
        return FakeResponse(200, payload)

    def stream(self, method, url, **kwargs):
        kind, payload = self.behavior
        if kind == "connect":
            raise httpx.ConnectError(
                "refused", request=httpx.Request(method, url)
            )
        if kind == "http":
            return FakeStreamResponse(payload, [])
        return FakeStreamResponse(200, payload)


@pytest.fixture
def fake_http(monkeypatch):
    monkeypatch.setattr(mc.httpx, "Client", FakeHTTPXClient)
    return FakeHTTPXClient


def test_get_version_success(fake_http):
    fake_http.behavior = ("ok", {"version": "MetaCubeX 1.19"})
    assert MihomoClient().get_version() == {"version": "MetaCubeX 1.19"}


def test_http_error_carries_status(fake_http):
    fake_http.behavior = ("http", 401)
    with pytest.raises(MihomoError) as exc_info:
        MihomoClient(secret="wrong").get_version()
    assert exc_info.value.status == 401
    assert exc_info.value.connection_error is False


def test_connection_error_is_distinguishable(fake_http):
    fake_http.behavior = ("connect", None)
    with pytest.raises(MihomoError) as exc_info:
        MihomoClient().get_version()
    assert exc_info.value.connection_error is True
    assert exc_info.value.status is None
    assert "cannot reach mihomo" in exc_info.value.message


def test_timeout_is_a_connection_error(fake_http):
    fake_http.behavior = ("timeout", None)
    with pytest.raises(MihomoError) as exc_info:
        MihomoClient().get_version()
    assert exc_info.value.connection_error is True


def test_reload_sends_put_with_force(fake_http):
    captured = {}
    real_request = FakeHTTPXClient.request

    def spy(self, method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured["params"] = kwargs.get("params")
        return real_request(self, method, url, **kwargs)

    fake_http.behavior = ("ok", {})
    fake_http.request = spy
    try:
        MihomoClient().reload_config(force=True)
    finally:
        fake_http.request = real_request
    assert captured["method"] == "PUT"
    assert captured["url"].endswith("/configs")
    assert captured["params"] == {"force": "true"}


def test_delay_returns_ms_and_encodes_name(fake_http):
    fake_http.behavior = ("ok", {"delay": 87})
    client = MihomoClient()
    assert client.test_delay("My Node", "http://example.com", timeout=5) == 87


def test_delay_missing_value_raises(fake_http):
    fake_http.behavior = ("ok", {})
    with pytest.raises(MihomoError, match="no delay"):
        MihomoClient().test_delay("Node", "http://example.com")


def test_get_traffic_reads_first_line(fake_http):
    fake_http.behavior = ("ok", ['{"up": 10, "down": 20}'])
    assert MihomoClient().get_traffic() == {"up": 10, "down": 20}


def test_get_traffic_empty_stream_raises(fake_http):
    fake_http.behavior = ("ok", [])
    with pytest.raises(MihomoError, match="closed without data"):
        MihomoClient().get_traffic()


def test_auth_header_only_when_secret_set():
    assert MihomoClient(secret="").headers == {}
    assert MihomoClient(secret="s3cr3t").headers == {
        "Authorization": "Bearer s3cr3t"
    }
