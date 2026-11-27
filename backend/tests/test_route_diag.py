"""Route-diagnosis connection states + exit-IP probe tests.

``connection`` has exactly four values (see
``app.route_check._connection``); the exit-IP endpoint's external
requests are faked — no network is used.
"""

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.deps import get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError
from app.probe_guard import reset_probe_guard
from app.routers import diagnostics as diag_mod

ADMIN_PASSWORD = "test-admin-password"

SS_PROXY = {
    "type": "ss", "server": "1.2.3.4", "port": 8388,
    "password": "pw", "cipher": "aes-128-gcm",
}
HY_PROXY = {
    "type": "hysteria2", "server": "5.6.7.8", "port": 443,
    "password": "pw2", "sni": "example.com",
}


class FakeClient:
    def __init__(self):
        self.down = False
        self.now = {}

    def _maybe_down(self):
        if self.down:
            raise MihomoError(
                "cannot reach mihomo at http://127.0.0.1:9090: refused",
                connection_error=True,
            )

    def get_version(self):
        self._maybe_down()
        return {"version": "fake-1.0-test"}

    def reload_config(self, force=True):
        self._maybe_down()

    def test_delay(self, proxy, url, timeout=5):
        self._maybe_down()
        return 42

    def get_proxy_group(self, name):
        self._maybe_down()
        return {"name": name, "type": "Fallback", "now": self.now.get(name)}


@pytest.fixture(autouse=True)
def _reset_probe_guard():
    # The probe guard is process-global (dedup cache + rate window);
    # reset it so each test starts unpolluted.
    reset_probe_guard()
    yield
    reset_probe_guard()


@pytest.fixture
def fake_client():
    return FakeClient()


@pytest.fixture
def app(tmp_path, fake_client):
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    app.state.db.set_setting(
        "admin_password_hash", hash_password(ADMIN_PASSWORD)
    )
    app.dependency_overrides[get_mihomo_client] = lambda: fake_client
    return app


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers(client):
    response = client.post(
        "/api/auth/login", json={"password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture
def seeded(app):
    """Two online nodes; youtube + ai + default bound (main A, backup B)."""
    db = app.state.db
    a = db.add_node("Node-A", "ss://fake-a", dict(SS_PROXY))
    b = db.add_node("Node-B", "ss://fake-b", dict(HY_PROXY))
    db.update_node(a, last_online=True, last_delay_ms=12)
    db.update_node(b, last_online=True, last_delay_ms=30)
    for group in ("youtube", "ai", "default"):
        db.set_binding(group, a, role="main", mode="fallback")
        db.set_binding(group, b, role="backup", mode="fallback")
    return {"a": a, "b": b}


def _check(client, auth_headers, domain):
    return client.post(
        "/api/diagnostics/route-check",
        headers=auth_headers,
        json={"domain": domain},
    )


def _exit_ip(client, auth_headers, domain):
    return client.post(
        "/api/diagnostics/exit-ip",
        headers=auth_headers,
        json={"domain": domain},
    )


# ---------------------------------------------------------------- connection
def test_connection_connected(client, auth_headers, seeded, fake_client):
    fake_client.now = {"YouTube": "Node-B"}
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["connection"] == "connected"
    assert body["current"]["name"] == "Node-B"
    assert body["current_source"] == "mihomo"
    assert body["mihomo_reachable"] is True


def test_connection_direct_unbound_group(
    client, auth_headers, seeded
):
    # Apple is unbound: effective target DIRECT.
    body = _check(client, auth_headers, "www.apple.com").json()
    assert body["effective_target"] == "DIRECT"
    assert body["connection"] == "direct"


def test_connection_direct_custom_rule(client, auth_headers, seeded, app):
    app.state.db.add_custom_rule(
        "DOMAIN-KEYWORD", "internal", "DIRECT", enabled=True
    )
    body = _check(client, auth_headers, "internal.corp.example").json()
    assert body["effective_target"] == "DIRECT"
    assert body["connection"] == "direct"


def test_connection_unreachable_all_offline(
    client, auth_headers, seeded, fake_client, app
):
    fake_client.down = True
    app.state.db.update_node(seeded["a"], last_online=False)
    app.state.db.update_node(seeded["b"], last_online=False)
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["current"] is None
    assert body["connection"] == "unreachable"


def test_connection_unknown_mihomo_down_inferred(
    client, auth_headers, seeded, fake_client
):
    # Mihomo down, main online: current is only inferred, so the live
    # connection state is unknown — not "connected".
    fake_client.down = True
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["current"]["name"] == "Node-A"
    assert body["current_source"] == "inferred"
    assert body["mihomo_reachable"] is False
    assert body["connection"] == "unknown"


def test_connection_unknown_reject_target(
    client, auth_headers, seeded, app
):
    app.state.db.add_custom_rule(
        "DOMAIN-KEYWORD", "blocked", "REJECT", enabled=True
    )
    body = _check(client, auth_headers, "blocked.example.org").json()
    assert body["effective_target"] == "REJECT"
    assert body["connection"] == "unknown"


def test_connection_unknown_target(client, auth_headers, seeded, app):
    app.state.db.add_custom_rule(
        "DOMAIN-SUFFIX", "typo.example", "TypoGroup", enabled=True
    )
    body = _check(client, auth_headers, "www.typo.example").json()
    assert body["group"] == "TypoGroup"
    assert body["group_key"] is None
    assert body["connection"] == "unknown"


def test_connection_no_match_follows_default(
    client, auth_headers, seeded, fake_client
):
    fake_client.now = {"Default": "Node-B"}
    body = _check(client, auth_headers, "unknown.example.org").json()
    assert body["matched"] is False
    assert body["connection"] == "connected"
    assert body["default_group"]["connection"] == "connected"


def test_connection_no_match_unknown_when_mihomo_down(
    client, auth_headers, seeded, fake_client
):
    fake_client.down = True
    body = _check(client, auth_headers, "unknown.example.org").json()
    assert body["matched"] is False
    assert body["connection"] == "unknown"
    assert body["default_group"]["connection"] == "unknown"


def test_resolve_group_connection_direct_empty_group(
    client, auth_headers, seeded
):
    # resolve_group itself carries the field (used by default_group).
    body = _check(client, auth_headers, "unknown.example.org").json()
    assert body["default_group"]["connection"] in (
        "connected", "unreachable", "unknown", "direct",
    )


# ------------------------------------------------------------------ exit-ip
def test_exit_ip_requires_auth(client, seeded):
    assert _exit_ip(client, {}, "youtube.com").status_code == 401


def test_exit_ip_empty_domain_400(client, auth_headers, seeded):
    assert _exit_ip(client, auth_headers, "   ").status_code == 400


def test_exit_ip_same_group_is_that_groups_ip(
    client, auth_headers, seeded, fake_client, monkeypatch
):
    # api.ipify.org matches no rule -> Default group; diagnosing an
    # unmatched domain also lands on Default, so via == diagnosed.
    monkeypatch.setattr(
        diag_mod, "_fetch_exit_ip",
        lambda settings: ("203.0.113.7", None, "api.ipify.org"),
    )
    response = _exit_ip(client, auth_headers, "unknown.example.org")
    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == "unknown.example.org"
    assert body["group"] == "Default"
    assert body["ip"] == "203.0.113.7"
    assert body["via_group"] == "Default"
    assert body["via_node"] == "Node-A"
    assert body["error"] is None
    assert "就是 Default 组的出口 IP" in body["note"]
    assert "一致" in body["note"]


def test_exit_ip_different_group_says_so(
    client, auth_headers, seeded, fake_client, monkeypatch
):
    monkeypatch.setattr(
        diag_mod, "_fetch_exit_ip",
        lambda settings: ("203.0.113.7", None, "api.ipify.org"),
    )
    body = _exit_ip(client, auth_headers, "youtube.com").json()
    assert body["group"] == "YouTube"
    assert body["ip"] == "203.0.113.7"
    assert body["via_group"] == "Default"
    assert body["via_node"] == "Node-A"
    assert body["error"] is None
    assert "不是诊断组 YouTube 的出口 IP" in body["note"]
    assert "Default 组的出口 IP" in body["note"]


def test_exit_ip_failure_returns_null_ip_never_fakes(
    client, auth_headers, seeded, monkeypatch
):
    monkeypatch.setattr(
        diag_mod, "_fetch_exit_ip",
        lambda settings: (
            None,
            "proxied request to https://api.ipify.org?format=json failed:"
            " [Errno 111] Connection refused",
            "api.ipify.org",
        ),
    )
    response = _exit_ip(client, auth_headers, "youtube.com")
    assert response.status_code == 200  # degradation, never a 500
    body = response.json()
    assert body["ip"] is None
    # L-17: the error is a sanitized category, never the raw
    # exception text — no "Connection refused" anywhere in the
    # response, only the category + a plain-language note.
    assert body["error"] == "connection_refused"
    assert "Connection refused" not in body["error"]
    assert "Connection refused" not in body["note"]
    assert "Errno 111" not in body["note"]
    assert "连接被拒绝" in body["note"]
    assert "未伪造" in body["note"]
    assert body["via_group"] == "Default"  # via route still reported


def test_exit_ip_failure_timeout_category(
    client, auth_headers, seeded, monkeypatch
):
    monkeypatch.setattr(
        diag_mod, "_fetch_exit_ip",
        lambda settings: (
            None,
            "proxied request to https://api.ipify.org?format=json failed:"
            " timed out",
            "api.ipify.org",
        ),
    )
    body = _exit_ip(client, auth_headers, "youtube.com").json()
    assert body["ip"] is None
    assert body["error"] == "timeout"
    assert "timed out" not in body["note"]


def test_exit_ip_dedup_reuses_result_within_5s(
    client, auth_headers, seeded, monkeypatch
):
    # M-31: the same domain within 5s reuses the first result.
    calls = []

    def counting_fetch(settings):
        calls.append(1)
        return ("203.0.113.7", None, "api.ipify.org")

    monkeypatch.setattr(diag_mod, "_fetch_exit_ip", counting_fetch)
    first = _exit_ip(client, auth_headers, "youtube.com").json()
    assert first["cached"] is False
    assert first["ip"] == "203.0.113.7"
    second = _exit_ip(client, auth_headers, "youtube.com").json()
    assert second["cached"] is True
    assert second["ip"] == "203.0.113.7"
    assert len(calls) == 1
    # A different domain is a different dedup key.
    third = _exit_ip(client, auth_headers, "unknown.example.org").json()
    assert third["cached"] is False
    assert len(calls) == 2


def test_exit_ip_drift_annotated(
    client, auth_headers, seeded, app, monkeypatch
):
    # M-13: drift is annotated on the exit-ip result too.
    app.state.db.set_setting("config_revision_db", "7")
    app.state.db.set_setting("config_revision_running", "2")
    monkeypatch.setattr(
        diag_mod, "_fetch_exit_ip",
        lambda settings: ("203.0.113.7", None, "api.ipify.org"),
    )
    body = _exit_ip(client, auth_headers, "youtube.com").json()
    assert body["config_drift"] is True
    assert body["db_revision"] == 7
    assert body["running_revision"] == 2
    assert "基于过期配置，仅供参考" in body["note"]


def test_fetch_exit_ip_falls_back_to_ifconfig(monkeypatch):
    calls = []

    def fake_fetch(url, settings, timeout=10.0):
        calls.append(url)
        if "api.ipify.org" in url:
            return None, "ipify down"
        return "198.51.100.9", None

    monkeypatch.setattr(diag_mod, "_fetch_via_socks5", fake_fetch)
    ip, error, via_domain = diag_mod._fetch_exit_ip(
        diag_mod.Settings()
    )
    assert ip == "198.51.100.9"
    assert error is None
    assert via_domain == "ifconfig.me"
    assert calls == [diag_mod.IPIFY_URL, diag_mod.IFCONFIG_URL]


def test_fetch_exit_ip_both_fail_reports_error(monkeypatch):
    monkeypatch.setattr(
        diag_mod, "_fetch_via_socks5",
        lambda url, settings, timeout=10.0: (None, f"{url} down"),
    )
    ip, error, via_domain = diag_mod._fetch_exit_ip(diag_mod.Settings())
    assert ip is None
    assert error is not None
    assert "ifconfig.me" in error  # last (fallback) attempt's error
    assert via_domain == "api.ipify.org"


# ------------------------------------------------------- echo body cap (M-33)
class _FakeSocket:
    """A socket that yields a pre-built byte stream, then EOF."""

    def __init__(self, payload: bytes):
        self._payload = payload
        self._pos = 0

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        pass

    def recv(self, n):
        if self._pos >= len(self._payload):
            return b""
        chunk = self._payload[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def close(self):
        pass


class _FakeTLSContext:
    def __init__(self, tls_socket):
        self._tls_socket = tls_socket

    def wrap_socket(self, sock, server_hostname=None):
        return self._tls_socket


def test_fetch_via_socks5_rejects_oversize_echo(monkeypatch):
    # M-33: an echo response over 64KB is aborted and reported as an
    # error — never read into memory in full, never parsed as an IP.
    big = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 70000\r\n"
        b"Connection: close\r\n\r\n" + b"1" * 70000
    )
    assert len(big) > diag_mod.MAX_ECHO_BYTES
    monkeypatch.setattr(
        diag_mod.probes, "_socks5_connect", lambda *a, **k: None
    )
    monkeypatch.setattr(
        diag_mod.socket, "create_connection",
        lambda addr, timeout=None: _FakeSocket(b""),
    )
    monkeypatch.setattr(
        diag_mod.ssl, "create_default_context",
        lambda: _FakeTLSContext(_FakeSocket(big)),
    )
    ip, error = diag_mod._fetch_via_socks5(
        diag_mod.IPIFY_URL, diag_mod.Settings()
    )
    assert ip is None
    assert error is not None
    assert "64KB" in error


def test_fetch_via_socks5_accepts_small_echo(monkeypatch):
    # The same fake plumbing with a small body still yields the IP.
    small = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: 20\r\nConnection: close\r\n\r\n"
        b'{"ip": "203.0.113.7"}'
    )
    monkeypatch.setattr(
        diag_mod.probes, "_socks5_connect", lambda *a, **k: None
    )
    monkeypatch.setattr(
        diag_mod.socket, "create_connection",
        lambda addr, timeout=None: _FakeSocket(b""),
    )
    monkeypatch.setattr(
        diag_mod.ssl, "create_default_context",
        lambda: _FakeTLSContext(_FakeSocket(small)),
    )
    ip, error = diag_mod._fetch_via_socks5(
        diag_mod.IPIFY_URL, diag_mod.Settings()
    )
    assert ip == "203.0.113.7"
    assert error is None


def test_exit_ip_oversize_echo_is_sanitized(
    client, auth_headers, seeded, monkeypatch
):
    # The 64KB error surfaces at the endpoint as its category.
    monkeypatch.setattr(
        diag_mod, "_fetch_exit_ip",
        lambda settings: (
            None,
            "echo service https://api.ipify.org?format=json response"
            " exceeded 64KB limit",
            "api.ipify.org",
        ),
    )
    body = _exit_ip(client, auth_headers, "youtube.com").json()
    assert body["ip"] is None
    assert body["error"] == "response_too_large"
    assert "64KB" in body["note"]
