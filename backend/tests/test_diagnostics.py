"""Diagnostics tests: status, link-check, config preview.

The mihomo client and the network probes are faked — no network is
used. The key property under test: a down mihomo degrades to clear
``running: false`` / per-probe errors, never a 500.
"""

import pytest
from fastapi.testclient import TestClient

from app import probes
from app.auth import hash_password
from app.deps import get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError
from app.probe_guard import reset_probe_guard

ADMIN_PASSWORD = "test-admin-password"


class FakeClient:
    def __init__(self, down=False):
        self.down = down

    def _maybe_down(self):
        if self.down:
            raise MihomoError(
                "cannot reach mihomo at http://127.0.0.1:9090: refused",
                connection_error=True,
            )

    def get_version(self):
        self._maybe_down()
        return {"version": "fake-1.0-test"}

    def get_connections(self):
        self._maybe_down()
        return {"connections": [{"id": "a"}, {"id": "b"}]}

    def get_traffic(self, timeout=5.0):
        self._maybe_down()
        return {"up": 1234, "down": 5678}

    def reload_config(self, force=True):
        self._maybe_down()

    def test_delay(self, proxy, url, timeout=5):
        self._maybe_down()
        return 42


@pytest.fixture
def fake_client():
    return FakeClient()


@pytest.fixture(autouse=True)
def _reset_probe_guard():
    # The probe guard is process-global (dedup cache + rate window);
    # reset it so each test starts unpolluted.
    reset_probe_guard()
    yield
    reset_probe_guard()


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


def test_status_requires_auth(client):
    assert client.get("/api/diagnostics/status").status_code == 401


def test_status_happy_path(client, auth_headers):
    body = client.get("/api/diagnostics/status", headers=auth_headers).json()
    assert body["mihomo"] == {
        "running": True, "version": "fake-1.0-test", "error": None,
    }
    assert body["connections"]["count"] == 2
    assert body["traffic"] == {"up": 1234, "down": 5678}
    assert body["config"]["exists"] is False  # no apply has run yet


def test_status_mihomo_down_degrades(client, auth_headers, fake_client):
    fake_client.down = True
    response = client.get("/api/diagnostics/status", headers=auth_headers)
    assert response.status_code == 200  # degradation, not a 500
    body = response.json()
    assert body["mihomo"]["running"] is False
    assert body["mihomo"]["version"] is None
    assert "cannot reach mihomo" in body["mihomo"]["error"]
    assert body["connections"]["count"] is None
    assert body["traffic"]["up"] is None


def _ok_probe(url, **kwargs):
    return {"url": url, "ok": True, "ttfb_ms": 42, "status": 200,
            "error": None, "elapsed_ms": 50}


def _failed_probe(url, **kwargs):
    return {"url": url, "ok": False, "ttfb_ms": None, "status": None,
            "error": "proxied request failed: [Errno 111] Connection refused",
            "elapsed_ms": 3}


def test_link_check_both_ok(client, auth_headers, monkeypatch):
    monkeypatch.setattr(probes, "probe_direct", _ok_probe)
    monkeypatch.setattr(probes, "probe_via_socks5", _ok_probe)
    body = client.post(
        "/api/diagnostics/link-check", headers=auth_headers
    ).json()
    assert body["direct"]["ok"] is True
    assert body["direct"]["url"] == "https://www.baidu.com"
    assert body["proxied"]["ok"] is True
    assert body["proxied"]["url"] == "https://www.youtube.com"


def test_link_check_mihomo_down(client, auth_headers, monkeypatch):
    monkeypatch.setattr(probes, "probe_direct", _ok_probe)
    monkeypatch.setattr(probes, "probe_via_socks5", _failed_probe)
    response = client.post(
        "/api/diagnostics/link-check", headers=auth_headers
    )
    assert response.status_code == 200  # degradation, not a 500
    body = response.json()
    assert body["direct"]["ok"] is True  # DIRECT probe is independent
    assert body["proxied"]["ok"] is False
    # L-17: the probe error is a sanitized category, never the raw
    # "[Errno 111] Connection refused" text.
    assert body["proxied"]["error"] == "connection_refused"
    assert "Connection refused" not in str(body)
    assert "Mixed listener" in body["proxied"]["hint"]


def test_link_check_probes_run_in_parallel(
    client, auth_headers, monkeypatch
):
    # L-45: the two probes run concurrently (asyncio gather), not
    # serially — two 1.5s probes finish in ~1.5s, not ~3s.
    import time

    def _slow_probe(url, **kwargs):
        time.sleep(1.5)
        return {"url": url, "ok": True, "ttfb_ms": 1500, "status": 200,
                "error": None, "elapsed_ms": 1500}

    monkeypatch.setattr(probes, "probe_direct", _slow_probe)
    monkeypatch.setattr(probes, "probe_via_socks5", _slow_probe)
    started = time.monotonic()
    body = client.post(
        "/api/diagnostics/link-check", headers=auth_headers
    ).json()
    elapsed = time.monotonic() - started
    assert body["direct"]["ok"] is True
    assert body["proxied"]["ok"] is True
    assert elapsed < 2.5, f"link-check took {elapsed:.2f}s (serial?)"


def test_link_check_dedup_reuses_result_within_5s(
    client, auth_headers, monkeypatch
):
    # M-31: the same target within 5s reuses the first result.
    calls = []

    def _counting_probe(url, **kwargs):
        calls.append(url)
        return _ok_probe(url, **kwargs)

    monkeypatch.setattr(probes, "probe_direct", _counting_probe)
    monkeypatch.setattr(probes, "probe_via_socks5", _counting_probe)
    first = client.post(
        "/api/diagnostics/link-check", headers=auth_headers
    ).json()
    assert first["cached"] is False
    second = client.post(
        "/api/diagnostics/link-check", headers=auth_headers
    ).json()
    assert second["cached"] is True
    assert second["direct"]["ok"] is True
    assert len(calls) == 2  # one direct + one proxied probe, once


def test_link_check_concurrency_cap_returns_429(
    client, auth_headers, app, monkeypatch
):
    # M-31: at most 2 probe tasks run at once; the third concurrent
    # link-check gets 429 instead of queueing behind slow probes.
    import asyncio
    import threading
    import time

    import httpx

    def _slow_probe(url, **kwargs):
        time.sleep(2.5)
        return {"url": url, "ok": True, "ttfb_ms": 2500, "status": 200,
                "error": None, "elapsed_ms": 2500}

    monkeypatch.setattr(probes, "probe_direct", _slow_probe)
    monkeypatch.setattr(probes, "probe_via_socks5", _slow_probe)
    barrier = threading.Barrier(3)
    statuses: list[int] = []

    async def _post_once():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as http_client:
            response = await http_client.post(
                "/api/diagnostics/link-check", headers=auth_headers
            )
            return response.status_code

    def _call():
        barrier.wait(timeout=10)
        statuses.append(asyncio.run(_post_once()))

    threads = [
        threading.Thread(target=_call) for _ in range(3)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert sorted(statuses) == [200, 200, 429]


def test_link_check_rate_limit_returns_429(
    client, auth_headers, monkeypatch
):
    # M-31: per-IP rate limit on probe endpoints.
    monkeypatch.setattr("app.probe_guard.PROBE_RATE_LIMIT", 3)
    monkeypatch.setattr(probes, "probe_direct", _ok_probe)
    monkeypatch.setattr(probes, "probe_via_socks5", _ok_probe)
    for _ in range(3):
        assert client.post(
            "/api/diagnostics/link-check", headers=auth_headers
        ).status_code == 200
    assert client.post(
        "/api/diagnostics/link-check", headers=auth_headers
    ).status_code == 429


def test_link_check_drift_annotated(client, auth_headers, app, monkeypatch):
    # M-13: a drifted config is annotated on the link-check result.
    monkeypatch.setattr(probes, "probe_direct", _ok_probe)
    monkeypatch.setattr(probes, "probe_via_socks5", _ok_probe)
    app.state.db.set_setting("config_revision_db", "4")
    app.state.db.set_setting("config_revision_running", "1")
    body = client.post(
        "/api/diagnostics/link-check", headers=auth_headers
    ).json()
    assert body["config_drift"] is True
    assert body["db_revision"] == 4
    assert body["running_revision"] == 1


def test_config_preview_missing(client, auth_headers):
    body = client.get(
        "/api/diagnostics/config-preview", headers=auth_headers
    ).json()
    assert body["exists"] is False
    assert body["config"] is None


def test_config_preview_masks_secrets(client, auth_headers, app):
    config_path = app.state.config_service.config_path
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "secret: fake-mihomo-secret\n"
        "listeners:\n"
        "  - {name: lan-ss, password: fake-ss-pass, port: 10001}\n"
        "proxies: []\n",
        encoding="utf-8",
    )
    body = client.get(
        "/api/diagnostics/config-preview", headers=auth_headers
    ).json()
    assert body["exists"] is True
    assert "fake-mihomo-secret" not in body["config"]
    assert "fake-ss-pass" not in body["config"]
    # L-23: long secrets keep first/last 2 chars, middle masked.
    assert "****" in body["config"]
    assert "10001" in body["config"]
