"""Version info tests: /health stamp and /api/version.

``/health`` is public and must stay light (no controller call); it
carries the build-time stamp from the environment. ``/api/version``
needs auth and adds the live mihomo version, degrading to
``mihomo_version: null`` + ``error`` (never a 500) when the
controller is down. The mihomo client is faked — no network is used.
"""

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.deps import get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError

ADMIN_PASSWORD = "test-admin-password"


class FakeClient:
    def __init__(self, down=False):
        self.down = down

    def get_version(self):
        if self.down:
            raise MihomoError(
                "cannot reach mihomo at http://127.0.0.1:9090: refused",
                connection_error=True,
            )
        return {"version": "1.19.34"}


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
def no_version_env(monkeypatch):
    """Ensure no version env vars leak in from the test environment."""
    for name in ("LANMUX_VERSION", "LANMUX_COMMIT", "LANMUX_BUILD_TIME"):
        monkeypatch.delenv(name, raising=False)


def test_health_includes_version_defaults(client, no_version_env):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["phase"] == 4
    assert body["version"] == "1.0.2"
    assert body["commit"] == "unknown"
    assert body["build_time"] == "unknown"


def test_health_reflects_env_vars(client, monkeypatch):
    monkeypatch.setenv("LANMUX_VERSION", "9.9.9")
    monkeypatch.setenv("LANMUX_COMMIT", "abc123def456")
    monkeypatch.setenv("LANMUX_BUILD_TIME", "2026-11-26T12:00:00Z")
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["phase"] == 4
    assert body["version"] == "9.9.9"
    assert body["commit"] == "abc123def456"
    assert body["build_time"] == "2026-11-26T12:00:00Z"


def test_version_requires_auth(client):
    assert client.get("/api/version").status_code == 401


def test_version_happy_path(client, auth_headers, no_version_env):
    body = client.get("/api/version", headers=auth_headers).json()
    assert body["version"] == "1.0.2"
    assert body["commit"] == "unknown"
    assert body["build_time"] == "unknown"
    assert body["mihomo_version"] == "1.19.34"
    assert "error" not in body


def test_version_mihomo_down_degrades(
    client, auth_headers, fake_client, no_version_env
):
    fake_client.down = True
    response = client.get("/api/version", headers=auth_headers)
    assert response.status_code == 200  # degradation, not a 500
    body = response.json()
    assert body["version"] == "1.0.2"
    assert body["commit"] == "unknown"
    assert body["build_time"] == "unknown"
    assert body["mihomo_version"] is None
    assert "cannot reach mihomo" in body["error"]
