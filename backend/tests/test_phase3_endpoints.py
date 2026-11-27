"""Phase 3 endpoint tests: first-run setup + ss-link + SPA serving.

* ``POST /api/auth/setup`` sets the admin password ONLY when none is
  configured, then returns a token like login; it refuses with 403
  once a password exists.
* ``GET /api/settings/ss-link`` (authenticated) builds the ``ss://``
  URL for the LAN total node from settings.
* ``GET /`` serves the single-file frontend console.
"""

import base64

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.main import create_app

ADMIN_PASSWORD = "test-admin-password"
SETUP_PASSWORD = "brand-new-admin-pass"


@pytest.fixture
def app(tmp_path):
    # No ADMIN_PASSWORD in the environment (conftest pops it), so the
    # app starts with no admin password configured.
    return create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def _set_admin(app, password=ADMIN_PASSWORD):
    app.state.db.set_setting("admin_password_hash", hash_password(password))


def _login(client, password=ADMIN_PASSWORD):
    response = client.post("/api/auth/login", json={"password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


# -------------------------------------------------------------------- setup
def test_setup_sets_password_and_logs_in(app, client):
    assert client.get("/api/auth/status").json()["admin_configured"] is False
    response = client.post(
        "/api/auth/setup",
        json={
            "password": SETUP_PASSWORD,
            "setup_token": app.state.setup_token,
        },
    )
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    assert token
    # The returned token works immediately.
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/settings", headers=headers).status_code == 200
    # Status now reports configured, and login accepts the new password.
    assert client.get("/api/auth/status").json()["admin_configured"] is True
    assert _login(client, SETUP_PASSWORD)


def test_setup_refuses_when_already_configured(app, client):
    _set_admin(app)
    response = client.post(
        "/api/auth/setup", json={"password": "attacker-password"}
    )
    assert response.status_code == 403, response.text
    # The original password is untouched.
    assert _login(client, ADMIN_PASSWORD)


def test_setup_rejects_short_password(app, client):
    response = client.post(
        "/api/auth/setup",
        json={"password": "short", "setup_token": app.state.setup_token},
    )
    assert response.status_code == 400, response.text
    assert client.get("/api/auth/status").json()["admin_configured"] is False


# ------------------------------------------------------------------ ss-link
def _seed_ss_settings(app):
    db = app.state.db
    db.set_setting("lan_ip", "10.0.0.2")
    db.set_setting("ss_port", 10001)
    db.set_setting("ss_cipher", "aes-128-gcm")
    db.set_setting("ss_password", "s3cret-pw")


def test_ss_link_requires_auth(client):
    assert client.get("/api/settings/ss-link").status_code == 401


def test_ss_link_returns_valid_url(app, client):
    _set_admin(app)
    _seed_ss_settings(app)
    response = client.get("/api/settings/ss-link", headers=_login(client))
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["host"] == "10.0.0.2"
    assert data["port"] == 10001
    assert data["cipher"] == "aes-128-gcm"
    assert data["password_set"] is True
    assert data["tag"] == "LanMux-Core"
    # The password is only inside the URL itself, never a bare field.
    assert "password" not in data
    assert "ss_password" not in data
    # The URL decodes to cipher:password@host:port (SIP002-style
    # full-base64url form) and round-trips through our own parser.
    url = data["url"]
    assert url.startswith("ss://")
    payload, _, tag = url[len("ss://"):].partition("#")
    assert tag == "LanMux-Core"
    padded = payload + "=" * (-len(payload) % 4)
    decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
    assert decoded == "aes-128-gcm:s3cret-pw@10.0.0.2:10001"
    from app.uri_parser import parse_uri

    proxy = parse_uri(url)
    assert proxy["type"] == "ss"
    assert proxy["server"] == "10.0.0.2"
    assert proxy["port"] == 10001
    assert proxy["cipher"] == "aes-128-gcm"
    assert proxy["password"] == "s3cret-pw"


def test_ss_link_requires_ss_password(app, client):
    _set_admin(app)
    # lan_ip/port/cipher are set, but no ss_password.
    app.state.db.set_setting("lan_ip", "10.0.0.2")
    response = client.get("/api/settings/ss-link", headers=_login(client))
    assert response.status_code == 400, response.text


# ------------------------------------------------------- frontend + version
def test_frontend_serves_spa(client):
    response = client.get("/")
    assert response.status_code == 200, response.text
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "总节点" in html
    assert "节点管理" in html
    assert "业务分流" in html
    assert "x-data" in html
    # The QR generator is vendored inline (works without internet).
    assert "QR Code Generator for JavaScript" in html
    assert "qrcode-generator" in html.lower() or "Kazuhiko Arase" in html


def test_health_reports_phase_4(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["phase"] == 4
    assert body["version"] == "1.0.2"
    assert body["commit"] == "unknown"
    assert body["build_time"] == "unknown"
