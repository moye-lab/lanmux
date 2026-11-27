"""Node failure-reason tests: ``last_error`` storage + migration.

A failed speedtest stores a sanitized one-line reason on the node row
(no URI / password / UUID may survive); a successful probe clears it.
The column is added by migration to pre-existing databases.
"""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.database import Database
from app.deps import get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError

ADMIN_PASSWORD = "test-admin-password"

SS_PROXY = {
    "type": "ss", "server": "1.2.3.4", "port": 8388,
    "password": "pw", "cipher": "aes-128-gcm",
}


class FakeClient:
    def __init__(self):
        self.fail_names = set()
        self.fail_message = "mihomo API error (GET /proxies/X/delay): timeout"
        self.delay_ms = 42

    def test_delay(self, proxy, url, timeout=5):
        if proxy in self.fail_names:
            raise MihomoError(self.fail_message, status=408)
        return self.delay_ms

    def get_version(self):
        return {"version": "fake-1.0-test"}

    def reload_config(self, force=True):
        pass


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
def node_id(app):
    return app.state.db.add_node("Node-A", "ss://fake-a", dict(SS_PROXY))


def _get_node(client, auth_headers, node_id):
    return client.get(
        f"/api/nodes/{node_id}", headers=auth_headers
    ).json()


def test_speedtest_failure_stores_reason(
    client, auth_headers, node_id, fake_client
):
    fake_client.fail_names = {"Node-A"}
    body = client.post(
        f"/api/nodes/{node_id}/speedtest", headers=auth_headers
    ).json()
    assert body["online"] is False
    node = _get_node(client, auth_headers, node_id)
    assert node["last_online"] is False
    assert node["last_error"] is not None
    assert "timeout" in node["last_error"]


def test_speedtest_failure_redacts_urls(
    client, auth_headers, node_id, fake_client
):
    fake_client.fail_names = {"Node-A"}
    fake_client.fail_message = (
        "cannot reach mihomo at http://127.0.0.1:9090: refused"
    )
    client.post(f"/api/nodes/{node_id}/speedtest", headers=auth_headers)
    node = _get_node(client, auth_headers, node_id)
    assert "http://" not in node["last_error"]
    assert "[url]" in node["last_error"]


def test_speedtest_success_clears_reason(
    client, auth_headers, node_id, fake_client
):
    fake_client.fail_names = {"Node-A"}
    client.post(f"/api/nodes/{node_id}/speedtest", headers=auth_headers)
    assert _get_node(client, auth_headers, node_id)["last_error"]
    fake_client.fail_names = set()
    body = client.post(
        f"/api/nodes/{node_id}/speedtest", headers=auth_headers
    ).json()
    assert body["online"] is True
    node = _get_node(client, auth_headers, node_id)
    assert node["last_online"] is True
    assert node["last_delay_ms"] == 42
    assert node["last_error"] is None


def test_speedtest_all_stores_per_node_reasons(
    client, auth_headers, app, fake_client
):
    bad = app.state.db.add_node("Bad-Node", "ss://fake-bad", dict(SS_PROXY))
    good = app.state.db.add_node(
        "Good-Node", "ss://fake-good", dict(SS_PROXY)
    )
    fake_client.fail_names = {"Bad-Node"}
    body = client.post(
        "/api/nodes/speedtest-all", headers=auth_headers
    ).json()
    assert body["tested"] == 2
    assert _get_node(client, auth_headers, bad)["last_error"] is not None
    assert _get_node(client, auth_headers, good)["last_error"] is None


def test_migration_adds_last_error_column(tmp_path):
    """A database created before v0.9.2 gains the column on open."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(str(path))
    conn.executescript(
        "CREATE TABLE nodes ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT NOT NULL, uri TEXT NOT NULL,"
        " proxy_json TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL DEFAULT (datetime('now')),"
        " last_delay_ms INTEGER, last_delay_at TEXT, last_online INTEGER"
        ");"
    )
    conn.commit()
    conn.close()
    db = Database(path)
    columns = {row[1] for row in db.conn.execute("PRAGMA table_info(nodes)")}
    assert "last_error" in columns
    node_id = db.add_node("N", "ss://x", {"type": "ss"})
    db.update_node(node_id, last_error="timeout")
    assert db.get_node(node_id)["last_error"] == "timeout"
    db.close()
