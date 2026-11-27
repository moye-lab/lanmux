"""Node health counters: ``failure_count`` / ``consecutive_failures``.

A failed speedtest increments both counters; a success clears the
consecutive streak but keeps the cumulative count. The columns are
added by migration to pre-existing databases, and ``NodeOut``
exposes them.
"""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.database import Database
from app.deps import get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError
from app.probe_guard import reset_probe_guard

ADMIN_PASSWORD = "test-admin-password"

SS_PROXY = {
    "type": "ss", "server": "1.2.3.4", "port": 8388,
    "password": "pw", "cipher": "aes-128-gcm",
}


class FakeClient:
    def __init__(self):
        self.fail_names = set()
        self.delay_ms = 42

    def test_delay(self, proxy, url, timeout=5):
        if proxy in self.fail_names:
            raise MihomoError(
                "mihomo API error (GET /proxies/X/delay): timeout",
                status=408,
            )
        return self.delay_ms

    def get_version(self):
        return {"version": "fake-1.0-test"}

    def reload_config(self, force=True):
        pass


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


@pytest.fixture
def node_id(app):
    return app.state.db.add_node("Node-A", "ss://fake-a", dict(SS_PROXY))


def _get_node(client, auth_headers, node_id):
    return client.get(
        f"/api/nodes/{node_id}", headers=auth_headers
    ).json()


def _speedtest(client, auth_headers, node_id):
    return client.post(
        f"/api/nodes/{node_id}/speedtest", headers=auth_headers
    )


def test_node_out_includes_new_fields(client, auth_headers, node_id):
    node = _get_node(client, auth_headers, node_id)
    assert node["failure_count"] == 0
    assert node["consecutive_failures"] == 0
    # The pre-existing health fields are still there alongside.
    assert node["last_online"] is None
    assert node["last_delay_ms"] is None
    assert node["last_error"] is None


def test_failure_increments_both_counters(
    client, auth_headers, node_id, fake_client
):
    fake_client.fail_names = {"Node-A"}
    assert _speedtest(client, auth_headers, node_id).json()["online"] is False
    node = _get_node(client, auth_headers, node_id)
    assert node["failure_count"] == 1
    assert node["consecutive_failures"] == 1
    assert _speedtest(client, auth_headers, node_id).json()["online"] is False
    node = _get_node(client, auth_headers, node_id)
    assert node["failure_count"] == 2
    assert node["consecutive_failures"] == 2


def test_success_clears_consecutive_but_keeps_cumulative(
    client, auth_headers, node_id, fake_client
):
    fake_client.fail_names = {"Node-A"}
    _speedtest(client, auth_headers, node_id)
    _speedtest(client, auth_headers, node_id)
    node = _get_node(client, auth_headers, node_id)
    assert (node["failure_count"], node["consecutive_failures"]) == (2, 2)
    fake_client.fail_names = set()
    assert _speedtest(client, auth_headers, node_id).json()["online"] is True
    node = _get_node(client, auth_headers, node_id)
    assert node["failure_count"] == 2  # cumulative history is kept
    assert node["consecutive_failures"] == 0
    assert node["last_online"] is True
    # A later failure starts a fresh streak from the kept total.
    fake_client.fail_names = {"Node-A"}
    _speedtest(client, auth_headers, node_id)
    node = _get_node(client, auth_headers, node_id)
    assert (node["failure_count"], node["consecutive_failures"]) == (3, 1)


def test_speedtest_all_counts_per_node(
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
    bad_node = _get_node(client, auth_headers, bad)
    assert (bad_node["failure_count"], bad_node["consecutive_failures"]) == (1, 1)
    good_node = _get_node(client, auth_headers, good)
    assert (good_node["failure_count"], good_node["consecutive_failures"]) == (0, 0)


def test_disabled_node_speedtest_does_not_count(
    client, auth_headers, node_id, app
):
    app.state.db.update_node(node_id, enabled=False)
    _speedtest(client, auth_headers, node_id)
    node = _get_node(client, auth_headers, node_id)
    assert (node["failure_count"], node["consecutive_failures"]) == (0, 0)


def test_speedtest_concurrency_cap_returns_429(
    client, auth_headers, app, node_id, fake_client, monkeypatch
):
    # M-31: at most 2 concurrent speedtest requests; the third
    # concurrent one gets 429 instead of queueing. (Results are
    # deliberately NOT deduped: each run updates the health
    # counters, so a cached result would falsify them.)
    import asyncio
    import threading
    import time

    import httpx

    def _slow_delay(proxy, url, timeout=5):
        time.sleep(2.5)
        return 42

    monkeypatch.setattr(fake_client, "test_delay", _slow_delay)
    barrier = threading.Barrier(3)
    statuses: list[int] = []

    async def _post_once():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as http_client:
            response = await http_client.post(
                f"/api/nodes/{node_id}/speedtest", headers=auth_headers
            )
            return response.status_code

    def _call():
        barrier.wait(timeout=10)
        statuses.append(asyncio.run(_post_once()))

    threads = [threading.Thread(target=_call) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert sorted(statuses) == [200, 200, 429]


def test_migration_adds_failure_columns(tmp_path):
    """A database created before this change gains both columns on open."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(str(path))
    conn.executescript(
        "CREATE TABLE nodes ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT NOT NULL, uri TEXT NOT NULL,"
        " proxy_json TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL DEFAULT (datetime('now')),"
        " last_delay_ms INTEGER, last_delay_at TEXT, last_online INTEGER,"
        " last_error TEXT"
        ");"
    )
    conn.commit()
    conn.close()
    db = Database(path)
    columns = {row[1] for row in db.conn.execute("PRAGMA table_info(nodes)")}
    assert "failure_count" in columns
    assert "consecutive_failures" in columns
    node_id = db.add_node("N", "ss://x", {"type": "ss"})
    node = db.get_node(node_id)
    assert node["failure_count"] == 0
    assert node["consecutive_failures"] == 0
    db.update_node(node_id, failure_count=3, consecutive_failures=2)
    node = db.get_node(node_id)
    assert (node["failure_count"], node["consecutive_failures"]) == (3, 2)
    db.close()
