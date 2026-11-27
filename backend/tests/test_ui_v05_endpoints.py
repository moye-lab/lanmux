"""Tests for v0.5.0 UI support endpoints: batch-action and manual reapply."""

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.deps import get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError

ADMIN_PASSWORD = "test-admin-password"
SAMPLE_URI_1 = "ss://YWVzLTEyOC1nY206cGFzczE=@1.1.1.1:8388#Node-One"
SAMPLE_URI_2 = "ss://YWVzLTEyOC1nY206cGFzczI=@2.2.2.2:8388#Node-Two"


class FakeClient:
    def __init__(self, down=False):
        self.down = down
        self.reloads = 0

    def reload_config(self, force=True):
        if self.down:
            raise MihomoError("mihomo unreachable", connection_error=True)
        self.reloads += 1


@pytest.fixture
def fake_client():
    return FakeClient()


@pytest.fixture
def app(tmp_path, fake_client):
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    db = app.state.db
    db.set_setting("admin_password_hash", hash_password(ADMIN_PASSWORD))
    db.set_setting("ss_password", "lan-ss-pass")
    db.set_setting("mihomo_secret", "lan-secret")
    app.state.config_service._client_factory = lambda: fake_client
    app.dependency_overrides[get_mihomo_client] = lambda: fake_client
    return app


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers(client):
    res = client.post("/api/auth/login", json={"password": ADMIN_PASSWORD})
    assert res.status_code == 200
    return {"Authorization": f"Bearer {res.json()['token']}"}


def test_batch_action_requires_auth(client):
    res = client.post(
        "/api/nodes/batch-action", json={"action": "disable", "ids": [1]}
    )
    assert res.status_code == 401


def test_batch_action_empty_ids_rejected(client, auth_headers):
    res = client.post(
        "/api/nodes/batch-action",
        headers=auth_headers,
        json={"action": "disable", "ids": []},
    )
    assert res.status_code == 400


def test_batch_action_disable_enable_delete_single_reload(
    client, auth_headers, fake_client
):
    n1 = client.post(
        "/api/nodes", headers=auth_headers, json={"uri": SAMPLE_URI_1}
    ).json()["node"]["id"]
    n2 = client.post(
        "/api/nodes", headers=auth_headers, json={"uri": SAMPLE_URI_2}
    ).json()["node"]["id"]
    # Bind Default first: since the H-04 gate, an apply with nodes in
    # the library but Default unbound is refused, and this test needs
    # the batch actions' applies to reach the reload stage. (Disabling
    # both nodes below then leaves Default bound-but-dead -> REJECT,
    # which still applies fine.)
    res = client.put(
        "/api/rules/bindings/default",
        headers=auth_headers,
        json={"main": n1, "backups": [n2], "mode": "fallback"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["reload"]["ok"] is True
    reloads_before = fake_client.reloads

    # Disable both in one reload
    res = client.post(
        "/api/nodes/batch-action",
        headers=auth_headers,
        json={"action": "disable", "ids": [n1, n2, 9999]},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["affected"] == 2
    assert body["reload"]["ok"] is True
    assert fake_client.reloads == reloads_before + 1
    nodes = client.get("/api/nodes", headers=auth_headers).json()
    assert all(not n["enabled"] for n in nodes)

    # Re-enable both
    res = client.post(
        "/api/nodes/batch-action",
        headers=auth_headers,
        json={"action": "enable", "ids": [n1, n2]},
    )
    assert res.status_code == 200
    assert res.json()["affected"] == 2
    nodes = client.get("/api/nodes", headers=auth_headers).json()
    assert all(n["enabled"] for n in nodes)

    # Delete both
    res = client.post(
        "/api/nodes/batch-action",
        headers=auth_headers,
        json={"action": "delete", "ids": [n1, n2]},
    )
    assert res.status_code == 200
    assert res.json()["affected"] == 2
    assert client.get("/api/nodes", headers=auth_headers).json() == []


def test_diagnostics_reapply_requires_auth(client):
    assert client.post("/api/diagnostics/reapply").status_code == 401


def test_diagnostics_reapply_ok_and_failure(client, auth_headers, fake_client):
    res = client.post("/api/diagnostics/reapply", headers=auth_headers)
    assert res.status_code == 200, res.text
    assert res.json()["reload"]["ok"] is True

    fake_client.down = True
    res = client.post("/api/diagnostics/reapply", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["reload"]["ok"] is False
    assert res.json()["reload"]["stage"] == "reload"
