"""Config revision / drift state tests (P1-1 + P1-2).

Pins the revision model in :mod:`app.config_service` and the
``config`` object of ``GET /api/diagnostics/status``:

* a successful apply bumps ``config_revision_db`` by 1 and the
  running revision catches up (``state="running"``, no drift);
* a reload failure bumps NEITHER revision (M-26: the revision only
  moves after write + reload success) but sets the explicit
  ``config_drift_flag`` and stage ``failed`` — the status endpoint
  still reports ``state="drift"``, ``drift=True`` from the flag,
  and the DB change is kept;
* a reload failure caused by an unreachable controller sets
  ``controller_unreachable`` instead of drift (L-29);
* a later successful apply (reapply) clears the drift flag and
  bumps both revisions;
* a compile failure bumps nothing and reports stage ``compile``.

The mihomo client is faked (no network, no mihomo binary); the
apply pipeline and the HTTP status endpoint are the real ones.
"""

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.config_service import ConfigApplyError, ConfigService
from app.database import Database
from app.deps import get_config_service, get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError

ADMIN_PASSWORD = "test-admin-password"


class FakeClient:
    """Records reload calls; ``fail_times=N`` fails the next N reloads."""

    def __init__(self, fail=False):
        self.fail = fail
        self.fail_times = 0
        self.reload_calls = 0

    def reload_config(self, force=True):
        self.reload_calls += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise MihomoError(
                "mihomo API error (PUT /configs): bad config", status=400
            )
        if self.fail:
            raise MihomoError(
                "cannot reach mihomo at http://127.0.0.1:9090: refused",
                connection_error=True,
            )

    # -- used by GET /api/diagnostics/status -------------------------
    def get_version(self):
        return {"version": "fake-1.0-test"}

    def get_connections(self):
        return {"connections": []}

    def get_traffic(self, timeout=5.0):
        return {"up": 0, "down": 0}


def _proxy(name):
    return {
        "name": name,
        "type": "ss",
        "server": "example.com",
        "port": 8388,
        "cipher": "aes-128-gcm",
        "password": "fake-pass",
    }


def _rev(db, key):
    return int(db.get_setting(key, "0") or "0")


def _add_node_with_binding(db):
    node_id = db.add_node(
        "NodeOne", "ss://fake@example.com:8388", _proxy("NodeOne")
    )
    db.set_binding("youtube", node_id, role="main")
    # Default must be bound too: since the H-04 gate, an apply with
    # nodes in the library but Default unbound is refused at compile
    # stage, and these drift tests need to reach the reload stage.
    db.set_binding("default", node_id, role="main")
    return node_id


# ------------------------------------------------------------ service-level
@pytest.fixture
def db(tmp_path):
    handle = Database(tmp_path / "lanmux.db")
    handle.set_setting("ss_password", "fake-ss-pass")
    handle.set_setting("mihomo_secret", "fake-mihomo-secret")
    yield handle
    handle.close()


@pytest.fixture
def service(db, tmp_path):
    client = FakeClient()
    handle = ConfigService(
        db, tmp_path / "mihomo" / "config.yaml", lambda: client
    )
    handle._fake_client = client  # test handle, not production API
    return handle


def test_success_apply_bumps_both_revisions(service, db):
    assert _rev(db, "config_revision_db") == 0
    assert _rev(db, "config_revision_running") == 0
    service.apply()
    assert _rev(db, "config_revision_db") == 1
    assert _rev(db, "config_revision_running") == 1
    assert db.get_setting("last_apply_stage") == "running"
    assert db.get_setting("last_apply_ok") == "1"
    service.apply()
    assert _rev(db, "config_revision_db") == 2
    assert _rev(db, "config_revision_running") == 2
    assert db.get_setting("last_apply_stage") == "running"


def _drift(service, db):
    """One good apply, then a DB change whose reload fails once.

    Returns ``(node_id, good_text)`` — the node added before the
    failed apply and the live config text from the good apply.
    """
    service.apply()
    good_text = service.config_path.read_text(encoding="utf-8")
    node_id = _add_node_with_binding(db)
    db.set_setting("ss_port", 10002)
    service._fake_client.fail_times = 1
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.stage == "reload"
    return node_id, good_text


def test_reload_failure_drifts_but_keeps_db_changes(service, db):
    node_id, good_text = _drift(service, db)
    # M-26: a failed apply bumps NEITHER revision — the generation
    # only moves after write + reload success. Drift is recorded
    # explicitly instead (config_drift_flag + stage "failed").
    assert _rev(db, "config_revision_db") == 1
    assert _rev(db, "config_revision_running") == 1
    assert db.get_setting("config_drift_flag") == "1"
    assert db.get_setting("last_apply_stage") == "failed"
    assert db.get_setting("last_apply_ok") == "0"
    # The live file was rolled back, but the DB change was NOT lost:
    # the node, its binding and the changed setting are all still there.
    assert service.config_path.read_text(encoding="utf-8") == good_text
    assert db.get_node(node_id) is not None
    assert db.get_node(node_id)["name"] == "NodeOne"
    assert db.list_bindings("youtube")[0]["node_id"] == node_id
    assert db.get_setting("ss_port") == "10002"


def test_reapply_clears_drift(service, db):
    _drift(service, db)
    assert _rev(db, "config_revision_db") == 1
    assert _rev(db, "config_revision_running") == 1
    assert db.get_setting("config_drift_flag") == "1"
    service.apply()  # reapply: a fresh generation, reload now succeeds
    assert _rev(db, "config_revision_db") == 2
    assert _rev(db, "config_revision_running") == 2
    assert db.get_setting("config_drift_flag") == "0"
    assert db.get_setting("last_apply_stage") == "running"
    assert db.get_setting("last_apply_ok") == "1"


def test_compile_failure_does_not_bump_revision(service, db):
    # Fresh DB: no generation exists yet.
    db.set_setting("mihomo_secret", "")  # required secret unset
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.stage == "compile"
    assert _rev(db, "config_revision_db") == 0
    assert _rev(db, "config_revision_running") == 0
    assert db.get_setting("last_apply_stage") == "compile"
    assert db.get_setting("last_apply_ok") == "0"
    assert not service.config_path.exists()
    assert service._fake_client.reload_calls == 0

    # Same after a successful apply: the revision stays where it was.
    db.set_setting("mihomo_secret", "fake-mihomo-secret")
    service.apply()
    assert _rev(db, "config_revision_db") == 1
    assert _rev(db, "config_revision_running") == 1
    db.set_setting("mihomo_secret", "")
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.stage == "compile"
    assert _rev(db, "config_revision_db") == 1
    assert _rev(db, "config_revision_running") == 1
    assert db.get_setting("last_apply_stage") == "compile"


# ------------------------------------------------------------ HTTP /status
@pytest.fixture
def http_app(tmp_path):
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    app.state.db.set_setting(
        "admin_password_hash", hash_password(ADMIN_PASSWORD)
    )
    app.state.db.set_setting("ss_password", "fake-ss-pass")
    app.state.db.set_setting("mihomo_secret", "fake-mihomo-secret")
    client = FakeClient()
    real_service = ConfigService(
        app.state.db,
        app.state.config_service.config_path,
        lambda: client,
    )
    real_service._fake_client = client
    app.state.config_service = real_service
    app.dependency_overrides[get_config_service] = lambda: real_service
    app.dependency_overrides[get_mihomo_client] = lambda: client
    return app


@pytest.fixture
def http_client(http_app):
    with TestClient(http_app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers(http_client):
    response = http_client.post(
        "/api/auth/login", json={"password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _status(http_client, auth_headers):
    response = http_client.get(
        "/api/diagnostics/status", headers=auth_headers
    )
    assert response.status_code == 200, response.text
    return response.json()["config"]


def test_status_initial_state(http_client, auth_headers):
    config = _status(http_client, auth_headers)
    assert config["db_revision"] == 0
    assert config["running_revision"] == 0
    assert config["drift"] is False
    assert config["state"] == "running"
    assert config["in_sync"] is True
    assert config["last_apply_stage"] == ""
    assert config["exists"] is False


def test_status_running_after_success(http_client, auth_headers, http_app):
    http_app.state.config_service.apply()
    config = _status(http_client, auth_headers)
    assert config == {
        **config,  # keeps last_apply_at / last_apply_error keys present
        "db_revision": 1,
        "running_revision": 1,
        "drift": False,
        "state": "running",
        "in_sync": True,
        "last_apply_stage": "running",
        "exists": True,
        "last_apply_error": None,
    }
    assert config["last_apply_at"] is not None


def test_status_drift_then_reapply_clears(http_client, auth_headers, http_app):
    service = http_app.state.config_service
    db = http_app.state.db
    service.apply()
    _add_node_with_binding(db)
    db.set_setting("ss_port", 10002)
    service._fake_client.fail_times = 1
    with pytest.raises(ConfigApplyError):
        service.apply()

    config = _status(http_client, auth_headers)
    # Revision did not move (failed apply bumps nothing), but the
    # explicit drift flag still reports drift.
    assert config["db_revision"] == 1
    assert config["running_revision"] == 1
    assert config["drift"] is True
    assert config["drift_flag"] is True
    assert config["state"] == "drift"
    assert config["in_sync"] is False
    assert config["last_apply_stage"] == "failed"
    assert config["last_apply_error"] is not None
    assert config["source"] == "database"
    assert config["freshness"] == "stale"
    assert "未应用" in config["note"]
    # The DB change survived the failed apply (visible via the API).
    nodes = http_client.get("/api/nodes", headers=auth_headers).json()
    assert [n["name"] for n in nodes] == ["NodeOne"]

    body = http_client.post(
        "/api/diagnostics/reapply", headers=auth_headers
    ).json()
    assert body["reload"]["ok"] is True

    config = _status(http_client, auth_headers)
    assert config["db_revision"] == 2
    assert config["running_revision"] == 2
    assert config["drift"] is False
    assert config["state"] == "running"
    assert config["in_sync"] is True
    assert config["freshness"] == "current"
    assert config["last_apply_stage"] == "running"
