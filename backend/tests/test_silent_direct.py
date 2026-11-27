"""Silent-DIRECT cluster tests (H-03 + H-04).

Fail-closed rules under test:

* H-03 — a group WITH binding rows whose nodes are all disabled or
  deleted compiles to ``REJECT``, never to a silent ``DIRECT``. A
  group that was never bound keeps the design-default ``DIRECT``.
* H-04 — with nodes in the library but Default never bound, applying
  is refused with guidance to bind Default first. A library with
  zero nodes may still generate its first config (DIRECT everywhere).
* DNS fallback (``#Default``) is only emitted while Default has a
  live node; otherwise the fallback query would go out direct.
* The panel surfaces both states (``dead_groups`` /
  ``default_unbound`` in ``GET /api/diagnostics/status`` + warning
  markers in ``frontend/index.html``) and route diagnosis agrees
  with the compiled config (dead group -> ``REJECT``).

All fixtures use fake secrets and example.com hosts; the mihomo
client is faked (no network, no mihomo binary).
"""

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.config_builder import (
    build_config,
    dead_group_keys,
    default_apply_gate,
    default_unbound_with_nodes,
)
from app.config_service import ConfigApplyError, ConfigService
from app.database import Database
from app.deps import get_config_service, get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError

ADMIN_PASSWORD = "test-admin-password"
FRONTEND_HTML = Path(__file__).resolve().parents[2] / "frontend" / "index.html"

SETTINGS = {
    "lan_ip": "10.0.0.2",
    "ss_port": 10001,
    "ss_cipher": "aes-128-gcm",
    "ss_password": "fake-ss-password",
    "mixed_port": 7890,
    "mihomo_secret": "fake-mihomo-secret",
    "controller_port": 9090,
}


def _node(node_id, name, enabled=True):
    return {
        "id": node_id,
        "name": name,
        "uri": f"ss://fake-{node_id}@example.com:8388",
        "proxy": {
            "name": name,
            "type": "ss",
            "server": "example.com",
            "port": 8388,
            "cipher": "aes-128-gcm",
            "password": f"fake-pass-{node_id}",
        },
        "enabled": enabled,
    }


def _binding(group_key, node_id, role="backup", mode="fallback"):
    return {
        "group_key": group_key,
        "node_id": node_id,
        "role": role,
        "mode": mode,
    }


def _groups(config):
    return {g["name"]: g for g in config["proxy-groups"]}


# ------------------------------------------------------------- H-03 builder
def test_bound_group_all_nodes_disabled_generates_reject():
    """Every bound node disabled -> REJECT, not a silent DIRECT."""
    nodes = [_node(1, "Node-A", enabled=False), _node(2, "Node-B", enabled=False)]
    bindings = [
        _binding("youtube", 1, role="main"),
        _binding("youtube", 2, role="backup"),
    ]
    config = build_config(nodes, bindings, [], SETTINGS)
    assert _groups(config)["YouTube"]["proxies"] == ["REJECT"]


def test_bound_group_with_only_deleted_nodes_generates_reject():
    """Bindings dangling at deleted node ids -> REJECT as well."""
    nodes = [_node(1, "Node-A")]
    bindings = [
        _binding("youtube", 99, role="main"),
        _binding("youtube", 100, role="backup"),
    ]
    config = build_config(nodes, bindings, [], SETTINGS)
    assert _groups(config)["YouTube"]["proxies"] == ["REJECT"]


def test_bound_group_with_live_backup_stays_proxied():
    """Dead means ALL bound nodes are unusable: a live backup keeps
    the group proxied (and the dead main is skipped)."""
    nodes = [_node(1, "Node-A", enabled=False), _node(2, "Node-B")]
    bindings = [
        _binding("youtube", 1, role="main"),
        _binding("youtube", 2, role="backup"),
    ]
    config = build_config(nodes, bindings, [], SETTINGS)
    assert _groups(config)["YouTube"]["proxies"] == ["Node-B"]


def test_never_bound_group_still_direct_and_differs_from_dead():
    """The H-03 byte-identity property, inverted: a dead group and a
    never-bound group must NOT compile the same way anymore."""
    nodes = [_node(1, "Node-A", enabled=False), _node(2, "Node-B")]
    bindings = [_binding("youtube", 1, role="main")]
    config = build_config(nodes, bindings, [], SETTINGS)
    groups = _groups(config)
    assert groups["YouTube"]["proxies"] == ["REJECT"]  # bound, dead
    assert groups["Apple"]["proxies"] == ["DIRECT"]  # never bound
    assert groups["YouTube"]["proxies"] != groups["Apple"]["proxies"]


def test_dead_group_keys_lists_only_bound_dead_groups():
    nodes = [_node(1, "Node-A", enabled=False), _node(2, "Node-B")]
    bindings = [
        _binding("youtube", 1, role="main"),  # dead
        _binding("telegram", 2, role="main"),  # live
        # apple: never bound -> not dead
    ]
    assert dead_group_keys(nodes, bindings) == ["youtube"]


def test_build_config_logs_dead_groups(caplog):
    nodes = [_node(1, "Node-A", enabled=False)]
    bindings = [_binding("youtube", 1, role="main")]
    with caplog.at_level(logging.WARNING, logger="app.config_builder"):
        build_config(nodes, bindings, [], SETTINGS)
    assert "YouTube" in caplog.text
    assert "REJECT" in caplog.text


# ------------------------------------------------------- H-04 DNS fallback
def test_dns_fallback_omitted_when_default_dead():
    """Default bound, but its only node is disabled: no fallback key
    at all — a fallback through a REJECT group would fail every
    query, and through DIRECT it would leak DNS direct."""
    nodes = [_node(1, "Node-A", enabled=False)]
    bindings = [_binding("default", 1, role="main")]
    config = build_config(nodes, bindings, [], SETTINGS)
    assert _groups(config)["Default"]["proxies"] == ["REJECT"]
    assert "fallback" not in config["dns"]


def test_dns_fallback_omitted_when_default_unbound_with_nodes():
    """Nodes exist but Default was never bound: the fallback would
    ride a DIRECT Default straight out — omit it."""
    nodes = [_node(1, "Node-A")]
    bindings = [_binding("youtube", 1, role="main")]
    config = build_config(nodes, bindings, [], SETTINGS)
    assert _groups(config)["Default"]["proxies"] == ["DIRECT"]
    assert "fallback" not in config["dns"]


def test_dns_fallback_present_when_default_live():
    nodes = [_node(1, "Node-A")]
    bindings = [_binding("default", 1, role="main")]
    config = build_config(nodes, bindings, [], SETTINGS)
    assert config["dns"]["fallback"] == [
        "https://1.1.1.1/dns-query#Default",
        "https://8.8.8.8/dns-query#Default",
    ]


# ---------------------------------------------------------- H-04 apply gate
def test_default_apply_gate_allows_zero_node_library():
    """Fresh install: no nodes at all -> gate passes (DIRECT is the
    only option for the first config)."""
    assert default_apply_gate([], []) is None
    assert default_unbound_with_nodes([], []) is False


def test_default_apply_gate_refuses_nodes_without_default_binding():
    nodes = [_node(1, "Node-A")]
    bindings = [_binding("youtube", 1, role="main")]
    assert default_unbound_with_nodes(nodes, bindings) is True
    message = default_apply_gate(nodes, bindings)
    assert message is not None
    assert "Default" in message
    assert "绑定" in message  # guidance: bind Default first


def test_default_apply_gate_passes_when_default_bound_even_if_dead():
    """Default bound to a disabled node is dead (REJECT), not
    unbound — the gate passes and the apply goes through fail-closed."""
    nodes = [_node(1, "Node-A", enabled=False)]
    bindings = [_binding("default", 1, role="main")]
    assert default_unbound_with_nodes(nodes, bindings) is False
    assert default_apply_gate(nodes, bindings) is None


# ------------------------------------------------------- service-level apply
class FakeClient:
    """Records reload calls; never fails."""

    def __init__(self):
        self.reload_calls = 0

    def reload_config(self, force=True):
        self.reload_calls += 1

    def get_version(self):
        return {"version": "fake-1.0-test"}

    def get_connections(self):
        return {"connections": []}

    def get_traffic(self, timeout=5.0):
        return {"up": 0, "down": 0}

    def get_proxy_group(self, name):
        return {"name": name, "type": "Fallback", "now": None}


def _proxy(name):
    return {
        "name": name,
        "type": "ss",
        "server": "example.com",
        "port": 8388,
        "cipher": "aes-128-gcm",
        "password": "fake-pass",
    }


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


def test_apply_refused_when_default_unbound_with_nodes(service, db):
    """H-04: nodes exist, Default never bound -> apply refused at
    compile stage with guidance; live config untouched, revision
    unmoved, no reload attempted. Binding Default then clears it."""
    node_id = db.add_node(
        "NodeOne", "ss://fake@example.com:8388", _proxy("NodeOne")
    )
    db.set_binding("youtube", node_id, role="main")
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    error = exc_info.value
    assert error.stage == "compile"
    assert "Default" in error.message
    assert "绑定" in error.message
    assert db.get_setting("last_apply_stage") == "compile"
    assert db.get_setting("last_apply_ok") == "0"
    assert "Default" in (db.get_setting("last_apply_error") or "")
    assert int(db.get_setting("config_revision_db", "0") or "0") == 0
    assert not service.config_path.exists()
    assert service._fake_client.reload_calls == 0

    # Recovery path the message points at: bind Default, reapply.
    db.set_binding("default", node_id, role="main")
    service.apply()
    assert db.get_setting("last_apply_ok") == "1"
    assert service.config_path.exists()


def test_apply_initial_skips_default_gate_but_apply_refuses(service, db):
    """Merge decision (H-04 scope): the gate guards the user-triggered
    apply() only. Startup (apply_initial) must still write a config
    for an upgrading install whose nodes are bound to specific groups
    but never to Default — refusing at boot would leave no config at
    all, and the unbound-Default state is surfaced via diagnostics
    (``default_unbound``) + the panel warning instead.
    """
    node_id = db.add_node(
        "NodeOne", "ss://fake@example.com:8388", _proxy("NodeOne")
    )
    db.set_binding("youtube", node_id, role="main")
    # Startup path: writes the config (Default DIRECT), does not raise.
    path = service.apply_initial()
    assert path.exists()
    # User path: still refused with guidance.
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.stage == "compile"
    assert "Default" in exc_info.value.message


def test_apply_allowed_for_zero_node_first_config(service):
    """H-04 boundary: a library with zero nodes generates its first
    config — all groups DIRECT, no DNS fallback — instead of being
    refused forever."""
    service.apply()
    config_text = service.config_path.read_text(encoding="utf-8")
    import yaml

    config = yaml.safe_load(config_text)
    assert all(
        g["proxies"] == ["DIRECT"] for g in config["proxy-groups"]
    )
    assert "fallback" not in config["dns"]
    assert service._fake_client.reload_calls == 1


def test_apply_allowed_when_default_dead_generates_reject(service, db):
    """H-03 + H-04 together: Default bound to a disabled node is
    dead, not unbound — the apply succeeds and Default is REJECT."""
    node_id = db.add_node(
        "NodeOne", "ss://fake@example.com:8388", _proxy("NodeOne"),
        enabled=False,
    )
    db.set_binding("default", node_id, role="main")
    service.apply()
    import yaml

    config = yaml.safe_load(
        service.config_path.read_text(encoding="utf-8")
    )
    groups = {g["name"]: g for g in config["proxy-groups"]}
    assert groups["Default"]["proxies"] == ["REJECT"]
    assert "fallback" not in config["dns"]
    assert service._fake_client.reload_calls == 1


def test_apply_allowed_when_default_bound_live(service, db):
    node_id = db.add_node(
        "NodeOne", "ss://fake@example.com:8388", _proxy("NodeOne")
    )
    db.set_binding("default", node_id, role="main")
    service.apply()
    import yaml

    config = yaml.safe_load(
        service.config_path.read_text(encoding="utf-8")
    )
    groups = {g["name"]: g for g in config["proxy-groups"]}
    assert groups["Default"]["proxies"] == ["NodeOne"]
    assert config["dns"]["fallback"] == [
        "https://1.1.1.1/dns-query#Default",
        "https://8.8.8.8/dns-query#Default",
    ]


# ------------------------------------------------- HTTP status + route-check
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


def test_status_reports_dead_groups(http_client, auth_headers, http_app):
    db = http_app.state.db
    dead_id = db.add_node(
        "DeadNode", "ss://dead@example.com:8388", _proxy("DeadNode"),
        enabled=False,
    )
    live_id = db.add_node(
        "LiveNode", "ss://live@example.com:8388", _proxy("LiveNode")
    )
    db.set_binding("youtube", dead_id, role="main")
    db.set_binding("default", live_id, role="main")
    config = _status(http_client, auth_headers)
    assert config["dead_groups"] == ["youtube"]
    assert config["default_unbound"] is False


def test_status_reports_default_unbound(http_client, auth_headers, http_app):
    db = http_app.state.db
    node_id = db.add_node(
        "NodeOne", "ss://fake@example.com:8388", _proxy("NodeOne")
    )
    db.set_binding("youtube", node_id, role="main")
    config = _status(http_client, auth_headers)
    assert config["dead_groups"] == []
    assert config["default_unbound"] is True


def test_delete_last_bound_node_reports_dead_group(
    http_client, auth_headers, http_app
):
    """End-to-end H-03 gap: deleting the last bound node through the
    API leaves a dangling binding row, so the group is reported dead
    (compiled to REJECT + panel warning) instead of silently
    reverting to "never bound" / DIRECT."""
    db = http_app.state.db
    yt_id = db.add_node(
        "YTNode", "ss://yt@example.com:8388", _proxy("YTNode")
    )
    dflt_id = db.add_node(
        "DfltNode", "ss://dflt@example.com:8388", _proxy("DfltNode")
    )
    db.set_binding("youtube", yt_id, role="main")
    db.set_binding("default", dflt_id, role="main")
    assert _status(http_client, auth_headers)["dead_groups"] == []

    resp = http_client.delete(f"/api/nodes/{yt_id}", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["reload"]["ok"] is True
    assert db.get_node(yt_id) is None
    # Binding row survives the delete as a dangling row.
    assert [b["node_id"] for b in db.list_bindings("youtube")] == [yt_id]
    assert _status(http_client, auth_headers)["dead_groups"] == [
        "youtube"
    ]


def test_rebind_after_delete_clears_dead_group(
    http_client, auth_headers, http_app
):
    """After the last bound node is deleted, binding a fresh node
    (same name, new id) revives the group — the old dangling row must
    not shadow it, and the panel stops reporting the group dead.
    Binding an unknown node id is still refused (L-19)."""
    db = http_app.state.db
    yt_id = db.add_node(
        "YTNode", "ss://yt@example.com:8388", _proxy("YTNode")
    )
    dflt_id = db.add_node(
        "DfltNode", "ss://dflt@example.com:8388", _proxy("DfltNode")
    )
    db.set_binding("youtube", yt_id, role="main")
    db.set_binding("default", dflt_id, role="main")
    http_client.delete(f"/api/nodes/{yt_id}", headers=auth_headers)
    assert _status(http_client, auth_headers)["dead_groups"] == [
        "youtube"
    ]

    # L-19 write-time validation: unknown node id -> 400, nothing kept.
    resp = http_client.put(
        "/api/rules/bindings/youtube",
        headers=auth_headers,
        json={"main": 99999, "backups": [], "mode": "fallback"},
    )
    assert resp.status_code == 400, resp.text
    assert [b["node_id"] for b in db.list_bindings("youtube")] == [yt_id]

    new_id = db.add_node(
        "YTNode", "ss://yt2@example.com:8388", _proxy("YTNode")
    )
    assert new_id != yt_id
    assert _status(http_client, auth_headers)["dead_groups"] == [
        "youtube"
    ]
    resp = http_client.put(
        "/api/rules/bindings/youtube",
        headers=auth_headers,
        json={"main": new_id, "backups": [], "mode": "fallback"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["reload"]["ok"] is True
    assert _status(http_client, auth_headers)["dead_groups"] == []
    assert db.list_bindings("youtube")[0]["node_id"] == new_id


def test_route_check_dead_group_reports_reject(
    http_client, auth_headers, http_app
):
    """Diagnosis must agree with the compiled config: a dead YouTube
    group reports REJECT (not DIRECT), while the never-bound Apple
    group still reports DIRECT."""
    db = http_app.state.db
    dead_id = db.add_node(
        "DeadNode", "ss://dead@example.com:8388", _proxy("DeadNode"),
        enabled=False,
    )
    db.set_binding("youtube", dead_id, role="main")
    body = http_client.post(
        "/api/diagnostics/route-check",
        headers=auth_headers,
        json={"domain": "youtube.com"},
    ).json()
    assert body["matched"] is True
    assert body["group"] == "YouTube"
    assert body["effective_target"] == "REJECT"
    assert body["connection"] == "unreachable"

    body = http_client.post(
        "/api/diagnostics/route-check",
        headers=auth_headers,
        json={"domain": "www.apple.com"},
    ).json()
    assert body["group"] == "Apple"
    assert body["effective_target"] == "DIRECT"


# ------------------------------------------------------------ panel markers
def test_panel_has_dead_group_warning_markers():
    """The panel must show a dead group / unbound Default at a
    glance: strong banner, per-group strip, REJECT badge text, and a
    nav warning dot on the routing tab."""
    html = FRONTEND_HTML.read_text(encoding="utf-8")
    # Strong banner driven by the status endpoint's new fields.
    assert 'x-show="deadGroups().length > 0 || defaultUnbound()"' in html
    assert "deadGroups().map(g => g.name).join('、')" in html
    assert "Default 组尚未绑定节点" in html
    assert "去业务分流处理" in html
    # Per-group helpers + routing-tab strip + overview badge text.
    assert "groupDead(key)" in html
    assert 'x-show="groupDead(g.key)"' in html
    assert "节点死光 · REJECT" in html
    assert "已绑定节点全部不可用 → REJECT" in html
    # Nav warning dot on the routing tab.
    assert "if (id === 'routing') return this.deadGroups().length > 0" in html
    # Unbound groups still render as DIRECT (design default kept).
    assert "未绑定 → DIRECT" in html
