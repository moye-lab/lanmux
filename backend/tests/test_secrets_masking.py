"""Secrets & entry-key tests (M-01 / M-02 / M-05 / M-06 / L-22 / L-23).

- M-01: config preview masks every sensitive field (whitelist +
  recursive), including obfs-password / public-key / short-id, and
  leaves normal preview structure intact.
- M-02: YAML parse failures never echo raw (unmasked) text — error
  responses carry only line/column + error type.
- M-05: node list / single reads are masked by default; the
  per-node export endpoint returns plaintext and writes an audit
  log row.
- M-06 + L-22: Mixed username/password are a pair — saving only
  one half is rejected with "用户名与密码须同时设置"; the compiler
  never emits ``password: ''`` and never silently drops auth.
- L-23: short secrets (<= 8 chars) mask fully; long secrets keep
  first/last 2 chars.
"""

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.config_builder import build_config
from app.config_service import mask_config_text, validate_config_yaml
from app.deps import get_config_service, get_mihomo_client
from app.main import create_app
from app.masking import mask_node_uri, mask_secret, mask_value

ADMIN_PASSWORD = "test-admin-password"

SS_URI = "ss://YWVzLTEyOC1nY206ZmFrZS1wYXNzd29yZA@example.com:8388#NodeOne"
VLESS_URI = (
    "vless://11111111-2222-3333-4444-555555555555"
    "@example.com:443#NodeTwo"
)


class FakeConfigService:
    def __init__(self):
        self.apply_calls = 0

    def apply(self):
        self.apply_calls += 1

    def read_config_text(self):
        return None

    def read_masked_config_text(self):
        return None


class FakeMihomoClient:
    def test_delay(self, proxy, url, timeout=5):
        return 123

    def get_version(self):
        return {"version": "fake-1.0-test"}

    def get_connections(self):
        return {"connections": []}

    def get_traffic(self, timeout=5.0):
        return {"up": 0, "down": 0}

    def reload_config(self, force=True):
        pass

    def get_proxies(self):
        return {"proxies": {}}


@pytest.fixture
def app(tmp_path):
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    app.state.db.set_setting(
        "admin_password_hash", hash_password(ADMIN_PASSWORD)
    )
    fake_service = FakeConfigService()
    app.dependency_overrides[get_config_service] = lambda: fake_service
    app.dependency_overrides[get_mihomo_client] = lambda: FakeMihomoClient()
    return app


@pytest.fixture
def preview_app(tmp_path):
    """App with the REAL ConfigService (config preview reads the file)."""
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    app.state.db.set_setting(
        "admin_password_hash", hash_password(ADMIN_PASSWORD)
    )
    app.dependency_overrides[get_mihomo_client] = lambda: FakeMihomoClient()
    return app


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def preview_client(preview_app):
    with TestClient(preview_app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers(client):
    response = client.post(
        "/api/auth/login", json={"password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture
def preview_auth_headers(preview_client):
    response = preview_client.post(
        "/api/auth/login", json={"password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _add_node(client, headers, uri=SS_URI):
    response = client.post("/api/nodes", json={"uri": uri}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["node"]


# ------------------------------------------------------------------- L-23
def test_mask_secret_short_fully_masked():
    assert mask_secret("") == "********"
    assert mask_secret("abcd") == "********"
    assert mask_secret("12345678") == "********"  # exactly 8
    assert mask_secret(12345) == "********"  # non-string


def test_mask_secret_long_keeps_first_last_two():
    assert mask_secret("123456789") == "12****89"  # 9 chars
    assert mask_secret("fake-password") == "fa****rd"
    assert mask_secret("fake-mihomo-secret") == "fa****et"


# ------------------------------------------------------------------- M-01
def test_mask_value_covers_all_sensitive_fields_recursively():
    config = {
        "secret": "topsecret-mihomo-123",
        "listeners": [
            {
                "name": "lan-ss",
                "type": "shadowsocks",
                "port": 10001,
                "password": "ss-password-123",
            },
            {
                "name": "lan-mixed",
                "type": "mixed",
                "port": 7890,
                "username": "lanuser",
                "password": "mixed-password-123",
            },
        ],
        "proxies": [
            {
                "name": "RealityNode",
                "type": "vless",
                "server": "example.com",
                "port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "flow": "xtls-rprx-vision",
                "tls": True,
                "servername": "www.example.com",
                "fingerprint": "chrome",
                "reality-opts": {
                    "public-key": "LONGPUBLICKEY1234567890",
                    "short-id": "abc123",
                },
            },
            {
                "name": "TrojanNode",
                "type": "trojan",
                "server": "example.net",
                "port": 443,
                "password": "trojan-password-123",
                "obfs-password": "obfs-secret-123",
            },
            {
                "name": "SsNode",
                "type": "ss",
                "server": "example.org",
                "port": 8388,
                "cipher": "aes-128-gcm",
                "password": "ss-node-password-1",
                "plugin-opts": {"token": "plugin-token-123"},
            },
        ],
    }
    masked = mask_value(config)
    blob = str(masked)
    for secret in (
        "topsecret-mihomo-123",
        "ss-password-123",
        "mixed-password-123",
        "11111111-2222-3333-4444-555555555555",
        "LONGPUBLICKEY1234567890",
        "abc123",
        "trojan-password-123",
        "obfs-secret-123",
        "ss-node-password-1",
        "plugin-token-123",
    ):
        assert secret not in blob, secret
    # Structure + safe fields survive intact.
    assert masked["proxies"][0]["server"] == "example.com"
    assert masked["proxies"][0]["port"] == 443
    assert masked["proxies"][0]["flow"] == "xtls-rprx-vision"
    assert masked["proxies"][0]["tls"] is True
    assert masked["proxies"][0]["fingerprint"] == "chrome"
    assert masked["proxies"][0]["servername"] == "www.example.com"
    assert masked["proxies"][2]["cipher"] == "aes-128-gcm"
    assert masked["listeners"][0]["port"] == 10001
    assert masked["listeners"][1]["username"] == "lanuser"
    assert masked["listeners"][1]["port"] == 7890
    assert "****" in blob


def test_mask_config_text_masks_every_sensitive_field():
    text = (
        "secret: topsecret-mihomo-123\n"
        "listeners:\n"
        "  - {name: lan-ss, password: ss-password-123, port: 10001}\n"
        "proxies:\n"
        "  - name: RealityNode\n"
        "    type: vless\n"
        "    server: example.com\n"
        "    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
        "    reality-opts: {public-key: LONGPUBLICKEY1234567890,"
        " short-id: abc123}\n"
        "  - {name: TrojanNode, type: trojan, server: example.net,"
        " port: 443, password: trojan-password-123,"
        " obfs-password: obfs-secret-123}\n"
    )
    masked = mask_config_text(text)
    for secret in (
        "topsecret-mihomo-123",
        "ss-password-123",
        "11111111-2222-3333-4444-555555555555",
        "LONGPUBLICKEY1234567890",
        "abc123",
        "trojan-password-123",
        "obfs-secret-123",
    ):
        assert secret not in masked, secret
    # Normal preview is still usable: structure + safe values intact.
    assert "example.com" in masked
    assert "example.net" in masked
    assert "10001" in masked
    assert "RealityNode" in masked
    assert "TrojanNode" in masked


def test_config_preview_masks_reality_fields(
    preview_client, preview_auth_headers, preview_app
):
    config_path = preview_app.state.config_service.config_path
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "secret: topsecret-mihomo-123\n"
        "listeners:\n"
        "  - {name: lan-ss, password: ss-password-123, port: 10001}\n"
        "proxies:\n"
        "  - name: RealityNode\n"
        "    type: vless\n"
        "    server: example.com\n"
        "    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
        "    reality-opts: {public-key: LONGPUBLICKEY1234567890,"
        " short-id: abc123}\n",
        encoding="utf-8",
    )
    body = preview_client.get(
        "/api/diagnostics/config-preview", headers=preview_auth_headers
    ).json()
    assert body["exists"] is True
    for secret in (
        "topsecret-mihomo-123",
        "ss-password-123",
        "11111111-2222-3333-4444-555555555555",
        "LONGPUBLICKEY1234567890",
        "abc123",
    ):
        assert secret not in body["config"], secret
    assert "example.com" in body["config"]
    assert "RealityNode" in body["config"]


# ------------------------------------------------------------------- M-02
def test_yaml_parse_error_never_echoes_raw_text():
    bad = "proxies: []\npassword: hunter2-topsecret: oops\n"
    with pytest.raises(ValueError, match="does not parse"):
        validate_config_yaml(bad)
    try:
        validate_config_yaml(bad)
    except ValueError as exc:
        assert "hunter2" not in str(exc)
        assert "line 2" in str(exc)  # line number + type only


def test_mask_config_text_broken_yaml_hides_raw_content():
    bad = (
        "secret: hunter2-topsecret\n"
        "listeners:\n"
        "  - {name: lan-ss, password: hunter2-pass, port: 10001}\n"
        "bad: [unclosed\n"
    )
    masked = mask_config_text(bad)
    assert "hunter2" not in masked
    assert "lan-ss" not in masked  # no raw lines at all
    assert "line" in masked  # only the failure location is reported


def test_mask_config_text_non_mapping_hides_raw_content():
    masked = mask_config_text("- just\n- a\n- list: hunter2-topsecret\n")
    assert "hunter2" not in masked


def test_config_preview_broken_yaml_hides_raw_content(
    preview_client, preview_auth_headers, preview_app
):
    config_path = preview_app.state.config_service.config_path
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        "secret: hunter2-topsecret\n"
        "listeners:\n"
        "  - {name: lan-ss, password: hunter2-pass, port: 10001}\n"
        "bad: [unclosed\n",
        encoding="utf-8",
    )
    body = preview_client.get(
        "/api/diagnostics/config-preview", headers=preview_auth_headers
    ).json()
    assert body["exists"] is True
    assert "hunter2" not in body["config"]
    assert "lan-ss" not in body["config"]


# ------------------------------------------------------------------- M-05
def test_node_list_and_single_read_are_masked(client, auth_headers):
    node = _add_node(client, auth_headers, SS_URI)
    other = _add_node(client, auth_headers, VLESS_URI)

    listed = client.get("/api/nodes", headers=auth_headers).json()
    assert len(listed) == 2
    blob = str(listed)
    assert "fake-password" not in blob
    assert "11111111-2222-3333-4444-555555555555" not in blob
    assert "YWVzLTEyOC1nY206ZmFrZS1wYXNzd29yZA" not in blob
    # Safe fields still visible: type / server / port / name.
    by_name = {n["name"]: n for n in listed}
    assert by_name["NodeOne"]["proxy"]["type"] == "ss"
    assert by_name["NodeOne"]["proxy"]["server"] == "example.com"
    assert by_name["NodeOne"]["proxy"]["port"] == 8388
    assert by_name["NodeTwo"]["proxy"]["type"] == "vless"
    assert by_name["NodeTwo"]["proxy"]["server"] == "example.com"
    # Masked URI keeps host/port/fragment, hides credentials.
    assert by_name["NodeOne"]["uri"] == (
        "ss://********@example.com:8388#NodeOne"
    )
    assert by_name["NodeTwo"]["uri"] == (
        "vless://********@example.com:443#NodeTwo"
    )

    single = client.get(
        f"/api/nodes/{node['id']}", headers=auth_headers
    ).json()
    assert "fake-password" not in str(single)
    assert single["proxy"]["server"] == "example.com"
    assert single["name"] == "NodeOne"

    # Create / update responses are masked too.
    created = client.post(
        "/api/nodes", json={"uri": SS_URI}, headers=auth_headers
    ).json()["node"]
    assert "fake-password" not in str(created)
    updated = client.put(
        f"/api/nodes/{other['id']}",
        json={"proxy": {"type": "vless", "server": "example.com",
                        "port": 443,
                        "uuid": "11111111-2222-3333-4444-555555555555"}},
        headers=auth_headers,
    ).json()["node"]
    assert "11111111-2222-3333-4444-555555555555" not in str(updated)
    assert updated["proxy"]["server"] == "example.com"


def test_mask_node_uri_forms():
    assert mask_node_uri(SS_URI) == (
        "ss://********@example.com:8388#NodeOne"
    )
    # Full-base64 ss:// form (no @ outside the blob).
    assert mask_node_uri(
        "ss://YWVzLTEyOC1nY206ZmFrZS1wYXNzd29yZEAxMC4wLjAuMjoxMDAwMQ#N"
    ) == "ss://********#N"
    # vmess:// base64 JSON blob.
    assert mask_node_uri(
        "vmess://eyJ2IjoiMiIsInBzIjoiTiIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1In0"
    ) == "vmess://********"
    # No credentials: untouched.
    assert mask_node_uri("ss://example.com:8388#Plain") == (
        "ss://example.com:8388#Plain"
    )


def test_node_export_returns_plaintext_and_audits(
    client, auth_headers, app
):
    node = _add_node(client, auth_headers, SS_URI)
    assert app.state.db.list_audit_log() == []

    # Merged (M-02): login sets an HttpOnly cookie kept in the
    # TestClient jar, so drop it first — without cookie and without
    # a Bearer header the export endpoint must refuse.
    client.cookies.clear()
    assert client.get(
        f"/api/nodes/{node['id']}/export"
    ).status_code == 401  # auth required

    body = client.get(
        f"/api/nodes/{node['id']}/export", headers=auth_headers
    ).json()
    assert body["node"]["proxy"]["password"] == "fake-password"
    assert body["node"]["uri"] == SS_URI
    assert "warning" in body

    rows = app.state.db.list_audit_log()
    assert len(rows) == 1
    assert rows[0]["action"] == "node_export"
    assert rows[0]["node_id"] == node["id"]
    assert "fake-password" not in rows[0]["detail"]

    assert client.get(
        "/api/nodes/99999/export", headers=auth_headers
    ).status_code == 404
    assert len(app.state.db.list_audit_log()) == 1  # no row for 404


def test_ss_link_export_is_audited(client, auth_headers, app):
    app.state.db.set_setting("ss_password", "s3cret-pw")
    app.state.db.set_setting("lan_ip", "10.0.0.2")
    body = client.get("/api/settings/ss-link", headers=auth_headers).json()
    assert body["url"].startswith("ss://")
    rows = app.state.db.list_audit_log()
    assert len(rows) == 1
    assert rows[0]["action"] == "ss_link"


# ------------------------------------------------------- M-06 + L-22
def test_mixed_auth_user_only_rejected(client, auth_headers, app):
    response = client.put(
        "/api/settings",
        json={"mixed_auth_user": "lanuser"},
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert "用户名与密码须同时设置" in response.json()["detail"]
    # Nothing persisted: the rejected half pair leaves no trace.
    assert app.state.db.get_setting("mixed_auth_user") == ""
    assert app.state.db.get_setting("mixed_auth_pass") == ""


def test_mixed_auth_pass_only_rejected(client, auth_headers, app):
    response = client.put(
        "/api/settings",
        json={"mixed_auth_pass": "secret-pass"},
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert "用户名与密码须同时设置" in response.json()["detail"]
    assert app.state.db.get_setting("mixed_auth_user") == ""
    assert app.state.db.get_setting("mixed_auth_pass") == ""


def test_mixed_auth_user_with_empty_password_rejected(
    client, auth_headers, app
):
    # L-22 via the API: username set + explicit empty password.
    response = client.put(
        "/api/settings",
        json={"mixed_auth_user": "lanuser", "mixed_auth_pass": ""},
        headers=auth_headers,
    )
    assert response.status_code == 400
    assert "用户名与密码须同时设置" in response.json()["detail"]
    assert app.state.db.get_setting("mixed_auth_user") == ""


def test_mixed_auth_pair_saves_and_clears_together(
    client, auth_headers, app
):
    body = client.put(
        "/api/settings",
        json={"mixed_auth_user": "lanuser",
              "mixed_auth_pass": "secret-pass"},
        headers=auth_headers,
    ).json()
    assert body["settings"]["mixed_auth_user"] == "lanuser"
    assert body["settings"]["mixed_auth_pass_set"] is True

    # Changing the username alone keeps the stored password (pair
    # still complete) — the form's "leave password unchanged" flow.
    body = client.put(
        "/api/settings",
        json={"mixed_auth_user": "otheruser"},
        headers=auth_headers,
    ).json()
    assert body["settings"]["mixed_auth_user"] == "otheruser"
    assert body["settings"]["mixed_auth_pass_set"] is True

    # Clearing the username turns auth off: the stored password is
    # cleared with it instead of stranding a half pair.
    body = client.put(
        "/api/settings",
        json={"mixed_auth_user": ""},
        headers=auth_headers,
    ).json()
    assert body["settings"]["mixed_auth_user"] == ""
    assert body["settings"]["mixed_auth_pass_set"] is False
    assert app.state.db.get_setting("mixed_auth_pass") == ""


def test_build_config_mixed_pair_rules():
    base = {
        "lan_ip": "10.0.0.2",
        "ss_port": 10001,
        "ss_cipher": "aes-128-gcm",
        "ss_password": "fake-ss-password",
        "mixed_port": 7890,
        "mihomo_secret": "fake-mihomo-secret",
        "controller_port": 9090,
    }

    def _mixed(**overrides):
        settings = dict(base)
        settings.update(overrides)
        config = build_config([], [], [], settings)
        return next(
            li for li in config["listeners"] if li["name"] == "lan-mixed"
        )

    # Neither set: no auth keys at all (never ``password: ''``).
    listener = _mixed()
    assert "username" not in listener
    assert "password" not in listener
    # Both set: emitted together.
    listener = _mixed(
        mixed_auth_user="lanuser", mixed_auth_pass="secret-pass"
    )
    assert listener["username"] == "lanuser"
    assert listener["password"] == "secret-pass"
    # Only one half: fail loudly instead of silently dropping auth.
    with pytest.raises(ValueError, match="用户名与密码须同时设置"):
        _mixed(mixed_auth_user="lanuser")
    with pytest.raises(ValueError, match="用户名与密码须同时设置"):
        _mixed(mixed_auth_pass="secret-pass")
    with pytest.raises(ValueError, match="用户名与密码须同时设置"):
        _mixed(mixed_auth_user="lanuser", mixed_auth_pass="")
