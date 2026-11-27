"""API tests (FastAPI TestClient): auth, nodes, rules, settings.

The config service and mihomo client are replaced with recording
fakes via ``app.dependency_overrides`` — the real reload/rollback
pipeline is tested in test_reload_rollback.py, the real HTTP client
in test_mihomo_client.py. No network is used.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.deps import get_config_service, get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError

ADMIN_PASSWORD = "test-admin-password"

SS_URI = "ss://YWVzLTEyOC1nY206ZmFrZS1wYXNzd29yZA@example.com:8388#NodeOne"
SS_URI_2 = "ss://YWVzLTEyOC1nY206ZmFrZS1wYXNzd29yZDI@example.org:8389#NodeTwo"
TROJAN_URI = "trojan://fake-pass@example.net:443#NodeThree"


class FakeConfigService:
    """Recording stand-in for ConfigService (apply always succeeds)."""

    def __init__(self):
        self.apply_calls = 0

    def apply(self):
        self.apply_calls += 1

    def read_config_text(self):
        return None

    def read_masked_config_text(self):
        return None


class FakeMihomoClient:
    """Delay tests return fixed values; ``failing`` names raise."""

    def __init__(self, delays=None, failing=None):
        self.delays = delays or {}
        self.failing = failing or set()
        self.tested = []

    def test_delay(self, proxy, url, timeout=5):
        self.tested.append(proxy)
        if proxy in self.failing:
            raise MihomoError(
                f"proxy {proxy!r} timed out", status=408
            )
        return self.delays.get(proxy, 123)

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
def fake_service():
    return FakeConfigService()


@pytest.fixture
def fake_client():
    return FakeMihomoClient()


@pytest.fixture
def app(tmp_path, fake_service, fake_client):
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    app.state.db.set_setting(
        "admin_password_hash", hash_password(ADMIN_PASSWORD)
    )
    app.dependency_overrides[get_config_service] = lambda: fake_service
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


def _add_node(client, headers, uri=SS_URI):
    response = client.post("/api/nodes", json={"uri": uri}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["node"]


# --------------------------------------------------------------------- auth
def test_health_is_public(client):
    assert client.get("/health").json()["status"] == "ok"


def test_api_requires_auth(client):
    for path in (
        "/api/nodes",
        "/api/rules/bindings",
        "/api/settings",
        "/api/diagnostics/status",
    ):
        assert client.get(path).status_code == 401, path


def test_login_flow_and_logout(client, app):
    assert client.post(
        "/api/auth/login", json={"password": "wrong"}
    ).status_code == 401
    response = client.post(
        "/api/auth/login", json={"password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    token = response.json()["token"]
    assert len(token) == 64  # token_hex(32)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/nodes", headers=headers).status_code == 200
    # An invalid Bearer token is rejected — with the login cookie
    # cleared first, since cookie auth takes precedence (M-03).
    client.cookies.clear()
    assert client.get(
        "/api/nodes",
        headers={"Authorization": "Bearer bogus"},
    ).status_code == 401
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/nodes", headers=headers).status_code == 401


def test_expired_token_rejected(client, app):
    response = client.post(
        "/api/auth/login", json={"password": ADMIN_PASSWORD}
    )
    token = response.json()["token"]
    store = app.state.token_store
    store._tokens[token] = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert client.get(
        "/api/nodes", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 401


def test_auth_status_reports_configured(client):
    body = client.get("/api/auth/status").json()
    assert body["admin_configured"] is True


# -------------------------------------------------------------------- nodes
def test_node_crud(client, auth_headers, fake_service):
    node = _add_node(client, auth_headers)
    assert node["name"] == "NodeOne"
    assert node["proxy"]["type"] == "ss"
    assert node["last_delay_ms"] is None
    node_id = node["id"]

    got = client.get(f"/api/nodes/{node_id}", headers=auth_headers).json()
    assert got["name"] == "NodeOne"
    assert len(client.get("/api/nodes", headers=auth_headers).json()) == 1

    renamed = client.put(
        f"/api/nodes/{node_id}",
        json={"name": "Renamed"},
        headers=auth_headers,
    ).json()["node"]
    assert renamed["name"] == "Renamed"
    assert renamed["proxy"]["name"] == "Renamed"

    edited = client.put(
        f"/api/nodes/{node_id}",
        json={"proxy": {"type": "ss", "server": "example.com",
                        "port": 9999, "cipher": "aes-256-gcm",
                        "password": "fake-new"}},
        headers=auth_headers,
    ).json()["node"]
    assert edited["proxy"]["port"] == 9999
    assert edited["proxy"]["name"] == "Renamed"

    disabled = client.put(
        f"/api/nodes/{node_id}",
        json={"enabled": False},
        headers=auth_headers,
    ).json()["node"]
    assert disabled["enabled"] is False

    assert client.delete(
        f"/api/nodes/{node_id}", headers=auth_headers
    ).status_code == 200
    assert client.get("/api/nodes", headers=auth_headers).json() == []
    assert client.get(
        f"/api/nodes/{node_id}", headers=auth_headers
    ).status_code == 404
    # create + rename + edit + disable + delete = 5 applies.
    assert fake_service.apply_calls == 5


def test_node_create_rejects_bad_uri(client, auth_headers):
    response = client.post(
        "/api/nodes", json={"uri": "not-a-uri"}, headers=auth_headers
    )
    assert response.status_code == 400
    assert client.get("/api/nodes", headers=auth_headers).json() == []


def test_node_create_name_override(client, auth_headers):
    node = _add_node(client, auth_headers, SS_URI)
    assert node["name"] == "NodeOne"
    response = client.post(
        "/api/nodes",
        json={"uri": SS_URI_2, "name": "CustomName"},
        headers=auth_headers,
    )
    assert response.json()["node"]["name"] == "CustomName"


def test_node_update_validates_proxy(client, auth_headers):
    node = _add_node(client, auth_headers)
    response = client.put(
        f"/api/nodes/{node['id']}",
        json={"proxy": {"server": "example.com"}},
        headers=auth_headers,
    )
    assert response.status_code == 400


@pytest.mark.parametrize("bad_proxy", [
    # Illegal type.
    {"type": "socks", "server": "example.com", "port": 1080},
    # Port out of range.
    {"type": "ss", "server": "example.com", "port": 99999,
     "cipher": "aes-128-gcm", "password": "pw"},
    # Missing uuid for a uuid-based type.
    {"type": "vless", "server": "example.com", "port": 443},
    # Malformed uuid.
    {"type": "vless", "server": "example.com", "port": 443,
     "uuid": "not-a-uuid"},
    # Missing password for a password-based type.
    {"type": "trojan", "server": "example.com", "port": 443},
    # Unknown cipher.
    {"type": "ss", "server": "example.com", "port": 8388,
     "cipher": "bad-cipher", "password": "pw"},
    # Bad host.
    {"type": "ss", "server": "bad_host!", "port": 8388,
     "cipher": "aes-128-gcm", "password": "pw"},
])
def test_node_update_rejects_bad_proxy_json(
    client, auth_headers, bad_proxy
):
    node = _add_node(client, auth_headers)
    response = client.put(
        f"/api/nodes/{node['id']}",
        json={"proxy": bad_proxy},
        headers=auth_headers,
    )
    assert response.status_code == 400
    # Nothing was written: the stored proxy is untouched.
    stored = client.get(
        f"/api/nodes/{node['id']}", headers=auth_headers
    ).json()
    assert stored["proxy"]["type"] == "ss"
    assert stored["proxy"]["cipher"] == "aes-128-gcm"


def test_node_update_accepts_valid_proxy_json(client, auth_headers):
    node = _add_node(client, auth_headers)
    response = client.put(
        f"/api/nodes/{node['id']}",
        json={"proxy": {
            "type": "trojan", "server": "example.net", "port": 443,
            "password": "new-pass",
        }},
        headers=auth_headers,
    )
    assert response.status_code == 200
    updated = response.json()["node"]
    assert updated["proxy"]["type"] == "trojan"
    assert updated["name"] == "NodeOne"  # name kept, not regenerated


def test_node_update_uri_keeps_existing_name(client, auth_headers):
    # M-21: PUT a new URI whose fragment names the node differently —
    # the stored name must survive unless the request names a new one.
    node = _add_node(client, auth_headers)
    assert node["name"] == "NodeOne"
    response = client.put(
        f"/api/nodes/{node['id']}",
        json={"uri": SS_URI_2.replace("#NodeTwo", "#FragmentName")},
        headers=auth_headers,
    )
    assert response.status_code == 200
    updated = response.json()["node"]
    assert updated["name"] == "NodeOne"
    assert updated["proxy"]["name"] == "NodeOne"
    # Merged (M-05): node responses are masked by default — the
    # returned URI redacts the credential part, so the stored URI is
    # verified through the audit-logged export endpoint instead.
    assert updated["uri"] == "ss://********@example.org:8389#FragmentName"
    exported = client.get(
        f"/api/nodes/{node['id']}/export", headers=auth_headers
    ).json()["node"]
    assert exported["uri"] == SS_URI_2.replace("#NodeTwo", "#FragmentName")
    # An explicit new name wins over both the old name and the fragment.
    response = client.put(
        f"/api/nodes/{node['id']}",
        json={"uri": SS_URI_2, "name": "Renamed"},
        headers=auth_headers,
    )
    assert response.json()["node"]["name"] == "Renamed"


def test_node_create_truncates_long_name(client, auth_headers):
    long_name = "L" * 100
    node = _add_node(client, auth_headers, SS_URI)
    response = client.put(
        f"/api/nodes/{node['id']}",
        json={"name": long_name},
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert len(response.json()["node"]["name"]) == 64
    assert any(
        "truncated to 64" in w for w in response.json()["warnings"]
    )


def test_batch_import_reports_per_line(client, auth_headers, fake_service):
    # M-19: error lines report the line number + a MASKED uri — the
    # bad line below carries a real-looking password, which must
    # never come back in the response.
    bad_uri = (
        "ss://YmFkLWNpcGhlcjpzZWNyZXQtcGFzc3dvcmQ@example.com:8388"
        # base64("bad-cipher:secret-password") — invalid cipher
    )
    text = f"{SS_URI}\nnot-a-uri\n\n{TROJAN_URI}\n{bad_uri}\n"
    body = client.post(
        "/api/nodes/batch", json={"text": text}, headers=auth_headers
    ).json()
    assert [n["name"] for n in body["imported"]] == ["NodeOne", "NodeThree"]
    assert len(body["errors"]) == 2
    assert body["errors"][0]["line"] == 2
    assert body["errors"][0]["uri"] == "not-a-uri"
    assert "scheme" in body["errors"][0]["error"]
    assert body["errors"][1]["line"] == 5
    assert "secret-password" not in body["errors"][1]["uri"]
    assert "YmFkLWNpcGhlcjpzZWNyZXQtcGFzc3dvcmQ" not in body["errors"][1]["uri"]
    assert body["errors"][1]["uri"].startswith("ss://***@example.com:8388")
    assert "unsupported cipher" in body["errors"][1]["error"]
    # Partial-submit semantics (L-21): some lines failed.
    assert body["partial"] is True
    assert body["skipped"] == 1  # the blank line
    assert body["duplicates"] == 0
    assert body["reload"]["ok"] is True
    # One apply for the whole batch, not one per node.
    assert fake_service.apply_calls == 1


def test_batch_import_dedupes_and_counts(client, auth_headers):
    # M-20 / L-06: same URI twice in one batch, and a second batch
    # re-importing an existing node — both are skipped as duplicates
    # and reported, with counts matching the actual rows written.
    text = f"{SS_URI}\n{SS_URI}\n{TROJAN_URI}\n"
    body = client.post(
        "/api/nodes/batch", json={"text": text}, headers=auth_headers
    ).json()
    assert [n["name"] for n in body["imported"]] == ["NodeOne", "NodeThree"]
    assert body["duplicates"] == 1
    assert body["errors"] == []
    assert body["partial"] is True  # a line was deduplicated
    assert any("duplicate URI" in w for w in body["warnings"])

    again = client.post(
        "/api/nodes/batch", json={"text": SS_URI}, headers=auth_headers
    ).json()
    assert again["imported"] == []
    assert again["duplicates"] == 1
    assert again["partial"] is True
    nodes = client.get("/api/nodes", headers=auth_headers).json()
    assert len(nodes) == 2  # no duplicate rows were written


def test_batch_import_dedupes_by_name(client, auth_headers):
    # Same name, different URI/host: also a duplicate (M-20).
    other = SS_URI_2.replace("#NodeTwo", "#NodeOne")
    body = client.post(
        "/api/nodes/batch",
        json={"text": f"{SS_URI}\n{other}\n"},
        headers=auth_headers,
    ).json()
    assert [n["name"] for n in body["imported"]] == ["NodeOne"]
    assert body["duplicates"] == 1
    assert any("duplicate node name" in w for w in body["warnings"])


def test_batch_import_over_limit_rejected(client, auth_headers):
    # M-20: more than 500 non-blank lines is refused up front and
    # nothing is imported.
    lines = "\n".join(
        f"ss://YWVzLTEyOC1nY206cHdkN3tp@host{i}.example.com:8388#N{i}"
        for i in range(501)
    )
    response = client.post(
        "/api/nodes/batch", json={"text": lines}, headers=auth_headers
    )
    assert response.status_code == 400
    assert "500" in response.json()["detail"]
    assert client.get("/api/nodes", headers=auth_headers).json() == []


def test_batch_import_all_ok_is_not_partial(client, auth_headers):
    body = client.post(
        "/api/nodes/batch",
        json={"text": f"{SS_URI}\n{TROJAN_URI}\n"},
        headers=auth_headers,
    ).json()
    assert body["partial"] is False
    assert body["duplicates"] == 0
    assert body["skipped"] == 0
    assert len(body["imported"]) == 2


def test_batch_import_surfaces_parse_warnings(client, auth_headers):
    # M-22: an unknown query parameter is a warning in the result,
    # not a silent drop and not a failure.
    uri = (
        "ss://YWVzLTEyOC1nY206ZmFrZS1wYXNzd29yZA@example.com:8388"
        "?bogusparam=1#Warned"
    )
    body = client.post(
        "/api/nodes/batch", json={"text": uri}, headers=auth_headers
    ).json()
    assert len(body["imported"]) == 1
    assert body["imported"][0]["name"] == "Warned"
    assert any(
        "unknown query parameter 'bogusparam'" in w
        for w in body["warnings"]
    )


# -------------------------------------------------------------------- rules
def test_binding_update_triggers_reload(client, auth_headers, fake_service):
    node = _add_node(client, auth_headers)
    other = _add_node(client, auth_headers, SS_URI_2)
    assert fake_service.apply_calls == 2  # two node creates

    body = client.put(
        "/api/rules/bindings/youtube",
        json={"main": node["id"], "backups": [other["id"]],
              "mode": "url-test"},
        headers=auth_headers,
    ).json()
    assert body["binding"]["main"] == node["id"]
    assert body["binding"]["backups"] == [other["id"]]
    assert body["binding"]["mode"] == "url-test"
    assert body["reload"]["ok"] is True
    assert fake_service.apply_calls == 3

    bindings = client.get(
        "/api/rules/bindings", headers=auth_headers
    ).json()
    assert bindings["youtube"]["main"] == node["id"]
    assert bindings["telegram"]["main"] is None  # untouched group


def test_binding_update_validates(client, auth_headers):
    node = _add_node(client, auth_headers)
    base = "/api/rules/bindings"
    assert client.put(
        f"{base}/nope", json={"main": node["id"]}, headers=auth_headers
    ).status_code == 400
    assert client.put(
        f"{base}/youtube", json={"main": 99999}, headers=auth_headers
    ).status_code == 400
    assert client.put(
        f"{base}/youtube",
        json={"main": node["id"], "backups": [node["id"]]},
        headers=auth_headers,
    ).status_code == 400


def test_custom_rules_crud(client, auth_headers, fake_service):
    created = client.post(
        "/api/rules/custom",
        json={"type": "DOMAIN-SUFFIX", "value": "example.org",
              "target": "YouTube"},
        headers=auth_headers,
    ).json()["rule"]
    assert created["value"] == "example.org"
    rule_id = created["id"]

    assert client.post(
        "/api/rules/custom",
        json={"type": "DOMAIN-SUFFIX", "value": "x.org",
              "target": "NotAGroup"},
        headers=auth_headers,
    ).status_code == 400
    assert client.post(
        "/api/rules/custom",
        json={"type": "IP-CIDR", "value": "not-an-ip",
              "target": "DIRECT"},
        headers=auth_headers,
    ).status_code == 400

    updated = client.put(
        f"/api/rules/custom/{rule_id}",
        json={"target": "REJECT"},
        headers=auth_headers,
    ).json()["rule"]
    assert updated["target"] == "REJECT"
    assert len(client.get(
        "/api/rules/custom", headers=auth_headers
    ).json()) == 1
    assert client.delete(
        f"/api/rules/custom/{rule_id}", headers=auth_headers
    ).status_code == 200
    assert client.delete(
        f"/api/rules/custom/{rule_id}", headers=auth_headers
    ).status_code == 404


def test_custom_rule_comma_value_400(client, auth_headers, fake_service):
    # M-12: a comma in the value would corrupt the generated rule line.
    assert client.post(
        "/api/rules/custom",
        json={"type": "DOMAIN-SUFFIX", "value": "a.org,b.org",
              "target": "DIRECT"},
        headers=auth_headers,
    ).status_code == 400
    assert client.post(
        "/api/rules/custom",
        json={"type": "DOMAIN-SUFFIX", "value": "exa mple.org",
              "target": "DIRECT"},
        headers=auth_headers,
    ).status_code == 400


def test_custom_rule_update_type_change_revalidates_value(
    client, auth_headers, fake_service
):
    # M-12: changing only the type must revalidate the stored value
    # under the new type ("example.org" is not a CIDR).
    rule_id = client.post(
        "/api/rules/custom",
        json={"type": "DOMAIN-SUFFIX", "value": "example.org",
              "target": "YouTube"},
        headers=auth_headers,
    ).json()["rule"]["id"]
    assert client.put(
        f"/api/rules/custom/{rule_id}",
        json={"type": "IP-CIDR"},
        headers=auth_headers,
    ).status_code == 400


def test_custom_rule_shadowed_flags(client, auth_headers, fake_service):
    # M-14: rules whose scope a forced rule provably covers first are
    # marked shadowed; ordinary rules are not.
    private_ip = client.post(
        "/api/rules/custom",
        json={"type": "IP-CIDR", "value": "192.168.0.0/16",
              "target": "YouTube"},
        headers=auth_headers,
    ).json()["rule"]
    assert private_ip["shadowed"] is True
    assert "被强制规则覆盖，未生效" in private_ip["shadow_reason"]
    assert "GEOIP,PRIVATE" in private_ip["shadow_reason"]

    private_domain = client.post(
        "/api/rules/custom",
        json={"type": "DOMAIN-SUFFIX", "value": "localhost",
              "target": "DIRECT"},
        headers=auth_headers,
    ).json()["rule"]
    assert private_domain["shadowed"] is True
    assert "GEOSITE,PRIVATE" in private_domain["shadow_reason"]

    normal = client.post(
        "/api/rules/custom",
        json={"type": "DOMAIN-SUFFIX", "value": "example.org",
              "target": "YouTube"},
        headers=auth_headers,
    ).json()["rule"]
    assert normal["shadowed"] is False
    assert normal["shadow_reason"] is None

    listed = client.get("/api/rules/custom", headers=auth_headers).json()
    by_value = {r["value"]: r for r in listed}
    assert by_value["192.168.0.0/16"]["shadowed"] is True
    assert by_value["example.org"]["shadowed"] is False


def test_custom_rule_order_and_move(
    client, auth_headers, fake_service, app
):
    # L-03/L-04: the list order is the generation order, moving a
    # rule persists (sort_order) and changes the compiled order.
    from app.config_builder import build_from_db

    def _add(value):
        return client.post(
            "/api/rules/custom",
            json={"type": "DOMAIN-SUFFIX", "value": value,
                  "target": "YouTube"},
            headers=auth_headers,
        ).json()["rule"]

    a = _add("a.example")
    b = _add("b.example")
    c = _add("c.example")
    listed = client.get("/api/rules/custom", headers=auth_headers).json()
    assert [r["value"] for r in listed] == [
        "a.example", "b.example", "c.example",
    ]
    assert [r["sort_order"] for r in listed] == sorted(
        r["sort_order"] for r in listed
    )

    # Move b up: compiled order becomes b, a, c.
    moved = client.post(
        f"/api/rules/custom/{b['id']}/move",
        json={"direction": "up"},
        headers=auth_headers,
    ).json()
    assert moved["moved"] is True
    listed = client.get("/api/rules/custom", headers=auth_headers).json()
    assert [r["value"] for r in listed] == [
        "b.example", "a.example", "c.example",
    ]
    # Persisted: a fresh DB read and the compiled config agree.
    assert [r["value"] for r in app.state.db.list_custom_rules()] == [
        "b.example", "a.example", "c.example",
    ]
    app.state.db.set_setting("mihomo_secret", "test-secret")
    app.state.db.set_setting("ss_password", "test-ss-pass")
    compiled = build_from_db(app.state.db)["rules"]
    customs = [r for r in compiled if "example" in r]
    assert customs == [
        "DOMAIN-SUFFIX,b.example,YouTube",
        "DOMAIN-SUFFIX,a.example,YouTube",
        "DOMAIN-SUFFIX,c.example,YouTube",
    ]

    # Moving the top rule up is a no-op, not an error.
    again = client.post(
        f"/api/rules/custom/{b['id']}/move",
        json={"direction": "up"},
        headers=auth_headers,
    ).json()
    assert again["moved"] is False
    # Move it back down restores the original order.
    client.post(
        f"/api/rules/custom/{b['id']}/move",
        json={"direction": "down"},
        headers=auth_headers,
    )
    listed = client.get("/api/rules/custom", headers=auth_headers).json()
    assert [r["value"] for r in listed] == [
        "a.example", "b.example", "c.example",
    ]
    assert client.post(
        "/api/rules/custom/999999/move",
        json={"direction": "up"},
        headers=auth_headers,
    ).status_code == 404


# ----------------------------------------------------------------- settings
def test_settings_desensitized(client, auth_headers, app):
    app.state.db.set_setting("ss_password", "fake-ss-secret")
    app.state.db.set_setting("mihomo_secret", "fake-mihomo-secret")
    body = client.get("/api/settings", headers=auth_headers).json()
    assert "fake-ss-secret" not in str(body)
    assert "fake-mihomo-secret" not in str(body)
    assert body["ss_password_set"] is True
    assert body["mihomo_secret_set"] is True
    assert body["mixed_auth_pass_set"] is False
    assert body["ss_port"] == 10001


def test_settings_update_validates(client, auth_headers):
    assert client.put(
        "/api/settings", json={"ss_port": 0}, headers=auth_headers
    ).status_code == 400
    assert client.put(
        "/api/settings", json={"ss_port": 70000}, headers=auth_headers
    ).status_code == 400
    assert client.put(
        "/api/settings", json={"ss_cipher": "rc4"}, headers=auth_headers
    ).status_code == 400
    body = client.put(
        "/api/settings",
        json={"ss_port": 10002, "ss_cipher": "2022-blake3-aes-128-gcm"},
        headers=auth_headers,
    ).json()
    assert body["settings"]["ss_port"] == 10002
    assert body["settings"]["ss_cipher"] == "2022-blake3-aes-128-gcm"
    assert body["reload"]["ok"] is True


def test_admin_password_change(client, auth_headers):
    assert client.post(
        "/api/settings/admin-password",
        json={"current_password": "wrong",
              "new_password": "new-password-123"},
        headers=auth_headers,
    ).status_code == 403
    assert client.post(
        "/api/settings/admin-password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "short"},
        headers=auth_headers,
    ).status_code == 400
    assert client.post(
        "/api/settings/admin-password",
        json={"current_password": ADMIN_PASSWORD,
              "new_password": "new-password-123"},
        headers=auth_headers,
    ).status_code == 200
    # Password change revokes all tokens, including the caller's.
    assert client.get("/api/nodes", headers=auth_headers).status_code == 401
    assert client.post(
        "/api/auth/login", json={"password": "new-password-123"}
    ).status_code == 200


# ---------------------------------------------------------------- speedtest
def test_speedtest_single_and_all(client, auth_headers, fake_client):
    node = _add_node(client, auth_headers)
    other = _add_node(client, auth_headers, SS_URI_2)
    fake_client.delays = {"NodeOne": 88, "NodeTwo": 250}
    fake_client.failing = {"NodeTwo"}

    single = client.post(
        f"/api/nodes/{node['id']}/speedtest", headers=auth_headers
    ).json()
    assert single == {"id": node["id"], "name": "NodeOne", "online": True,
                      "delay_ms": 88, "error": None}
    stored = client.get(
        f"/api/nodes/{node['id']}", headers=auth_headers
    ).json()
    assert stored["last_delay_ms"] == 88
    assert stored["last_online"] is True
    assert stored["last_delay_at"] is not None

    all_result = client.post(
        "/api/nodes/speedtest-all", headers=auth_headers
    ).json()
    assert all_result["tested"] == 2
    by_name = {r["name"]: r for r in all_result["results"]}
    assert by_name["NodeOne"]["online"] is True
    assert by_name["NodeTwo"]["online"] is False
    assert "timed out" in by_name["NodeTwo"]["error"]
    stored_two = client.get(
        f"/api/nodes/{other['id']}", headers=auth_headers
    ).json()
    assert stored_two["last_online"] is False
    assert stored_two["last_delay_ms"] is None


def test_speedtest_disabled_node(client, auth_headers):
    node = _add_node(client, auth_headers)
    client.put(
        f"/api/nodes/{node['id']}", json={"enabled": False},
        headers=auth_headers,
    )
    body = client.post(
        f"/api/nodes/{node['id']}/speedtest", headers=auth_headers
    ).json()
    assert body["online"] is False
    assert "disabled" in body["error"]
