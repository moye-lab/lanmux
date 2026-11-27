"""Route-check tests: rule matching order, group resolution, fallback.

The mihomo client is faked — no network is used. Key properties under
test:

* matching follows the config compiler's rule order (AI rules before
  GEOSITE,google; custom rules before business rules);
* the current node prefers mihomo's live ``now``, and degrades to DB
  probe-state inference when mihomo is down — never a 500;
* an unmatched domain reports honestly, with the downstream path
  (GEOIP CN -> DIRECT, otherwise MATCH -> Default).
"""

import pytest
from fastapi.testclient import TestClient

from app.config_builder import build_from_db, domain_matchable_rules
from app.auth import hash_password
from app.deps import get_mihomo_client
from app.main import create_app
from app.mihomo_client import MihomoError

ADMIN_PASSWORD = "test-admin-password"

SS_PROXY = {
    "type": "ss", "server": "1.2.3.4", "port": 8388,
    "password": "pw", "cipher": "aes-128-gcm",
}
HY_PROXY = {
    "type": "hysteria2", "server": "5.6.7.8", "port": 443,
    "password": "pw2", "sni": "example.com",
}


class FakeClient:
    def __init__(self):
        self.down = False
        self.now = {}

    def _maybe_down(self):
        if self.down:
            raise MihomoError(
                "cannot reach mihomo at http://127.0.0.1:9090: refused",
                connection_error=True,
            )

    def get_version(self):
        self._maybe_down()
        return {"version": "fake-1.0-test"}

    def reload_config(self, force=True):
        self._maybe_down()

    def test_delay(self, proxy, url, timeout=5):
        self._maybe_down()
        return 42

    def get_proxy_group(self, name):
        self._maybe_down()
        return {"name": name, "type": "Fallback", "now": self.now.get(name)}


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
def seeded(app):
    """Two online nodes; youtube + ai + default bound (main A, backup B)."""
    db = app.state.db
    a = db.add_node("Node-A", "ss://fake-a", dict(SS_PROXY))
    b = db.add_node("Node-B", "ss://fake-b", dict(HY_PROXY))
    db.update_node(a, last_online=True, last_delay_ms=12)
    db.update_node(b, last_online=True, last_delay_ms=30)
    for group in ("youtube", "ai", "default"):
        db.set_binding(group, a, role="main", mode="fallback")
        db.set_binding(group, b, role="backup", mode="fallback")
    return {"a": a, "b": b}


def _check(client, auth_headers, domain):
    return client.post(
        "/api/diagnostics/route-check",
        headers=auth_headers,
        json={"domain": domain},
    )


def test_route_check_requires_auth(client, seeded):
    assert _check(client, {}, "youtube.com").status_code == 401


def test_youtube_matches_youtube_group(
    client, auth_headers, seeded, fake_client
):
    fake_client.now = {"YouTube": "Node-B"}
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["matched"] is True
    assert body["rule"] == "GEOSITE,youtube,YouTube"
    assert body["rule_kind"] == "geosite"
    assert body["group"] == "YouTube"
    assert body["group_key"] == "youtube"
    assert body["effective_target"] == "YouTube"
    assert body["policy"] == "fallback"
    assert body["main"]["name"] == "Node-A"
    assert [n["name"] for n in body["backups"]] == ["Node-B"]
    # Live mihomo `now` wins over the DB main node.
    assert body["current"]["name"] == "Node-B"
    assert body["current"]["delay_ms"] == 30
    assert body["current_source"] == "mihomo"
    assert body["mihomo_reachable"] is True


def test_subdomain_matches_suffix(client, auth_headers, seeded):
    body = _check(client, auth_headers, "www.youtube.com").json()
    assert body["matched"] is True
    assert body["group"] == "YouTube"


def test_gemini_goes_to_ai_not_google(client, auth_headers, seeded):
    # gemini.google.com is a google.com subdomain: the AI
    # DOMAIN-SUFFIX rules must win over GEOSITE,google.
    body = _check(client, auth_headers, "gemini.google.com").json()
    assert body["matched"] is True
    assert body["rule"] == "DOMAIN-SUFFIX,gemini.google.com,AI"
    assert body["group"] == "AI"
    assert body["group_key"] == "ai"


def test_apple_group_resolves_direct(client, auth_headers, seeded):
    # Apple is unbound in the seed: the group compiles to ["DIRECT"].
    body = _check(client, auth_headers, "www.apple.com").json()
    assert body["matched"] is True
    assert body["rule"] == "GEOSITE,apple,Apple"
    assert body["group"] == "Apple"
    assert body["effective_target"] == "DIRECT"
    assert body["current"] is None
    assert body["main"] is None
    assert body["backups"] == []


def test_unknown_domain_reports_no_match(client, auth_headers, seeded):
    body = _check(client, auth_headers, "unknown.example.org").json()
    assert body["matched"] is False
    assert body["rule"] is None
    assert body["group"] is None
    assert "未命中域名规则" in body["note"]
    assert "GEOIP,CN" in body["note"]
    assert "Default" in body["note"]
    # The downstream path is spelled out: MATCH -> Default group.
    assert body["default_group"]["group"] == "Default"
    assert body["default_group"]["main"]["name"] == "Node-A"


def test_custom_rule_beats_business_rules(client, auth_headers, seeded, app):
    app.state.db.add_custom_rule(
        "DOMAIN-SUFFIX", "example.org", "Netflix", enabled=True
    )
    body = _check(client, auth_headers, "www.example.org").json()
    assert body["matched"] is True
    assert body["rule"] == "DOMAIN-SUFFIX,example.org,Netflix"
    assert body["rule_kind"] == "custom"
    assert body["group"] == "Netflix"


def test_custom_direct_target(client, auth_headers, seeded, app):
    app.state.db.add_custom_rule(
        "DOMAIN-KEYWORD", "internal", "DIRECT", enabled=True
    )
    body = _check(client, auth_headers, "internal.corp.example").json()
    assert body["matched"] is True
    assert body["target"] == "DIRECT"
    assert body["effective_target"] == "DIRECT"
    assert body["group"] is None
    assert body["current"] is None


def test_domain_normalization(client, auth_headers, seeded):
    body = _check(
        client, auth_headers, "HTTPS://YouTube.com/watch?v=1"
    ).json()
    assert body["domain"] == "youtube.com"
    assert body["group"] == "YouTube"


def test_empty_domain_400(client, auth_headers, seeded):
    assert _check(client, auth_headers, "   ").status_code == 400


def test_mihomo_down_infers_main(
    client, auth_headers, seeded, fake_client
):
    fake_client.down = True
    response = _check(client, auth_headers, "youtube.com")
    assert response.status_code == 200  # degradation, not a 500
    body = response.json()
    assert body["mihomo_reachable"] is False
    assert body["current"]["name"] == "Node-A"  # main is online
    assert body["current_source"] == "inferred"


def test_mihomo_down_falls_back_to_backup(
    client, auth_headers, seeded, fake_client, app
):
    fake_client.down = True
    app.state.db.update_node(seeded["a"], last_online=False)
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["current"]["name"] == "Node-B"
    assert body["current_source"] == "inferred"


def test_mihomo_down_all_offline(
    client, auth_headers, seeded, fake_client, app
):
    fake_client.down = True
    app.state.db.update_node(seeded["a"], last_online=False)
    app.state.db.update_node(seeded["b"], last_online=False)
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["current"] is None
    assert body["current_source"] == "inferred"


def test_matchable_rules_follow_config_order(app, seeded):
    """The route-check rule list is a subsequence of the compiled
    config rules, in the same order — matching can never disagree
    with what mihomo actually evaluates."""
    db = app.state.db
    db.set_setting("mihomo_secret", "test-secret")
    db.set_setting("ss_password", "test-ss-pass")
    db.add_custom_rule("DOMAIN-SUFFIX", "example.org", "Netflix")
    config_rules = build_from_db(db)["rules"]
    matchable = domain_matchable_rules(db.list_custom_rules())
    positions = [config_rules.index(r["rule"]) for r in matchable]
    assert positions == sorted(positions)
    # AI rules precede GEOSITE,google in both lists.
    ai_pos = config_rules.index("DOMAIN-SUFFIX,gemini.google.com,AI")
    google_pos = config_rules.index("GEOSITE,google,Google")
    assert ai_pos < google_pos
    matchable_ai = next(
        i for i, r in enumerate(matchable)
        if r["rule"] == "DOMAIN-SUFFIX,gemini.google.com,AI"
    )
    matchable_google = next(
        i for i, r in enumerate(matchable)
        if r["rule"] == "GEOSITE,google,Google"
    )
    assert matchable_ai < matchable_google


# ------------------------------------------------------- forced rules (M-09)
def test_forced_rule_matches_private_ip(client, auth_headers, seeded):
    # A private IP input hits the forced rule first — labelled as the
    # CN egress guard, not as a business-group DIRECT.
    body = _check(client, auth_headers, "192.168.1.5").json()
    assert body["matched"] is True
    assert body["rule"] == "GEOIP,PRIVATE,DIRECT"
    assert body["rule_kind"] == "forced"
    assert body["rule_source"] == "forced"
    assert body["target"] == "DIRECT"
    assert body["effective_target"] == "DIRECT"
    assert body["direct_reason"] == "forced"
    assert body["connection"] == "direct"
    assert "强制 DIRECT（CN 出口防护）" in body["note"]
    forced = {r["rule"]: r for r in body["forced_rules"]}
    assert set(forced) == {
        "GEOIP,PRIVATE,DIRECT",
        "GEOSITE,PRIVATE,DIRECT",
        "GEOSITE,CN,DIRECT",
        "GEOIP,CN,DIRECT",
    }
    assert all(r["source"] == "forced" for r in body["forced_rules"])
    assert all(
        "强制 DIRECT（CN 出口防护）" in r["label"]
        for r in body["forced_rules"]
    )


def test_forced_rule_matches_private_domain(client, auth_headers, seeded):
    body = _check(client, auth_headers, "printer.local").json()
    assert body["matched"] is True
    assert body["rule"] == "GEOSITE,PRIVATE,DIRECT"
    assert body["rule_kind"] == "forced"
    assert body["rule_source"] == "forced"
    assert body["direct_reason"] == "forced"
    assert "强制 DIRECT（CN 出口防护）" in body["note"]


def test_unbound_group_direct_is_business_not_forced(
    client, auth_headers, seeded
):
    # M-09: Apple resolves to DIRECT because the group has no usable
    # members — "业务组 DIRECT", explicitly not the forced rule.
    body = _check(client, auth_headers, "www.apple.com").json()
    assert body["matched"] is True
    assert body["rule"] == "GEOSITE,apple,Apple"
    assert body["rule_source"] == "builtin"
    assert body["effective_target"] == "DIRECT"
    assert body["direct_reason"] == "unbound_group"
    assert "业务组 DIRECT" in body["note"]
    assert "未绑定可用节点" in body["note"]


# ------------------------------------------------- custom IP-CIDR rules (M-10)
def test_custom_ip_cidr_matches_ip_input(
    client, auth_headers, seeded, app
):
    app.state.db.add_custom_rule(
        "IP-CIDR", "45.1.2.0/24", "YouTube", enabled=True
    )
    body = _check(client, auth_headers, "45.1.2.3").json()
    assert body["matched"] is True
    assert body["rule"] == "IP-CIDR,45.1.2.0/24,YouTube"
    assert body["rule_kind"] == "custom"
    assert body["rule_source"] == "custom"
    assert body["group"] == "YouTube"
    assert body["group_key"] == "youtube"


def test_custom_ip_cidr_outside_range_no_match(
    client, auth_headers, seeded, app
):
    app.state.db.add_custom_rule(
        "IP-CIDR", "45.1.2.0/24", "YouTube", enabled=True
    )
    body = _check(client, auth_headers, "45.9.9.9").json()
    assert body["matched"] is False
    assert body["default_group"]["group"] == "Default"


def test_ip_cidr_rules_listed_for_domain_input(
    client, auth_headers, seeded, app
):
    # The diagnostic model includes IP-CIDR rules even when the
    # input is a domain — they just cannot be evaluated from it.
    app.state.db.add_custom_rule(
        "IP-CIDR", "45.1.2.0/24", "YouTube", enabled=True
    )
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["ip_cidr_rules"] == [
        {"rule": "IP-CIDR,45.1.2.0/24,YouTube", "target": "YouTube"}
    ]
    assert "IP-CIDR" in body["note"]
    assert "仅对 IP 输入生效" in body["note"]


def test_matchable_rules_include_ip_cidr_in_config_order(app, seeded):
    db = app.state.db
    db.set_setting("mihomo_secret", "test-secret")
    db.set_setting("ss_password", "test-ss-pass")
    db.add_custom_rule("IP-CIDR", "45.1.2.0/24", "YouTube")
    db.add_custom_rule("DOMAIN-SUFFIX", "example.org", "Netflix")
    config_rules = build_from_db(db)["rules"]
    matchable = domain_matchable_rules(db.list_custom_rules())
    assert any(
        r["rule"] == "IP-CIDR,45.1.2.0/24,YouTube" for r in matchable
    )
    positions = [config_rules.index(r["rule"]) for r in matchable]
    assert positions == sorted(positions)


def test_invalid_custom_rule_filtered_from_diagnosis(
    client, auth_headers, seeded, app
):
    # M-12: a legacy invalid row (written before validation) is
    # invisible to diagnosis — the same validator the compiler uses
    # drops it — while valid rules still diagnose.
    db = app.state.db
    db.add_custom_rule("IP-CIDR", "not-an-ip", "YouTube")
    db.add_custom_rule("DOMAIN-SUFFIX", "example.org", "Netflix")
    matchable = domain_matchable_rules(db.list_custom_rules())
    assert not any("not-an-ip" in r["rule"] for r in matchable)
    assert any(
        r["rule"] == "DOMAIN-SUFFIX,example.org,Netflix"
        for r in matchable
    )
    body = _check(client, auth_headers, "www.example.org").json()
    assert body["matched"] is True
    assert body["group"] == "Netflix"


# ------------------------------------------- group-outside live now (M-11)
def test_live_now_outside_group_ignored(
    client, auth_headers, seeded, fake_client, app
):
    # Node-C exists and is online, but is bound to no group. Mihomo
    # reporting it as YouTube's live `now` must not make it
    # YouTube's diagnosed exit node.
    c = app.state.db.add_node("Node-C", "ss://fake-c", dict(SS_PROXY))
    app.state.db.update_node(c, last_online=True, last_delay_ms=5)
    fake_client.now = {"YouTube": "Node-C"}
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["current"]["name"] == "Node-A"  # inferred group main
    assert body["current_source"] == "inferred"
    assert body["now_outside_group"] == "Node-C"
    assert body["connection"] == "unknown"


# ------------------------------------------------------------ drift (M-13)
def test_drift_annotates_diagnosis(client, auth_headers, seeded, app):
    db = app.state.db
    db.set_setting("config_revision_db", "5")
    db.set_setting("config_revision_running", "3")
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["config_drift"] is True
    assert body["db_revision"] == 5
    assert body["running_revision"] == 3
    assert "基于过期配置，仅供参考" in body["note"]
    assert body["matched"] is True  # still diagnosed, but labelled


def test_no_drift_no_annotation(client, auth_headers, seeded, app):
    db = app.state.db
    db.set_setting("config_revision_db", "2")
    db.set_setting("config_revision_running", "2")
    body = _check(client, auth_headers, "youtube.com").json()
    assert body["config_drift"] is False
    assert "基于过期配置" not in body["note"]


# ------------------------------------------------- domain validation (L-16)
@pytest.mark.parametrize(
    "bad",
    [
        "notadomain",  # no dot, not an IP
        "localhost",  # single label
        "a..b.com",  # empty label
        "-bad.com",
        "bad-.com",
        "exa_mple.com",  # underscore is not a hostname char
        "x" * 64 + ".com",  # label > 63 chars
        "x" * 250 + ".com",  # total > 253 chars
        "example.com:abc",  # non-numeric port
        "http://",  # empty after scheme strip
        "[::1",  # unbalanced bracket
        "1.2.3.4:abc",
    ],
)
def test_invalid_domain_400(client, auth_headers, seeded, bad):
    assert _check(client, auth_headers, bad).status_code == 400


@pytest.mark.parametrize(
    "good,expected",
    [
        ("1.2.3.4", "1.2.3.4"),
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]:8080", "2001:db8::1"),
        ("example.com:8080", "example.com"),
        ("HTTPS://YouTube.com/watch?v=1", "youtube.com"),
    ],
)
def test_valid_domain_and_ip_inputs(
    client, auth_headers, seeded, good, expected
):
    body = _check(client, auth_headers, good)
    assert body.status_code == 200, body.text
    assert body.json()["domain"] == expected
