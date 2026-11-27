"""Unit tests for app.config_builder.

Covers cold start, multi-node fallback/url-test compilation, the DNS
baseline, forced-rule order, custom rules, and the no-placeholder
guarantee. All fixtures use fake secrets and example.com hosts.
"""

import pytest
import yaml

from app.config_builder import (
    AI_DOMAINS,
    FORCED_RULES,
    HEALTH_CHECK_URL,
    build_config,
    build_from_db,
    dump_yaml,
    write_config_file,
)
from app.database import Database

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


# --------------------------------------------------------------- cold start
def test_cold_start_valid_yaml_groups_point_at_direct():
    config = build_config([], [], [], SETTINGS)
    text = dump_yaml(config)
    reparsed = yaml.safe_load(text)
    assert reparsed == config  # round-trips cleanly
    assert config["proxies"] == []
    assert len(config["proxy-groups"]) == 14  # v0.8.0 group count
    for group in config["proxy-groups"]:
        assert group["proxies"] == ["DIRECT"], group["name"]
        assert group["type"] == "fallback"
    assert config["rules"][-1] == "MATCH,Default"


def test_cold_start_has_all_baseline_sections():
    config = build_config([], [], [], SETTINGS)
    assert config["ipv6"] is False
    assert config["tcp-concurrent"] is True
    assert config["unified-delay"] is True
    assert config["find-process-mode"] == "off"
    assert config["external-controller"] == "0.0.0.0:9090"
    assert config["secret"] == "fake-mihomo-secret"
    listeners = {l["name"]: l for l in config["listeners"]}
    assert listeners["lan-ss"] == {
        "name": "lan-ss",
        "type": "shadowsocks",
        "listen": "0.0.0.0",
        "port": 10001,
        "cipher": "aes-128-gcm",
        "password": "fake-ss-password",
        "udp": True,
    }
    assert listeners["lan-mixed"] == {
        "name": "lan-mixed",
        "type": "mixed",
        "listen": "0.0.0.0",
        "port": 7890,
        "udp": True,
    }
    assert config["sniffer"] == {
        "enable": True,
        "parse-pure-ip": True,
        "sniff": {
            "HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
            "TLS": {"ports": [443, 8443]},
            "QUIC": {"ports": [443, 8443]},
        },
    }


# ---------------------------------------------------------------------- DNS
def test_dns_baseline_exact_values():
    """Cold start (zero nodes): Default has no live node, so the DNS
    section has NO fallback — fallback DoH rides through the Default
    group, and with Default unbound it would go out direct (H-04).
    Everything else keeps the baseline values."""
    config = build_config([], [], [], SETTINGS)
    assert config["dns"] == {
        "enable": True,
        "ipv6": False,
        "prefer-h3": False,
        "cache-algorithm": "arc",
        "enhanced-mode": "redir-host",
        "respect-rules": True,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        # M-40: proxy hostnames resolve via a trusted overseas DoH,
        # not domestic UDP (a poisoned answer would fake a node
        # offline).
        "proxy-server-nameserver": ["https://dns.google/dns-query"],
        "direct-nameserver": ["223.5.5.5", "119.29.29.29"],
        "nameserver-policy": {
            "geosite:private,cn": ["223.5.5.5", "119.29.29.29"],
        },
        "nameserver": [
            "https://dns.alidns.com/dns-query",
            "https://doh.pub/dns-query",
        ],
        # M-39: fallback-filter carries ipcidr + domain (mihomo
        # actual format: CIDRs, "+." suffix patterns).
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "CN",
            "geosite": ["gfw"],
            "ipcidr": ["240.0.0.0/4", "0.0.0.0/32"],
            "domain": ["+.google.com", "+.youtube.com"],
        },
    }


def test_dns_schema_matches_mihomo_docs():
    """L-31: every generated DNS field checked against the mihomo
    v1.19.34 DNS table (config/config.go): key set, value domains,
    URL schemes, and cross-field references (fallback #group must
    name an existing proxy group; default-nameserver must be plain
    IPs — they bootstrap the DoH hostnames)."""
    import ipaddress
    import urllib.parse

    config = build_config([], [], [], SETTINGS)
    dns = config["dns"]
    # Merged (H-04): zero nodes means no live Default, so the zero-node
    # build omits `fallback` entirely (a #Default fallback would leak
    # DNS out direct). The live-Default shape is checked below.
    assert "fallback" not in dns
    allowed_keys = {
        "enable", "ipv6", "prefer-h3", "ipv6-timeout", "use-hosts",
        "use-system-hosts", "respect-rules", "nameserver", "fallback",
        "fallback-filter", "fallback-lazy-query", "listen",
        "enhanced-mode", "fake-ip-range", "fake-ip-range6",
        "fake-ip-filter", "fake-ip-filter-mode", "fake-ip-ttl",
        "default-nameserver", "cache-algorithm", "cache-max-size",
        "nameserver-policy", "proxy-server-nameserver",
        "proxy-server-nameserver-policy", "direct-nameserver",
        "direct-nameserver-follow-policy",
    }
    assert set(dns) <= allowed_keys, set(dns) - allowed_keys
    assert dns["enable"] is True
    assert dns["enhanced-mode"] in ("normal", "redir-host", "fake-ip")
    assert dns["cache-algorithm"] in ("lru", "arc")
    # default-nameserver: plain IPs only (bootstrap resolvers).
    for entry in dns["default-nameserver"]:
        ipaddress.ip_address(entry)
    # nameserver / proxy-server-nameserver: URL grammar — bare IP
    # (UDP/53) or https:// DoH (tls:// / tcp:// also legal).
    # (`fallback` is absent in this zero-node build; its grammar is
    # checked on the live-Default build below.)
    for key in ("nameserver", "proxy-server-nameserver"):
        assert dns[key], f"{key} must not be empty"
        for entry in dns[key]:
            base = entry.split("#", 1)[0]
            try:
                ipaddress.ip_address(base)
            except ValueError:
                parsed = urllib.parse.urlparse(base)
                assert parsed.scheme in (
                    "https", "tls", "tcp", "udp", "quic", "h3",
                ), f"{key} entry {entry!r} has an unsupported scheme"
                assert parsed.netloc, f"{key} entry {entry!r} has no host"
    # Live Default: fallback appears, with the same grammar + a
    # #Default fragment naming a real proxy group.
    live = build_config(
        [_node(1, "Node-A")], [_binding("default", 1, role="main")],
        [], SETTINGS,
    )
    live_dns = live["dns"]
    assert set(live_dns) <= allowed_keys, set(live_dns) - allowed_keys
    assert live_dns["fallback"] == [
        "https://1.1.1.1/dns-query#Default",
        "https://8.8.8.8/dns-query#Default",
    ]
    live_groups = {g["name"] for g in live["proxy-groups"]}
    for entry in live_dns["fallback"]:
        assert "#" in entry, f"fallback {entry!r} needs a #group fragment"
        assert entry.split("#", 1)[1] in live_groups
        base = entry.split("#", 1)[0]
        parsed = urllib.parse.urlparse(base)
        assert parsed.scheme == "https", f"fallback {entry!r} is not DoH"
        assert parsed.netloc, f"fallback {entry!r} has no host"
    # fallback-filter: documented keys only; ipcidr entries are
    # CIDRs; domain entries are "+." patterns or plain domains;
    # geosite entries are category names.
    ff = dns["fallback-filter"]
    assert set(ff) <= {"geoip", "geoip-code", "geosite", "ipcidr", "domain"}
    assert ff["geoip"] is True
    assert ff["geoip-code"] == "CN"
    for cidr in ff["ipcidr"]:
        ipaddress.ip_network(cidr, strict=False)
    for domain in ff["domain"]:
        assert domain.startswith("+.") or "." in domain
        assert "," not in domain and " " not in domain
    assert ff["geosite"] == ["gfw"]
    # nameserver-policy keys use the documented geosite: form.
    for key in dns["nameserver-policy"]:
        assert key.startswith("geosite:") or "." in key, key
    # YAML round-trip keeps every DNS value intact.
    reparsed = yaml.safe_load(dump_yaml(config))
    assert reparsed["dns"] == dns


def test_dns_fallback_fragment_survives_yaml_round_trip():
    """The '#Default' fragment must survive as part of the scalar.
    Fallback is only emitted while Default has a live node, so the
    fixture binds one (a zero-node cold start has no fallback)."""
    nodes = [_node(1, "Node-A")]
    bindings = [_binding("default", 1, role="main")]
    config = build_config(nodes, bindings, [], SETTINGS)
    reparsed = yaml.safe_load(dump_yaml(config))
    assert reparsed["dns"]["fallback"] == [
        "https://1.1.1.1/dns-query#Default",
        "https://8.8.8.8/dns-query#Default",
    ]


# ------------------------------------------------- fallback / url-test groups
def test_multi_node_fallback_compilation():
    nodes = [_node(1, "Node-A"), _node(2, "Node-B"), _node(3, "Node-C")]
    bindings = [
        _binding("youtube", 1, role="main"),
        _binding("youtube", 2, role="backup"),
        _binding("default", 3, role="main"),
    ]
    config = build_config(nodes, bindings, [], SETTINGS)
    groups = _groups(config)
    assert groups["YouTube"]["type"] == "fallback"
    assert groups["YouTube"]["proxies"] == ["Node-A", "Node-B"]
    assert groups["YouTube"]["url"] == HEALTH_CHECK_URL
    assert groups["YouTube"]["interval"] == 60
    assert groups["YouTube"]["timeout"] == 5000
    assert groups["YouTube"]["lazy"] is False
    assert groups["Default"]["proxies"] == ["Node-C"]
    # Unbound groups fall back to DIRECT.
    assert groups["Telegram"]["proxies"] == ["DIRECT"]
    assert groups["Streaming"]["proxies"] == ["DIRECT"]
    assert groups["AI"]["proxies"] == ["DIRECT"]
    assert [p["name"] for p in config["proxies"]] == [
        "Node-A", "Node-B", "Node-C",
    ]


def test_health_check_values_on_every_group():
    """Regression test for the 2026-11-24 failover outage.

    mihomo's group `timeout` is in MILLISECONDS while `interval` is in
    SECONDS. The old config wrote timeout=5 (5ms), so every scheduled
    health check timed out, every proxy stayed "dead", and fallback
    groups never switched nodes at runtime. Pin the correct values on
    all 14 groups, plus lazy=False (mihomo defaults lazy=true, which
    skips checks for idle groups and lets health data go stale).
    """
    nodes = [_node(1, "Node-A"), _node(2, "Node-B")]
    bindings = [_binding("youtube", 1, role="main")]
    config = build_config(nodes, bindings, [], SETTINGS)
    assert len(config["proxy-groups"]) == 14
    for group in config["proxy-groups"]:
        assert group["url"] == HEALTH_CHECK_URL
        assert group["interval"] == 60
        assert group["timeout"] == 5000
        assert group["lazy"] is False


def test_url_test_mode_per_group():
    nodes = [_node(1, "Node-A"), _node(2, "Node-B")]
    bindings = [
        _binding("ai", 1, role="main", mode="url-test"),
        _binding("ai", 2, role="backup", mode="url-test"),
    ]
    config = build_config(nodes, bindings, [], SETTINGS)
    groups = _groups(config)
    assert groups["AI"]["type"] == "url-test"
    assert groups["AI"]["proxies"] == ["Node-A", "Node-B"]
    assert groups["YouTube"]["type"] == "fallback"


def test_disabled_or_missing_nodes_skipped():
    """H-03: a bound group whose nodes all died compiles to REJECT,
    never to a silent DIRECT. The disabled main (id 1) and the
    deleted backup (id 99) both resolve to nothing, but the binding
    rows still exist — so YouTube must fail closed."""
    nodes = [_node(1, "Node-A", enabled=False), _node(2, "Node-B")]
    bindings = [
        _binding("youtube", 1, role="main"),   # disabled -> skipped
        _binding("youtube", 99, role="backup"),  # deleted -> skipped
        _binding("telegram", 2, role="main"),
    ]
    config = build_config(nodes, bindings, [], SETTINGS)
    groups = _groups(config)
    assert groups["YouTube"]["proxies"] == ["REJECT"]
    assert groups["Telegram"]["proxies"] == ["Node-B"]
    assert [p["name"] for p in config["proxies"]] == ["Node-B"]


def test_duplicate_node_names_deduplicated():
    nodes = [_node(1, "Same"), _node(2, "Same")]
    bindings = [_binding("default", 1, role="main"),
                _binding("default", 2, role="backup")]
    config = build_config(nodes, bindings, [], SETTINGS)
    assert [p["name"] for p in config["proxies"]] == ["Same", "Same (2)"]
    assert _groups(config)["Default"]["proxies"] == ["Same", "Same (2)"]


# --------------------------------------------------------------------- rules
def test_forced_rules_order():
    config = build_config([], [], [], SETTINGS)
    assert config["rules"][:4] == FORCED_RULES
    assert config["rules"][:4] == [
        "GEOIP,PRIVATE,DIRECT",
        "GEOSITE,PRIVATE,DIRECT",
        "GEOSITE,CN,DIRECT",
        "GEOIP,CN,DIRECT",
    ]


def test_business_rules_present():
    config = build_config([], [], [], SETTINGS)
    rules = config["rules"]
    assert "GEOSITE,youtube,YouTube" in rules
    assert "GEOSITE,telegram,Telegram" in rules
    assert "GEOIP,telegram,Telegram" in rules
    # v0.8.0: Netflix split out of Streaming into its own group.
    assert "GEOSITE,netflix,Netflix" in rules
    assert "GEOSITE,netflix,Streaming" not in rules
    assert "GEOSITE,tiktok,TikTok" in rules
    assert "GEOSITE,spotify,Spotify" in rules
    assert "GEOSITE,twitter,Twitter" in rules
    assert "GEOSITE,facebook,Facebook" in rules
    assert "GEOSITE,disney,Streaming" in rules
    assert "GEOSITE,hbo,Streaming" in rules
    assert "GEOSITE,hulu,Streaming" in rules
    assert "GEOSITE,primevideo,Streaming" in rules
    for domain in AI_DOMAINS:
        assert f"DOMAIN-SUFFIX,{domain},AI" in rules
    # Every curated domain the task book named must be present.
    for required in (
        "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
        "gemini.google.com", "ai.google.dev",
        "generativelanguage.googleapis.com",
    ):
        assert required in AI_DOMAINS
    assert "GEOSITE,google,Google" in rules
    assert "GEOSITE,apple,Apple" in rules
    assert "GEOSITE,microsoft,Microsoft" in rules
    assert "GEOSITE,bilibili,Bilibili" in rules
    assert rules[-1] == "MATCH,Default"


def test_ai_rules_come_before_google_rule():
    """gemini.google.com etc. are google.com subdomains: if the Google
    geosite rule came first, the AI group would never match them."""
    config = build_config([], [], [], SETTINGS)
    rules = config["rules"]
    google_idx = rules.index("GEOSITE,google,Google")
    for domain in AI_DOMAINS:
        assert rules.index(f"DOMAIN-SUFFIX,{domain},AI") < google_idx


def test_fourteen_proxy_groups_all_english_names():
    """v0.8.0: 14 groups, every display name English, in rule order."""
    from app.config_builder import GROUP_KEYS
    from app.models import GROUP_DISPLAY_NAMES

    config = build_config([], [], [], SETTINGS)
    names = [g["name"] for g in config["proxy-groups"]]
    assert names == [GROUP_DISPLAY_NAMES[k] for k in GROUP_KEYS]
    assert len(names) == 14
    assert all(name.isascii() for name in names)


def test_direct_groups_fall_back_to_direct_when_unbound():
    """Apple/Microsoft/Bilibili stay unbound by design; the compiler's
    empty-group fallback makes them DIRECT groups."""
    nodes = [_node(1, "Node-A")]
    bindings = [
        _binding("default", 1, role="main"),
        _binding("youtube", 1, role="main"),
    ]
    config = build_config(nodes, bindings, [], SETTINGS)
    groups = _groups(config)
    assert groups["Apple"]["proxies"] == ["DIRECT"]
    assert groups["Microsoft"]["proxies"] == ["DIRECT"]
    assert groups["Bilibili"]["proxies"] == ["DIRECT"]
    assert groups["Default"]["proxies"] == ["Node-A"]
    assert groups["YouTube"]["proxies"] == ["Node-A"]


def test_custom_rules_inserted_between_forced_and_business():
    rules = [
        {"type": "DOMAIN-SUFFIX", "value": "example.org",
         "target": "YouTube", "enabled": True},
        {"type": "IP-CIDR", "value": "203.0.113.0/24",
         "target": "DIRECT", "enabled": True},
        {"type": "DOMAIN-KEYWORD", "value": "skipped",
         "target": "REJECT", "enabled": False},
    ]
    config = build_config([], [], rules, SETTINGS)
    compiled = config["rules"]
    assert compiled[4] == "DOMAIN-SUFFIX,example.org,YouTube"
    assert compiled[5] == "IP-CIDR,203.0.113.0/24,DIRECT"
    assert not any("skipped" in r for r in compiled)
    assert compiled[6] == "GEOSITE,youtube,YouTube"


def test_invalid_custom_rule_rejected():
    with pytest.raises(ValueError, match="invalid custom rule type"):
        build_config([], [], [
            {"type": "DOMAIN", "value": "x", "target": "DIRECT",
             "enabled": True},
        ], SETTINGS)


def test_invalid_custom_rule_target_rejected():
    # M-12: the compiler shares the save-path validator — an unknown
    # target must fail the compile, never be emitted.
    with pytest.raises(ValueError, match="invalid rule target"):
        build_config([], [], [
            {"type": "DOMAIN-SUFFIX", "value": "example.org",
             "target": "NotAGroup", "enabled": True},
        ], SETTINGS)


def test_custom_rule_comma_value_rejected():
    # M-12: a comma in the value would split the generated
    # "TYPE,value,target" CSV line and corrupt the rule.
    with pytest.raises(ValueError, match="must not contain spaces or commas"):
        build_config([], [], [
            {"type": "DOMAIN-SUFFIX", "value": "a.org,b.org",
             "target": "DIRECT", "enabled": True},
        ], SETTINGS)


def test_custom_rule_invalid_cidr_rejected():
    # M-12: CIDR values are checked with the ipaddress module.
    with pytest.raises(ValueError, match="invalid IP-CIDR"):
        build_config([], [], [
            {"type": "IP-CIDR", "value": "not-an-ip",
             "target": "DIRECT", "enabled": True},
        ], SETTINGS)
    with pytest.raises(ValueError, match="invalid IP-CIDR"):
        build_config([], [], [
            {"type": "IP-CIDR", "value": "10.0.0.0/33",
             "target": "DIRECT", "enabled": True},
        ], SETTINGS)


def test_custom_rule_invalid_domain_rejected():
    with pytest.raises(ValueError, match="invalid domain value"):
        build_config([], [], [
            {"type": "DOMAIN-SUFFIX", "value": "bad_domain",
             "target": "DIRECT", "enabled": True},
        ], SETTINGS)


def test_disabled_invalid_custom_rule_ignored():
    # Disabled rules are skipped before validation (same as before):
    # a disabled bad row must not break the compile.
    config = build_config([], [], [
        {"type": "DOMAIN", "value": "x", "target": "DIRECT",
         "enabled": False},
    ], SETTINGS)
    assert not any("DOMAIN,x" in r for r in config["rules"])


# --------------------------------------------------------- secrets / output
def test_no_placeholders_in_output():
    nodes = [_node(1, "Node-A")]
    config = build_config(
        nodes, [_binding("default", 1, role="main")], [], SETTINGS
    )
    text = dump_yaml(config)
    assert "${" not in text
    assert "fake-mihomo-secret" in text
    assert "fake-ss-password" in text


def test_missing_secrets_rejected_not_rendered():
    no_secret = dict(SETTINGS, mihomo_secret="")
    with pytest.raises(ValueError, match="mihomo_secret"):
        build_config([], [], [], no_secret)
    no_ss_pass = dict(SETTINGS, ss_password="")
    with pytest.raises(ValueError, match="ss_password"):
        build_config([], [], [], no_ss_pass)


def test_settings_override_ports_cipher_and_mixed_auth():
    settings = dict(
        SETTINGS,
        ss_port=10002,
        ss_cipher="2022-blake3-aes-128-gcm",
        mixed_port=7891,
        mixed_auth_user="lanuser",
        mixed_auth_pass="fake-mixed-pass",
    )
    config = build_config([], [], [], settings)
    listeners = {l["name"]: l for l in config["listeners"]}
    assert listeners["lan-ss"]["port"] == 10002
    assert listeners["lan-ss"]["cipher"] == "2022-blake3-aes-128-gcm"
    assert listeners["lan-mixed"]["port"] == 7891
    assert listeners["lan-mixed"]["username"] == "lanuser"
    assert listeners["lan-mixed"]["password"] == "fake-mixed-pass"


def test_write_config_file_round_trip(tmp_path):
    config = build_config([], [], [], SETTINGS)
    target = write_config_file(config, tmp_path / "config.yaml")
    assert yaml.safe_load(target.read_text(encoding="utf-8")) == config


def test_unique_proxy_names_suffix_never_collides():
    # H-10: a user-owned "X (2)" plus a second "X" must not produce
    # a duplicate "X (2)" — the generated suffix keeps incrementing
    # against the final name set.
    from app.config_builder import _unique_proxy_names
    names = _unique_proxy_names([
        {"id": 1, "name": "X"},
        {"id": 2, "name": "X (2)"},
        {"id": 3, "name": "X"},
        {"id": 4, "name": "X"},
    ])
    assert names == {1: "X", 2: "X (2)", 3: "X (3)", 4: "X (4)"}
    assert len(set(names.values())) == 4


def test_special_char_name_survives_yaml_round_trip():
    # L-15: a name with YAML-special characters (colon, hash, quotes)
    # round-trips exactly through yaml.safe_dump / safe_load, so the
    # generated config names the proxy the user named.
    weird = 'Test: "quoted" #hash : colon'
    config = build_config([_node(1, weird)], [], [], SETTINGS)
    text = dump_yaml(config)
    loaded = yaml.safe_load(text)
    assert loaded["proxies"][0]["name"] == weird
    assert len({p["name"] for p in loaded["proxies"]}) == 1


def test_write_config_file_unwritable_path_errors(tmp_path):
    # L-12: a destination whose parent cannot be created (a file
    # sits where the directory should be) fails with an explicit
    # error instead of a bare OS traceback mid-write.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    with pytest.raises(OSError, match="cannot create config directory"):
        write_config_file(
            build_config([], [], [], SETTINGS),
            blocker / "config.yaml",
        )


# ------------------------------------------------------------ DB integration
def test_build_from_db(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    db.set_setting("mihomo_secret", "fake-mihomo-secret")
    db.set_setting("ss_password", "fake-ss-password")
    node_a = db.add_node("Node-A", "ss://fake-a@example.com:8388",
                         _node(0, "Node-A")["proxy"])
    node_b = db.add_node("Node-B", "ss://fake-b@example.com:8388",
                         _node(0, "Node-B")["proxy"])
    db.set_binding("youtube", node_a, role="main")
    db.set_binding("youtube", node_b, role="backup")
    db.add_custom_rule("DOMAIN-SUFFIX", "example.org", "Telegram")
    config = build_from_db(db)
    groups = _groups(config)
    assert groups["YouTube"]["proxies"] == ["Node-A", "Node-B"]
    assert "DOMAIN-SUFFIX,example.org,Telegram" in config["rules"]
    db.close()


# ------------------------------------------------------------ external-ui
def test_external_ui_emitted_when_set():
    settings = dict(SETTINGS, external_ui="/opt/lanmux/metacubexd")
    config = build_config([], [], [], settings)
    assert config["external-ui"] == "/opt/lanmux/metacubexd"


def test_external_ui_survives_yaml_round_trip(tmp_path):
    settings = dict(SETTINGS, external_ui="/opt/lanmux/metacubexd")
    config = build_config([], [], [], settings)
    target = write_config_file(config, tmp_path / "config.yaml")
    loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert loaded["external-ui"] == "/opt/lanmux/metacubexd"


def test_external_ui_omitted_when_unset():
    config = build_config([], [], [], SETTINGS)
    assert "external-ui" not in config


def test_external_ui_omitted_when_blank():
    settings = dict(SETTINGS, external_ui="   ")
    config = build_config([], [], [], settings)
    assert "external-ui" not in config


def test_external_ui_from_db(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    db.set_setting("mihomo_secret", "fake-mihomo-secret")
    db.set_setting("ss_password", "fake-ss-password")
    db.set_setting("external_ui", "/opt/lanmux/metacubexd")
    config = build_from_db(db)
    assert config["external-ui"] == "/opt/lanmux/metacubexd"
    db.close()
