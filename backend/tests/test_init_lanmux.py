"""Tests for app.init_lanmux (Phase 4 installer helper).

Covers: fresh-install seeding + cold-start config generation, the
seed-only-if-unset upgrade contract (web-changed values are never
clobbered), invalid input handling, and idempotent re-runs. All
fixtures use fake secrets and example.com hosts.
"""

import pytest
import yaml

from app.auth import verify_password
from app.database import Database
from app.init_lanmux import (
    apply_settings,
    init_lanmux,
    main,
    migrate_groups,
    seed_settings,
)

BASE_ENV = {
    "ADMIN_PASSWORD": "fake-admin-password",
    "MIHOMO_SECRET": "fake-mihomo-secret",
    "SS_PASSWORD": "fake-ss-password",
    "SS_CIPHER": "aes-128-gcm",
    "LANMUX_LAN_IP": "10.0.0.2",
    "LANMUX_SS_PORT": "10001",
    "LANMUX_MIXED_PORT": "7890",
    "LANMUX_CONTROLLER_PORT": "9090",
    "LANMUX_EXTERNAL_UI": "/opt/lanmux/metacubexd",
}


def _env(tmp_path, **overrides):
    env = dict(BASE_ENV)
    env["LANMUX_DB_PATH"] = str(tmp_path / "lanmux.db")
    env["LANMUX_CONFIG_PATH"] = str(tmp_path / "config.yaml")
    env.update(overrides)
    return env


def test_fresh_init_seeds_settings_and_writes_cold_start_config(tmp_path):
    config_path = init_lanmux(_env(tmp_path))
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    # Cold start: no nodes, every group falls back to DIRECT.
    for group in config["proxy-groups"]:
        assert group["proxies"] == ["DIRECT"]
    assert config["secret"] == "fake-mihomo-secret"
    assert config["external-ui"] == "/opt/lanmux/metacubexd"
    listeners = {l["name"]: l for l in config["listeners"]}
    assert listeners["lan-ss"]["port"] == 10001
    assert listeners["lan-ss"]["password"] == "fake-ss-password"
    assert listeners["lan-mixed"]["port"] == 7890
    assert config["external-controller"] == "0.0.0.0:9090"

    db = Database(tmp_path / "lanmux.db")
    settings = db.get_settings()
    assert settings.lan_ip == "10.0.0.2"
    assert settings.ss_cipher == "aes-128-gcm"
    assert settings.external_ui == "/opt/lanmux/metacubexd"
    assert verify_password(
        "fake-admin-password", settings.admin_password_hash
    )
    db.close()


def test_init_without_external_ui_omits_key(tmp_path):
    env = _env(tmp_path)
    del env["LANMUX_EXTERNAL_UI"]
    config_path = init_lanmux(env)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert "external-ui" not in config


def test_upgrade_never_clobbers_web_changed_values(tmp_path):
    # First install.
    init_lanmux(_env(tmp_path))
    # The user changes the SS password and SS port via the web UI.
    db = Database(tmp_path / "lanmux.db")
    db.set_setting("ss_password", "web-changed-ss-password")
    db.set_setting("ss_port", "10002")
    db.close()
    # Upgrade re-runs init with the *original* install env.
    config_path = init_lanmux(_env(tmp_path))
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    listeners = {l["name"]: l for l in config["listeners"]}
    assert listeners["lan-ss"]["password"] == "web-changed-ss-password"
    assert listeners["lan-ss"]["port"] == 10002


def test_upgrade_preserves_nodes_and_regenerates_config(tmp_path):
    init_lanmux(_env(tmp_path))
    db = Database(tmp_path / "lanmux.db")
    node_id = db.add_node(
        "Node-A",
        "ss://fake-a@example.com:8388",
        {"name": "Node-A", "type": "ss", "server": "example.com",
         "port": 8388, "cipher": "aes-128-gcm", "password": "fake-pass"},
    )
    db.set_binding("youtube", node_id, role="main")
    db.close()
    config_path = init_lanmux(_env(tmp_path))
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    groups = {g["name"]: g for g in config["proxy-groups"]}
    assert groups["YouTube"]["proxies"] == ["Node-A"]


def test_init_fails_without_secrets(tmp_path):
    env = _env(tmp_path)
    del env["MIHOMO_SECRET"]
    del env["SS_PASSWORD"]
    with pytest.raises(ValueError, match="mihomo_secret"):
        init_lanmux(env)
    assert not (tmp_path / "config.yaml").exists()


def test_seed_settings_rejects_bad_port(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    with pytest.raises(ValueError, match="LANMUX_SS_PORT"):
        seed_settings(db, {"LANMUX_SS_PORT": "not-a-port"})
    with pytest.raises(ValueError, match="LANMUX_MIXED_PORT"):
        seed_settings(db, {"LANMUX_MIXED_PORT": "70000"})
    db.close()


def test_seed_settings_skips_empty_and_stored_values(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    db.set_setting("ss_password", "already-stored")
    seeded = seed_settings(
        db,
        {"SS_PASSWORD": "new-value", "MIHOMO_SECRET": "",
         "LANMUX_LAN_IP": "10.0.0.2"},
    )
    assert seeded == ["lan_ip"]
    assert db.get_setting("ss_password") == "already-stored"
    assert db.get_setting("mihomo_secret") == ""
    db.close()


def test_main_reads_real_environment(tmp_path, monkeypatch, capsys):
    for key, value in _env(tmp_path).items():
        monkeypatch.setenv(key, value)
    assert main([]) == 0
    assert "wrote" in capsys.readouterr().out
    assert (tmp_path / "config.yaml").exists()


def test_main_returns_2_on_bad_input(tmp_path, monkeypatch, capsys):
    for key, value in _env(tmp_path, LANMUX_SS_PORT="nope").items():
        monkeypatch.setenv(key, value)
    assert main([]) == 2
    assert "LANMUX_SS_PORT" in capsys.readouterr().err


def test_main_help_exits_zero(capsys):
    assert main(["--help"]) == 0
    assert "init_lanmux" in capsys.readouterr().out


def test_main_rejects_unknown_argument(capsys):
    assert main(["--bogus"]) == 2
    assert "unknown argument" in capsys.readouterr().err


# ------------------------------------------------------------ --apply-env
def test_apply_env_overwrites_non_secrets_but_not_secrets(tmp_path):
    init_lanmux(_env(tmp_path))
    db = Database(tmp_path / "lanmux.db")
    applied = apply_settings(
        db,
        {
            "LANMUX_MIXED_PORT": "7891",  # non-secret: overwritten
            "LANMUX_LAN_IP": "10.0.0.9",  # non-secret: overwritten
            "SS_PASSWORD": "attacker-value",  # secret: ignored
            "MIHOMO_SECRET": "attacker-value",  # secret: ignored
        },
    )
    assert applied == ["lan_ip", "mixed_port"]
    assert db.get_setting("mixed_port") == "7891"
    assert db.get_setting("lan_ip") == "10.0.0.9"
    assert db.get_setting("ss_password") == "fake-ss-password"
    assert db.get_setting("mihomo_secret") == "fake-mihomo-secret"
    db.close()


def test_apply_env_seeds_missing_secrets(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    applied = apply_settings(
        db, {"SS_PASSWORD": "fresh-secret", "LANMUX_SS_PORT": "10002"}
    )
    assert applied == ["ss_password", "ss_port"]
    assert db.get_setting("ss_password") == "fresh-secret"
    db.close()


def test_init_lanmux_apply_env_regenerates_config_with_new_ports(tmp_path):
    init_lanmux(_env(tmp_path))
    env = _env(tmp_path, LANMUX_MIXED_PORT="7891", LANMUX_SS_PORT="10002")
    config_path = init_lanmux(env, apply_env=True)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    listeners = {l["name"]: l for l in config["listeners"]}
    assert listeners["lan-mixed"]["port"] == 7891
    assert listeners["lan-ss"]["port"] == 10002
    # Secrets survive the --apply-env re-run unchanged.
    assert listeners["lan-ss"]["password"] == "fake-ss-password"
    assert config["secret"] == "fake-mihomo-secret"


# ------------------------------------------------------- v0.8.0 migrations
def _seed_two_nodes_with_default_binding(tmp_path):
    """DB with two nodes; default group bound (main 1, backup 2)."""
    init_lanmux(_env(tmp_path))
    db = Database(tmp_path / "lanmux.db")
    proxy = {
        "name": "Node-A", "type": "ss", "server": "example.com",
        "port": 8388, "cipher": "aes-128-gcm", "password": "fake-pass",
    }
    node_a = db.add_node("Node-A", "ss://fake-a@example.com:8388", proxy)
    node_b = db.add_node(
        "Node-B", "ss://fake-b@example.com:8388",
        {**proxy, "name": "Node-B"},
    )
    db.set_binding("default", node_a, role="main")
    db.set_binding("default", node_b, role="backup")
    return db, node_a, node_b


def test_migrate_groups_inherits_default_binding(tmp_path):
    db, node_a, node_b = _seed_two_nodes_with_default_binding(tmp_path)
    result = migrate_groups(db)
    # Every empty proxy group inherits main + backup from default.
    assert "netflix" in result["inherited"]
    assert "google" in result["inherited"]
    for key in ("netflix", "tiktok", "spotify", "twitter", "facebook",
                "google"):
        rows = db.list_bindings(key)
        assert [(r["node_id"], r["role"]) for r in rows] == [
            (node_a, "main"), (node_b, "backup")
        ]
    # DIRECT groups stay unbound (= DIRECT) on purpose.
    assert "apple" not in result["inherited"]
    assert "microsoft" not in result["inherited"]
    assert "bilibili" not in result["inherited"]
    for key in ("apple", "microsoft", "bilibili"):
        assert db.list_bindings(key) == []
    db.close()


def test_migrate_groups_copies_dangling_default_binding(tmp_path):
    """Merge unification (H-03 + L-19): a Default binding whose node
    was deleted is dangling, not gone. Migrating it into an empty
    group must copy the dangling row verbatim (the group then resolves
    to REJECT, fail-closed) instead of raising at startup — a raise
    here would crash-loop init_lanmux on every boot. The user-facing
    write path still refuses a dangling node id.
    """
    db, node_a, node_b = _seed_two_nodes_with_default_binding(tmp_path)
    db.delete_node(node_a)
    db.delete_node(node_b)
    assert db.list_bindings("default")  # rows survive deletion (H-03)
    with pytest.raises(ValueError, match="unknown node id"):
        db.set_binding("youtube", node_a, role="main")
    result = migrate_groups(db)
    assert "netflix" in result["inherited"]
    rows = db.list_bindings("netflix")
    assert [(r["node_id"], r["role"]) for r in rows] == [
        (node_a, "main"), (node_b, "backup")
    ]
    db.close()


def test_migrate_groups_is_idempotent(tmp_path):
    db, _, _ = _seed_two_nodes_with_default_binding(tmp_path)
    first = migrate_groups(db)
    assert first["inherited"]
    second = migrate_groups(db)
    assert second == {"inherited": [], "renamed": []}
    db.close()


def test_migrate_groups_never_overwrites_existing_bindings(tmp_path):
    db, node_a, node_b = _seed_two_nodes_with_default_binding(tmp_path)
    # The user already bound Netflix to node B only.
    db.set_binding("netflix", node_b, role="main")
    result = migrate_groups(db)
    assert "netflix" not in result["inherited"]
    rows = db.list_bindings("netflix")
    assert [(r["node_id"], r["role"]) for r in rows] == [(node_b, "main")]
    db.close()


def test_migrate_groups_noop_without_default_binding(tmp_path):
    init_lanmux(_env(tmp_path))
    db = Database(tmp_path / "lanmux.db")
    result = migrate_groups(db)
    assert result == {"inherited": [], "renamed": []}
    db.close()


def test_migrate_groups_renames_custom_rule_targets(tmp_path):
    init_lanmux(_env(tmp_path))
    db = Database(tmp_path / "lanmux.db")
    rid_old = db.add_custom_rule(
        "DOMAIN-SUFFIX", "old.example", "流媒体", True
    )
    rid_default = db.add_custom_rule(
        "DOMAIN-SUFFIX", "d.example", "默认代理", True
    )
    rid_ai = db.add_custom_rule("DOMAIN-SUFFIX", "a.example", "AI 服务", True)
    rid_yt = db.add_custom_rule("DOMAIN-SUFFIX", "y.example", "YouTube", True)
    result = migrate_groups(db)
    assert len(result["renamed"]) == 3
    assert db.get_custom_rule(rid_old)["target"] == "Streaming"
    assert db.get_custom_rule(rid_default)["target"] == "Default"
    assert db.get_custom_rule(rid_ai)["target"] == "AI"
    assert db.get_custom_rule(rid_yt)["target"] == "YouTube"
    # Second run renames nothing.
    assert migrate_groups(db)["renamed"] == []
    db.close()


def test_init_lanmux_runs_migration_on_upgrade(tmp_path):
    """Full upgrade path: init_lanmux applies the migration before it
    regenerates the config, so the new groups work immediately."""
    db, _, _ = _seed_two_nodes_with_default_binding(tmp_path)
    db.close()
    config_path = init_lanmux(_env(tmp_path))
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    groups = {g["name"]: g for g in config["proxy-groups"]}
    assert groups["Netflix"]["proxies"] == ["Node-A", "Node-B"]
    assert groups["Apple"]["proxies"] == ["DIRECT"]
    db = Database(tmp_path / "lanmux.db")
    assert db.list_bindings("netflix")
    db.close()
