"""Tests for the v1.0.0 three-level env fallback (LANMUX_* > FENLIU_* > HUB_*).

The v1.0.0 rename made ``LANMUX_*`` the canonical spelling. The
pre-v1.0.0 ``FENLIU_*`` spelling (systemd installs) and the Docker-era
``HUB_*`` spelling (existing Docker ``.env`` files) are accepted as
legacy aliases, in that priority order. These tests pin the contract
in the seed helper (:mod:`app.init_lanmux`) and the app factory
(:func:`app.main.create_app`).
"""

from app.database import Database
from app.init_lanmux import apply_settings, init_lanmux, seed_settings
from app.main import create_app


def _env(db_path, config_path, **overrides):
    env = {
        "LANMUX_DB_PATH": str(db_path),
        "LANMUX_CONFIG_PATH": str(config_path),
    }
    env.update(overrides)
    return env


def test_seed_settings_reads_hub_prefixed_vars(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    try:
        seeded = seed_settings(
            db,
            _env(
                tmp_path / "lanmux.db",
                tmp_path / "config.yaml",
                HUB_LAN_IP="192.168.1.50",
                HUB_SS_PORT="10001",
                HUB_MIXED_PORT="7891",
            ),
        )
        assert set(seeded) == {"lan_ip", "ss_port", "mixed_port"}
        assert db.get_setting("lan_ip") == "192.168.1.50"
        assert db.get_setting("ss_port") == "10001"
        assert db.get_setting("mixed_port") == "7891"
    finally:
        db.close()


def test_seed_settings_reads_fenliu_prefixed_vars(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    try:
        seeded = seed_settings(
            db,
            _env(
                tmp_path / "lanmux.db",
                tmp_path / "config.yaml",
                FENLIU_LAN_IP="10.0.0.2",
                FENLIU_SS_PORT="10001",
            ),
        )
        assert set(seeded) == {"lan_ip", "ss_port"}
        assert db.get_setting("lan_ip") == "10.0.0.2"
        assert db.get_setting("ss_port") == "10001"
    finally:
        db.close()


def test_seed_settings_lanmux_wins_over_hub(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    try:
        seed_settings(
            db,
            _env(
                tmp_path / "lanmux.db",
                tmp_path / "config.yaml",
                LANMUX_LAN_IP="10.0.0.2",
                HUB_LAN_IP="192.168.1.50",
            ),
        )
        assert db.get_setting("lan_ip") == "10.0.0.2"
    finally:
        db.close()


def test_seed_settings_lanmux_wins_over_fenliu(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    try:
        seed_settings(
            db,
            _env(
                tmp_path / "lanmux.db",
                tmp_path / "config.yaml",
                LANMUX_LAN_IP="10.0.0.2",
                FENLIU_LAN_IP="192.168.1.50",
            ),
        )
        assert db.get_setting("lan_ip") == "10.0.0.2"
    finally:
        db.close()


def test_seed_settings_fenliu_wins_over_hub(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    try:
        seed_settings(
            db,
            _env(
                tmp_path / "lanmux.db",
                tmp_path / "config.yaml",
                FENLIU_LAN_IP="10.0.0.2",
                HUB_LAN_IP="192.168.1.50",
            ),
        )
        assert db.get_setting("lan_ip") == "10.0.0.2"
    finally:
        db.close()


def test_apply_settings_reads_hub_prefixed_vars(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    try:
        applied = apply_settings(
            db,
            _env(
                tmp_path / "lanmux.db",
                tmp_path / "config.yaml",
                HUB_CONTROLLER_PORT="9091",
                HUB_EXTERNAL_UI="https://lanproxyhub.adong.qzz.io",
            ),
        )
        assert set(applied) == {"controller_port", "external_ui"}
        assert db.get_setting("controller_port") == "9091"
    finally:
        db.close()


def test_init_lanmux_paths_fall_back_to_hub(tmp_path):
    config_path = init_lanmux(
        {
            "HUB_DB_PATH": str(tmp_path / "hub.db"),
            "HUB_CONFIG_PATH": str(tmp_path / "mihomo" / "config.yaml"),
            "ADMIN_PASSWORD": "test-admin-123",
        },
        auto_secrets=True,
    )
    assert config_path == tmp_path / "mihomo" / "config.yaml"
    assert (tmp_path / "hub.db").is_file()
    assert not (tmp_path / "lanmux.db").exists()


def test_init_lanmux_paths_fenliu_beats_hub(tmp_path):
    config_path = init_lanmux(
        {
            "FENLIU_DB_PATH": str(tmp_path / "fenliu.db"),
            "FENLIU_CONFIG_PATH": str(tmp_path / "mihomo" / "config.yaml"),
            "HUB_DB_PATH": str(tmp_path / "hub.db"),
            "HUB_CONFIG_PATH": str(tmp_path / "other" / "config.yaml"),
            "ADMIN_PASSWORD": "test-admin-123",
        },
        auto_secrets=True,
    )
    assert config_path == tmp_path / "mihomo" / "config.yaml"
    assert (tmp_path / "fenliu.db").is_file()
    assert not (tmp_path / "hub.db").exists()


def test_create_app_paths_fall_back_to_hub(tmp_path, monkeypatch):
    monkeypatch.delenv("LANMUX_DB_PATH", raising=False)
    monkeypatch.delenv("LANMUX_CONFIG_PATH", raising=False)
    monkeypatch.setenv("HUB_DB_PATH", str(tmp_path / "hub.db"))
    monkeypatch.setenv("HUB_CONFIG_PATH", str(tmp_path / "config.yaml"))
    app = create_app()
    assert app.state.db.path == tmp_path / "hub.db"
    assert app.state.config_service.config_path == tmp_path / "config.yaml"
    app.state.db.close()


def test_create_app_paths_fenliu_beats_hub(tmp_path, monkeypatch):
    monkeypatch.delenv("LANMUX_DB_PATH", raising=False)
    monkeypatch.delenv("LANMUX_CONFIG_PATH", raising=False)
    monkeypatch.setenv("FENLIU_DB_PATH", str(tmp_path / "fenliu.db"))
    monkeypatch.setenv("FENLIU_CONFIG_PATH", str(tmp_path / "config.yaml"))
    monkeypatch.setenv("HUB_DB_PATH", str(tmp_path / "hub.db"))
    monkeypatch.setenv("HUB_CONFIG_PATH", str(tmp_path / "other.yaml"))
    app = create_app()
    assert app.state.db.path == tmp_path / "fenliu.db"
    assert app.state.config_service.config_path == tmp_path / "config.yaml"
    app.state.db.close()
