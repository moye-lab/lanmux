"""Tests for the All-in-One Docker support: auto-secrets & docker_runner.

The seed helper is the unified :mod:`app.init_lanmux` (``LANMUX_*``
env spellings are canonical; ``FENLIU_*`` / ``HUB_*`` are accepted as
legacy aliases); the auto-secrets tests here exercise that path
through the Docker cold-start values.
"""

import base64
from pathlib import Path

import yaml

from app.database import Database
from app.docker_runner import GEODATA_FILES, prepare_runtime_env, sync_assets
from app.init_lanmux import (
    _generate_ss_password,
    ensure_generated_secrets,
    init_lanmux,
    main as init_main,
)


def test_generate_ss_password_matches_cipher_requirements():
    classic = _generate_ss_password("aes-128-gcm")
    assert len(classic) >= 16

    psk128 = _generate_ss_password("2022-blake3-aes-128-gcm")
    assert len(base64.b64decode(psk128)) == 16

    psk256 = _generate_ss_password("2022-blake3-aes-256-gcm")
    assert len(base64.b64decode(psk256)) == 32

    psk_cc = _generate_ss_password("2022-blake3-chacha20-poly1305")
    assert len(base64.b64decode(psk_cc)) == 32


def test_init_lanmux_auto_secrets_cold_start_and_idempotency(tmp_path):
    env = {
        "LANMUX_DB_PATH": str(tmp_path / "lanmux.db"),
        "LANMUX_CONFIG_PATH": str(tmp_path / "mihomo" / "config.yaml"),
        "LANMUX_LAN_IP": "192.168.1.50",
    }
    config_path = init_lanmux(env, auto_secrets=True)
    cfg1 = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    secret1 = cfg1["secret"]
    ss_pass1 = cfg1["listeners"][0]["password"]
    assert len(secret1) >= 16
    assert len(ss_pass1) >= 16

    # Re-running with empty env must preserve the previously generated secrets.
    init_lanmux(env, auto_secrets=True)
    cfg2 = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert cfg2["secret"] == secret1
    assert cfg2["listeners"][0]["password"] == ss_pass1


def test_init_lanmux_cli_auto_secrets_flag(tmp_path, monkeypatch):
    # Canonical LANMUX_* paths (conftest sets them; the HUB_* fallback
    # is pinned separately in test_env_fallback.py).
    monkeypatch.setenv("LANMUX_DB_PATH", str(tmp_path / "lanmux.db"))
    monkeypatch.setenv("LANMUX_CONFIG_PATH", str(tmp_path / "config.yaml"))
    monkeypatch.delenv("MIHOMO_SECRET", raising=False)
    monkeypatch.delenv("SS_PASSWORD", raising=False)
    assert init_main(["--auto-secrets"]) == 0
    assert (tmp_path / "config.yaml").is_file()


def test_ensure_generated_secrets_respects_existing_values(tmp_path):
    db = Database(tmp_path / "lanmux.db")
    db.set_setting("mihomo_secret", "custom-secret")
    generated = ensure_generated_secrets(db)
    assert generated == ["ss_password"]
    assert db.get_setting("mihomo_secret") == "custom-secret"
    assert db.get_setting("ss_password")
    db.close()


def test_sync_assets_copies_missing_without_overwriting(tmp_path):
    assets = tmp_path / "assets"
    (assets / "ui").mkdir(parents=True)
    for name in GEODATA_FILES:
        (assets / name).write_text(f"bundled-{name}", encoding="utf-8")
    (assets / "ui" / "index.html").write_text("<html>bundled</html>", encoding="utf-8")

    mihomo_dir = tmp_path / "data" / "mihomo"
    mihomo_dir.mkdir(parents=True)
    # Pre-existing custom GeoIP.dat must not be overwritten.
    (mihomo_dir / "GeoIP.dat").write_text("user-custom-geoip", encoding="utf-8")

    copied = sync_assets(assets, mihomo_dir, include_ui=True)
    assert "GeoIP.dat" not in copied
    assert "GeoSite.dat" in copied
    assert "Country.mmdb" in copied
    assert "ui/" in copied
    assert (mihomo_dir / "GeoIP.dat").read_text(encoding="utf-8") == "user-custom-geoip"
    assert (mihomo_dir / "ui" / "index.html").read_text(encoding="utf-8") == "<html>bundled</html>"

    # Second run is a no-op.
    assert sync_assets(assets, mihomo_dir, include_ui=True) == []


def test_prepare_runtime_env_sets_external_ui_and_respects_none(tmp_path):
    assets = tmp_path / "assets"
    (assets / "ui").mkdir(parents=True)
    (assets / "ui" / "index.html").write_text("<html>ui</html>", encoding="utf-8")

    env = prepare_runtime_env(
        {
            "LANMUX_DB_PATH": str(tmp_path / "data" / "lanmux.db"),
            "LANMUX_CONFIG_PATH": str(tmp_path / "data" / "mihomo" / "config.yaml"),
            "LANMUX_ASSETS_DIR": str(assets),
            "LANMUX_LAN_IP": "10.0.0.5",
        }
    )
    assert env["MIHOMO_BASE_URL"] == "http://127.0.0.1:{port}"
    assert env["LANMUX_EXTERNAL_UI"] == str(tmp_path / "data" / "mihomo" / "ui")

    env_disabled = prepare_runtime_env(
        {
            "LANMUX_DB_PATH": str(tmp_path / "data2" / "lanmux.db"),
            "LANMUX_CONFIG_PATH": str(tmp_path / "data2" / "mihomo" / "config.yaml"),
            "LANMUX_ASSETS_DIR": str(assets),
            "LANMUX_LAN_IP": "10.0.0.5",
            "LANMUX_EXTERNAL_UI": "none",
        }
    )
    assert env_disabled["LANMUX_EXTERNAL_UI"] == ""
    assert not (tmp_path / "data2" / "mihomo" / "ui").exists()


def test_prepare_runtime_env_hub_aliases_normalize_to_lanmux(tmp_path):
    # An old Docker .env that only sets HUB_* must still work: the
    # runner normalizes every prefixed variable to its LANMUX_* name.
    assets = tmp_path / "assets"
    (assets / "ui").mkdir(parents=True)
    (assets / "ui" / "index.html").write_text("<html>ui</html>", encoding="utf-8")

    env = prepare_runtime_env(
        {
            "HUB_DB_PATH": str(tmp_path / "data" / "hub.db"),
            "HUB_CONFIG_PATH": str(tmp_path / "data" / "mihomo" / "config.yaml"),
            "HUB_ASSETS_DIR": str(assets),
            "HUB_LAN_IP": "10.0.0.5",
            "HUB_WEB_PORT": "18086",
        }
    )
    assert env["LANMUX_DB_PATH"] == str(tmp_path / "data" / "hub.db")
    assert env["LANMUX_CONFIG_PATH"] == str(tmp_path / "data" / "mihomo" / "config.yaml")
    assert env["LANMUX_ASSETS_DIR"] == str(assets)
    assert env["LANMUX_LAN_IP"] == "10.0.0.5"
    assert env["LANMUX_WEB_PORT"] == "18086"
    assert env["LANMUX_EXTERNAL_UI"] == str(tmp_path / "data" / "mihomo" / "ui")


def test_sync_assets_refresh_replaces_bundled_assets(tmp_path):
    assets = tmp_path / "assets"
    (assets / "ui").mkdir(parents=True)
    for name in GEODATA_FILES:
        (assets / name).write_text(f"new-{name}", encoding="utf-8")
    (assets / "ui" / "index.html").write_text("<html>new</html>", encoding="utf-8")

    mihomo_dir = tmp_path / "data" / "mihomo"
    mihomo_dir.mkdir(parents=True)
    for name in GEODATA_FILES:
        (mihomo_dir / name).write_text(f"old-{name}", encoding="utf-8")
    (mihomo_dir / "ui").mkdir()
    (mihomo_dir / "ui" / "index.html").write_text("<html>old</html>", encoding="utf-8")

    copied = sync_assets(assets, mihomo_dir, include_ui=True, refresh=True)
    assert set(copied) == set(GEODATA_FILES) | {"ui/"}
    assert (mihomo_dir / "GeoIP.dat").read_text(encoding="utf-8") == "new-GeoIP.dat"
    assert (mihomo_dir / "ui" / "index.html").read_text(encoding="utf-8") == "<html>new</html>"


def test_prepare_runtime_env_refresh_assets_flag(tmp_path):
    assets = tmp_path / "assets"
    (assets / "ui").mkdir(parents=True)
    (assets / "ui" / "index.html").write_text("<html>ui</html>", encoding="utf-8")

    env = prepare_runtime_env(
        {
            "LANMUX_DB_PATH": str(tmp_path / "data" / "lanmux.db"),
            "LANMUX_CONFIG_PATH": str(tmp_path / "data" / "mihomo" / "config.yaml"),
            "LANMUX_ASSETS_DIR": str(assets),
            "LANMUX_REFRESH_ASSETS": "1",
            "LANMUX_LAN_IP": "10.0.0.5",
        }
    )
    assert env["LANMUX_REFRESH_ASSETS"] == "1"
