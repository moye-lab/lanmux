"""Hardening tests for the config-apply / rollback cluster.

Covers the audit items fixed in this branch (H-07/H-08/H-09,
M-26/M-34/M-35/M-36/M-37, L-27/L-28/L-29/L-30, M-51, H-05/H-06):

* concurrent apply: no lost revisions, no shared tmp files, valid
  config, multi-generation backups;
* .bak missing / corrupt: rollback refused, live file untouched;
* non-MihomoError reload failure: rollback + stage failed + sanitized
  error;
* revision only moves after write + reload success;
* write failure: no .tmp left, drift flag + stage failed;
* deep config validation (ports, proxies, rules);
* snapshot reads: a writer cannot slip between the four reads;
* init_lanmux uses the safe path (backup, 0600, revision);
* Secret / controller-port change: restart-required, never a
  hot-reload attempt; confirm after a simulated restart;
* settings PUT rolls the DB back on genuine failure, keeps the new
  values on restart-required;
* /status + /config-preview annotate source and freshness, and an
  unreachable controller is not counted as drift.

The mihomo client is faked throughout (no network, no binary);
the file pipeline, the revision SQL and the HTTP endpoints are real.
"""

import os
import stat
import threading

import pytest
import yaml
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.config_builder import (
    build_from_db,
    validate_config_dict,
    validate_proxy_dict,
)
from app.config_service import ConfigApplyError, ConfigService
from app.database import Database
from app.deps import get_config_service, get_mihomo_client
from app.init_lanmux import init_lanmux
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

    def get_version(self):
        return {"version": "fake-1.0-test"}

    def get_connections(self):
        return {"connections": []}

    def get_traffic(self, timeout=5.0):
        return {"up": 0, "down": 0}


class ExplodingClient(FakeClient):
    """First reload succeeds; later reloads raise NON-MihomoError (H-09)."""

    def reload_config(self, force=True):
        self.reload_calls += 1
        if self.reload_calls == 1:
            return
        raise RuntimeError("boom: unexpected factory failure")


class SaboteurClient(FakeClient):
    """Corrupts/deletes the backups DURING one reload, then fails it.

    Models an external actor (or a concurrent destroyer) damaging
    the rollback baseline between the write and the reload — the
    only way a fresh apply can reach rollback with no valid backup.
    ``sabotage_on`` is the reload call number to sabotage.
    """

    def __init__(self, service, mode, sabotage_on=2):
        super().__init__()
        self.service = service
        self.mode = mode  # "delete" | "corrupt"
        self.sabotage_on = sabotage_on

    def reload_config(self, force=True):
        self.reload_calls += 1
        if self.reload_calls != self.sabotage_on:
            return
        for generation in range(5):
            suffix = (
                ".yaml.bak"
                if generation == 0
                else f".yaml.bak.{generation}"
            )
            path = self.service.config_path.with_suffix(suffix)
            if self.mode == "delete":
                path.unlink(missing_ok=True)
            elif self.mode == "corrupt" and generation == 0:
                path.write_text("not: [valid", encoding="utf-8")
        raise MihomoError(
            "mihomo API error (PUT /configs): bad config", status=400
        )


class StatefulFakeClient:
    """Models real mihomo: secret/port changes need a restart.

    ``active_secret`` / ``active_port`` are what the running mihomo
    uses. The client is built from the DB (new values), so a reload
    raises 401 / connection-refused until ``restart()`` copies the
    DB values into the active ones.
    """

    def __init__(self, db):
        self.db = db
        self.reload_calls = 0
        self.active_secret = db.get_settings().mihomo_secret
        self.active_port = db.get_settings().controller_port

    def _current(self):
        settings = self.db.get_settings()
        return settings.mihomo_secret, settings.controller_port

    def reload_config(self, force=True):
        self.reload_calls += 1
        secret, port = self._current()
        if secret != self.active_secret:
            raise MihomoError(
                "mihomo API error (PUT /configs): unauthorized",
                status=401,
            )
        if port != self.active_port:
            raise MihomoError(
                f"cannot reach mihomo at http://127.0.0.1:{port}: refused",
                connection_error=True,
            )

    def restart(self):
        secret, port = self._current()
        self.active_secret = secret
        self.active_port = port

    def get_version(self):
        secret, port = self._current()
        if secret != self.active_secret or port != self.active_port:
            raise MihomoError("unauthorized", status=401)
        return {"version": "fake-1.0-test"}

    def get_connections(self):
        return {"connections": []}

    def get_traffic(self, timeout=5.0):
        return {"up": 0, "down": 0}


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


def _rev(db, key):
    return int(db.get_setting(key, "0") or "0")


def _bak(service, generation=0):
    suffix = ".yaml.bak" if generation == 0 else f".yaml.bak.{generation}"
    return service.config_path.with_suffix(suffix)


def _valid_config():
    return {
        "proxies": [
            {
                "name": "N1",
                "type": "ss",
                "server": "example.com",
                "port": 8388,
                "cipher": "aes-128-gcm",
                "password": "pw",
            }
        ],
        "proxy-groups": [
            {
                "name": "Default",
                "type": "fallback",
                "proxies": ["N1"],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 60,
            }
        ],
        "rules": ["MATCH,Default"],
        "listeners": [
            {
                "name": "lan-ss",
                "type": "shadowsocks",
                "port": 10001,
                "cipher": "aes-128-gcm",
                "password": "pw",
            },
            {"name": "lan-mixed", "type": "mixed", "port": 7890},
        ],
        "dns": {"enable": True},
        "secret": "s3cret",
        "external-controller": "0.0.0.0:9090",
    }


# ------------------------------------------------------- H-07 concurrency
def test_concurrent_apply_no_lost_revisions(service, db):
    """8 threads applying at once: every revision lands, config valid."""
    service.apply()
    assert _rev(db, "config_revision_db") == 1
    errors: list[BaseException] = []

    def _run():
        try:
            service.apply()
        except BaseException as exc:  # noqa: BLE001 - collected, asserted
            errors.append(exc)

    threads = [threading.Thread(target=_run) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not [t for t in threads if t.is_alive()]
    assert errors == []
    # 1 initial + 8 concurrent = 9, none lost (H-07/M-26).
    assert _rev(db, "config_revision_db") == 9
    assert _rev(db, "config_revision_running") == 9
    assert db.get_setting("last_apply_stage") == "running"
    # The live config parses and no stray tmp files remain.
    yaml.safe_load(service.config_path.read_text(encoding="utf-8"))
    leftovers = [
        p for p in service.config_path.parent.iterdir()
        if ".tmp-" in p.name
    ]
    assert leftovers == []
    assert service._fake_client.reload_calls == 9


# ------------------------------------------------- H-08 / M-36 rollback
def test_rollback_refused_when_backup_missing(db, tmp_path):
    """H-08: no valid backup at rollback time => refuse, keep live file."""
    client_holder: dict[str, SaboteurClient] = {}
    service = ConfigService(
        db, tmp_path / "mihomo" / "config.yaml",
        lambda: client_holder["client"],
    )
    client_holder["client"] = SaboteurClient(service, "delete")
    service._fake_client = client_holder["client"]
    service.apply()
    good_text = service.config_path.read_text(encoding="utf-8")
    db.set_setting("ss_port", 10002)
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    error = exc_info.value
    assert error.stage == "reload"
    assert error.rolled_back is False
    assert "backup" in error.message.lower()
    # The live file was NOT deleted: it still holds the new config
    # (valid YAML), because there was nothing safe to restore.
    assert service.config_path.exists()
    assert service.config_path.read_text(encoding="utf-8") != good_text
    yaml.safe_load(service.config_path.read_text(encoding="utf-8"))
    assert db.get_setting("last_apply_stage") == "failed"


def test_rollback_refused_when_backup_corrupt(db, tmp_path):
    """H-08/M-36: a corrupt live file poisons its own backup => refuse."""
    client = FakeClient()
    service = ConfigService(
        db, tmp_path / "mihomo" / "config.yaml", lambda: client
    )
    service._fake_client = client
    service.apply()
    # Corrupt the LIVE file (not the backup): the next apply backs
    # the corrupt bytes up as .bak, so at rollback time every
    # generation is invalid and the rollback must refuse.
    service.config_path.write_text(":\n - [\n broken: [", encoding="utf-8")
    db.set_setting("ss_port", 10002)
    client.fail_times = 1
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.rolled_back is False
    assert "backup" in exc_info.value.message.lower()
    assert service.config_path.exists()
    yaml.safe_load(service.config_path.read_text(encoding="utf-8"))


def test_rollback_falls_back_to_older_backup_generation(db, tmp_path):
    """A corrupt .bak falls back to .bak.1 instead of giving up."""
    client_holder: dict[str, SaboteurClient] = {}
    service = ConfigService(
        db, tmp_path / "mihomo" / "config.yaml",
        lambda: client_holder["client"],
    )
    # Sabotage only the 4th reload (after 3 good applies).
    client_holder["client"] = SaboteurClient(service, "corrupt", 4)
    service._fake_client = client_holder["client"]
    texts = []
    for port in (10001, 10002, 10003):
        db.set_setting("ss_port", port)
        service.apply()
        texts.append(service.config_path.read_text(encoding="utf-8"))
    # Generations: .bak == texts[1], .bak.1 == texts[0].
    assert service.config_path.with_suffix(".yaml.bak").read_text(
        encoding="utf-8"
    ) == texts[1]
    assert service.config_path.with_suffix(".yaml.bak.1").read_text(
        encoding="utf-8"
    ) == texts[0]
    # The 4th apply writes .bak == texts[2]; its reload corrupts
    # .bak mid-reload and fails: rollback must restore .bak.1
    # (== texts[1]), not refuse outright.
    db.set_setting("ss_port", 10004)
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.rolled_back is True
    assert service.config_path.read_text(encoding="utf-8") == texts[1]


# ------------------------------------------------------------- H-09 / M-26
def test_non_mihomo_error_on_reload_rolls_back_and_fails(db, tmp_path):
    client = ExplodingClient()
    handle = ConfigService(
        db, tmp_path / "mihomo" / "config.yaml", lambda: client
    )
    handle.apply()
    good_text = handle.config_path.read_text(encoding="utf-8")
    db.set_setting("ss_port", 10002)
    with pytest.raises(ConfigApplyError) as exc_info:
        handle.apply()
    assert exc_info.value.stage == "reload"
    assert exc_info.value.rolled_back is True
    assert handle.config_path.read_text(encoding="utf-8") == good_text
    # Stage is failed (not "applied"), error recorded and sanitized:
    # no traceback, no raw internals, just the exception class.
    assert db.get_setting("last_apply_stage") == "failed"
    assert db.get_setting("last_apply_ok") == "0"
    error = db.get_setting("last_apply_error") or ""
    assert "RuntimeError" in error
    assert "Traceback" not in error
    assert "boom" in error  # the message itself is fine, sanitized
    # M-26: the failed apply bumped neither revision.
    assert _rev(db, "config_revision_db") == 1
    assert _rev(db, "config_revision_running") == 1


def test_revision_not_bumped_on_compile_or_write_failure(service, db):
    db.set_setting("mihomo_secret", "")
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.stage == "compile"
    assert _rev(db, "config_revision_db") == 0
    db.set_setting("mihomo_secret", "fake-mihomo-secret")
    service.apply()
    assert _rev(db, "config_revision_db") == 1
    db.set_setting("mihomo_secret", "")
    with pytest.raises(ConfigApplyError):
        service.apply()
    assert _rev(db, "config_revision_db") == 1


# ------------------------------------------------------- L-27 / L-28 / M-37
def test_write_failure_leaves_no_tmp_and_flags_drift(
    service, db, tmp_path, monkeypatch
):
    service.apply()
    good_text = service.config_path.read_text(encoding="utf-8")
    db.set_setting("ss_port", 10002)
    real_replace = os.replace

    def _fail_once(src, dst):
        if "config.yaml" in str(dst) and ".tmp-" in str(src):
            raise OSError("simulated disk failure")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _fail_once)
    with pytest.raises(ConfigApplyError) as exc_info:
        service.apply()
    assert exc_info.value.stage == "write"
    monkeypatch.undo()
    # No .tmp litter, live file untouched, revision untouched.
    leftovers = [
        p for p in service.config_path.parent.iterdir()
        if ".tmp-" in p.name
    ]
    assert leftovers == []
    assert service.config_path.read_text(encoding="utf-8") == good_text
    assert _rev(db, "config_revision_db") == 1
    # M-37: logged + drift flag + stage failed (not silent).
    assert db.get_setting("config_drift_flag") == "1"
    assert db.get_setting("last_apply_stage") == "failed"
    assert "write failed" in (db.get_setting("last_apply_error") or "")


def test_five_backup_generations_kept(service, db):
    texts = []
    for port in (10001, 10002, 10003, 10004, 10005, 10006, 10007):
        db.set_setting("ss_port", port)
        service.apply()
        texts.append(service.config_path.read_text(encoding="utf-8"))
    # 7 applies: live == 7th, .bak == 6th … .bak.4 == 2nd; .bak.5 pruned.
    assert service.config_path.read_text(encoding="utf-8") == texts[6]
    for generation in range(5):
        assert _bak(service, generation).read_text(
            encoding="utf-8"
        ) == texts[5 - generation]
    assert not _bak(service, 5).exists()
    # Config + backups are 0600 (M-08 config part).
    assert stat.S_IMODE(service.config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(_bak(service, 0).stat().st_mode) == 0o600


# ------------------------------------------- M-28 backup hookup (apply)
def test_apply_takes_database_backup_first(service, db):
    """apply() snapshots the DB before writing the new config.

    The newest backup must appear as a result of the apply and must
    be a usable copy of the live database at apply time.
    """
    before = set(db.list_backups())
    db.set_setting("ss_port", 10001)
    service.apply()
    new = [b for b in db.list_backups() if b not in before]
    assert len(new) == 1, f"expected one new backup, got {new}"
    # The backup is a real, openable copy of the live DB.
    copy = Database(new[0])
    try:
        assert copy.get_setting("ss_port") == "10001"
        assert copy._integrity_problems() == []
    finally:
        copy.close()


def test_apply_survives_backup_failure(service, db, caplog):
    """A failing pre-apply backup is logged, never fails the apply."""
    import logging

    orig_backup = db.backup

    def _boom():
        raise OSError("disk full (simulated)")

    db.backup = _boom
    try:
        with caplog.at_level(logging.WARNING, logger="lanmux.config_service"):
            service.apply()
    finally:
        db.backup = orig_backup
    assert service.config_path.exists()
    assert "pre-apply database backup failed" in caplog.text
    assert _rev(db, "config_revision_db") >= 1


# ------------------------------------------------------------- M-34 deep
def test_validate_config_dict_deep_checks():
    base = _valid_config()
    validate_config_dict(base)

    dup = _valid_config()
    dup["proxies"].append(dict(dup["proxies"][0]))
    with pytest.raises(ValueError, match="duplicate proxy name"):
        validate_config_dict(dup)

    bad_port = _valid_config()
    bad_port["proxies"][0]["port"] = 70000
    # Merged (M-34 + H-11): the shared validator says "out-of-range".
    with pytest.raises(ValueError, match="out-of-range"):
        validate_config_dict(bad_port)

    bad_type = _valid_config()
    bad_type["proxies"][0]["type"] = "wireguard-plus"
    with pytest.raises(ValueError, match="unsupported type"):
        validate_config_dict(bad_type)

    missing_uuid = _valid_config()
    missing_uuid["proxies"][0] = {
        "name": "V1", "type": "vmess",
        "server": "example.com", "port": 443,
    }
    # Merged (M-34 + H-11): the shared uri_parser validator raises
    # "proxy JSON is missing the UUID" (capital UUID).
    with pytest.raises(ValueError, match="(?i)uuid"):
        validate_config_dict(missing_uuid)

    port_clash = _valid_config()
    port_clash["listeners"][1]["port"] = 10001
    with pytest.raises(ValueError, match="used by both"):
        validate_config_dict(port_clash)

    ctrl_clash = _valid_config()
    ctrl_clash["external-controller"] = "0.0.0.0:10001"
    with pytest.raises(ValueError, match="used by both"):
        validate_config_dict(ctrl_clash)

    bad_rule = _valid_config()
    bad_rule["rules"] = ["DOMAIN-SUFFIX,example.com,NoSuchGroup"]
    with pytest.raises(ValueError, match="unknown group"):
        validate_config_dict(bad_rule)

    bad_cidr = _valid_config()
    bad_cidr["rules"] = ["IP-CIDR,999.1.1.0/24,DIRECT"]
    with pytest.raises(ValueError, match="invalid CIDR"):
        validate_config_dict(bad_cidr)

    bad_member = _valid_config()
    bad_member["proxy-groups"][0]["proxies"] = ["Ghost"]
    with pytest.raises(ValueError, match="unknown proxy/group"):
        validate_config_dict(bad_member)


def test_validate_proxy_dict_local():
    validate_proxy_dict(
        {"name": "V", "type": "vless", "server": "example.com",
         "port": 443, "uuid": "11111111-1111-1111-1111-111111111111"}
    )
    # Merged (M-34 + H-11): the shared uri_parser validator raises
    # "proxy JSON is missing the UUID" (capital UUID).
    with pytest.raises(ValueError, match="(?i)uuid"):
        validate_proxy_dict(
            {"name": "V", "type": "vless",
             "server": "example.com", "port": 443}
        )
    with pytest.raises(ValueError, match="unsupported type"):
        validate_proxy_dict(
            {"name": "V", "type": "socks4",
             "server": "example.com", "port": 1080}
        )


def test_validate_proxy_dict_merged_delegation():
    """Merged ``validate_proxy_dict`` (M-34 + H-11): the six node
    protocols go through the shared ``uri_parser`` validator, legacy
    exotic types keep the local structural checks.

    The ``hy2`` alias is resolved at entry (PUT / import store the
    normalized ``hysteria2``), so a raw ``hy2`` in a compiled dict
    is still rejected here — same as before the merge.
    """
    # Shared validator: malformed UUID rejected (format, not just missing).
    with pytest.raises(ValueError, match="(?i)invalid UUID"):
        validate_proxy_dict(
            {"name": "V", "type": "vless", "server": "example.com",
             "port": 443, "uuid": "not-a-uuid"}
        )
    # Shared validator: server shape checked, not just non-empty.
    with pytest.raises(ValueError, match="invalid server address"):
        validate_proxy_dict(
            {"name": "V", "type": "vless", "server": "not a host!!!",
             "port": 443, "uuid": "11111111-1111-1111-1111-111111111111"}
        )
    # Digit-string port: the shared validator would coerce it in its
    # own copy, but the compiled dict must carry a real int.
    with pytest.raises(ValueError, match="port must be an integer"):
        validate_proxy_dict(
            {"name": "V", "type": "vless", "server": "example.com",
             "port": "443", "uuid": "11111111-1111-1111-1111-111111111111"}
        )
    # Legacy exotic type: local structural checks only, still accepted.
    validate_proxy_dict(
        {"name": "W", "type": "wireguard", "server": "10.0.0.1",
         "port": 51820, "private-key": "abc123"}
    )
    # ... and its required field is still enforced.
    with pytest.raises(ValueError, match="private-key"):
        validate_proxy_dict(
            {"name": "W", "type": "wireguard", "server": "10.0.0.1",
             "port": 51820}
        )
    # Raw hy2 alias in a compiled dict: rejected (resolved at entry).
    with pytest.raises(ValueError, match="unsupported type"):
        validate_proxy_dict(
            {"name": "H", "type": "hy2", "server": "example.com",
             "port": 443, "password": "x"}
        )


# ------------------------------------------------------------- M-35 snapshot
def test_build_from_db_snapshot_blocks_writer_between_reads(db):
    """A writer cannot slip between the four snapshot reads (M-35).

    The snapshot holds the DB lock across all reads; a concurrent
    set_setting must block until the snapshot finishes.
    """
    original_list_nodes = db.list_nodes
    writer_done = threading.Event()
    writer_thread: list[threading.Thread] = []

    def _writer():
        db.set_setting("ss_port", "10003")
        writer_done.set()

    def _patched_list_nodes(*args, **kwargs):
        thread = threading.Thread(target=_writer)
        writer_thread.append(thread)
        thread.start()
        # The writer must still be blocked 0.3s into list_nodes:
        # build_from_db holds the lock for the whole snapshot.
        assert not writer_done.wait(timeout=0.3)
        return original_list_nodes(*args, **kwargs)

    db.list_nodes = _patched_list_nodes  # type: ignore[method-assign]
    try:
        config = build_from_db(db)
    finally:
        db.list_nodes = original_list_nodes  # type: ignore[method-assign]
    # The snapshot is done, so the writer can now proceed.
    writer_thread[0].join(timeout=5)
    assert writer_done.is_set()
    # The snapshot read the OLD ss_port (writer landed after it).
    listeners = {entry["name"]: entry for entry in config["listeners"]}
    assert listeners["lan-ss"]["port"] == 10001
    assert db.get_setting("ss_port") == "10003"


# ------------------------------------------------------------- M-51 init
def test_init_lanmux_uses_safe_path(tmp_path):
    env = {
        "ADMIN_PASSWORD": "fake-admin-password",
        "MIHOMO_SECRET": "fake-mihomo-secret",
        "SS_PASSWORD": "fake-ss-password",
        "LANMUX_DB_PATH": str(tmp_path / "lanmux.db"),
        "LANMUX_CONFIG_PATH": str(tmp_path / "config.yaml"),
        "LANMUX_SS_PORT": "10001",
    }
    path = init_lanmux(env)
    assert path == tmp_path / "config.yaml"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    handle = Database(tmp_path / "lanmux.db")
    try:
        assert _rev(handle, "config_revision_db") == 1
        assert _rev(handle, "config_revision_running") == 1
    finally:
        handle.close()
    # Second run (upgrade) with a changed port: backup kept, file safe.
    env["LANMUX_SS_PORT"] = "10002"
    first_text = path.read_text(encoding="utf-8")
    init_lanmux(env, apply_env=True)
    assert path.with_suffix(".yaml.bak").read_text(
        encoding="utf-8"
    ) == first_text
    assert "10002" in path.read_text(encoding="utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_init_lanmux_still_fails_without_secrets(tmp_path):
    env = {
        "ADMIN_PASSWORD": "fake-admin-password",
        "LANMUX_DB_PATH": str(tmp_path / "lanmux.db"),
        "LANMUX_CONFIG_PATH": str(tmp_path / "config.yaml"),
    }
    with pytest.raises(ValueError, match="mihomo_secret"):
        init_lanmux(env)
    assert not (tmp_path / "config.yaml").exists()


# ------------------------------------------------------- H-05 / H-06 restart
@pytest.fixture
def stateful_service(db, tmp_path):
    client = StatefulFakeClient(db)
    handle = ConfigService(
        db, tmp_path / "mihomo" / "config.yaml", lambda: client
    )
    handle._fake_client = client
    return handle


def test_secret_change_requires_restart_not_hot_reload(
    stateful_service, db
):
    """H-05: changing the secret never attempts a doomed hot reload."""
    stateful_service.apply()
    assert _rev(db, "config_revision_db") == 1
    db.set_setting("mihomo_secret", "new-secret-value")
    with pytest.raises(ConfigApplyError) as exc_info:
        stateful_service.apply()
    error = exc_info.value
    assert error.stage == "restart_required"
    assert error.restart_required is True
    assert error.restart_reason == "mihomo_secret"
    assert "restart" in error.message.lower()
    assert error.rolled_back is False
    # The new config IS on disk (what mihomo must load at restart);
    # the fake mihomo still runs the old secret (no reload attempted
    # with the new one — reload_calls stayed at 1).
    assert stateful_service._fake_client.reload_calls == 1
    assert "new-secret-value" in stateful_service.config_path.read_text(
        encoding="utf-8"
    )
    # DB keeps the new value on purpose; revision did not move until
    # the restart is confirmed; pending flag + stage are set.
    assert db.get_setting("mihomo_secret") == "new-secret-value"
    assert _rev(db, "config_revision_db") == 1
    assert db.get_setting("config_restart_pending") == "1"
    assert db.get_setting("last_apply_stage") == "restart_pending"
    assert db.get_setting("last_apply_ok") == "0"


def test_reapply_before_restart_keeps_pending_and_file(
    stateful_service, db
):
    stateful_service.apply()
    db.set_setting("mihomo_secret", "new-secret-value")
    with pytest.raises(ConfigApplyError):
        stateful_service.apply()
    new_text = stateful_service.config_path.read_text(encoding="utf-8")
    # Re-applying before the restart must NOT roll the file back and
    # must NOT report success: still restart_required. The re-apply
    # probes the controller once (reload_calls 2: first apply + this
    # probe) and the probe fails, so pending state is kept.
    db.set_setting("ss_port", 10002)
    with pytest.raises(ConfigApplyError) as exc_info:
        stateful_service.apply()
    assert exc_info.value.stage == "restart_required"
    assert exc_info.value.restart_required is True
    assert "10002" in stateful_service.config_path.read_text(
        encoding="utf-8"
    )
    assert db.get_setting("config_restart_pending") == "1"
    assert stateful_service._fake_client.reload_calls == 2


def test_confirm_restart_after_secret_change(stateful_service, db):
    stateful_service.apply()
    db.set_setting("mihomo_secret", "new-secret-value")
    with pytest.raises(ConfigApplyError):
        stateful_service.apply()
    # Confirming before the restart fails and keeps pending.
    result = stateful_service.confirm_restart()
    assert result["ok"] is False
    assert result["restart_pending"] is True
    assert db.get_setting("config_restart_pending") == "1"
    # Simulate the operator restarting mihomo (new secret now live).
    stateful_service._fake_client.restart()
    result = stateful_service.confirm_restart()
    assert result["ok"] is True
    assert result["restart_pending"] is False
    assert db.get_setting("config_restart_pending") == "0"
    assert db.get_setting("last_apply_stage") == "running"
    assert _rev(db, "config_revision_db") == 2
    assert _rev(db, "config_revision_running") == 2
    # A plain apply works again now (new secret is live).
    stateful_service.apply()
    assert _rev(db, "config_revision_db") == 3


def test_controller_port_change_requires_restart(stateful_service, db):
    """H-06: changing the controller port takes the restart path."""
    stateful_service.apply()
    db.set_setting("controller_port", 19090)
    with pytest.raises(ConfigApplyError) as exc_info:
        stateful_service.apply()
    assert exc_info.value.stage == "restart_required"
    assert exc_info.value.restart_required is True
    assert exc_info.value.restart_reason == "controller_port"
    assert "19090" in stateful_service.config_path.read_text(
        encoding="utf-8"
    )
    stateful_service._fake_client.restart()
    result = stateful_service.confirm_restart()
    assert result["ok"] is True
    assert _rev(db, "config_revision_db") == 2
    assert _rev(db, "config_revision_running") == 2


def test_confirm_restart_without_pending_is_noop(stateful_service):
    result = stateful_service.confirm_restart()
    assert result["ok"] is False
    assert result["restart_pending"] is False


# ------------------------------------------------- L-29 / L-30 + HTTP paths
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


def test_status_unreachable_controller_is_not_drift(
    http_client, auth_headers, http_app
):
    """L-29: mihomo down => controller_unreachable, not drift."""
    service = http_app.state.config_service
    service.apply()
    http_app.state.db.set_setting("ss_port", 10002)
    service._fake_client.fail = True
    with pytest.raises(ConfigApplyError):
        service.apply()
    config = _status(http_client, auth_headers)
    assert config["drift"] is False
    assert config["drift_flag"] is False
    assert config["controller_unreachable"] is True
    assert config["state"] == "controller_unreachable"
    assert config["freshness"] == "unknown"
    assert "不可达" in config["note"]
    assert config["db_revision"] == 1
    assert config["running_revision"] == 1


def test_status_rejection_counts_as_drift(http_client, auth_headers, http_app):
    """A 400 rejection (not unreachable) still counts as drift."""
    service = http_app.state.config_service
    service.apply()
    http_app.state.db.set_setting("ss_port", 10002)
    service._fake_client.fail_times = 1
    with pytest.raises(ConfigApplyError):
        service.apply()
    config = _status(http_client, auth_headers)
    assert config["drift"] is True
    assert config["drift_flag"] is True
    assert config["controller_unreachable"] is False
    assert config["state"] == "drift"
    assert config["freshness"] == "stale"
    assert "未应用" in config["note"]
    assert config["source"] == "database"


def test_config_preview_annotates_source_and_freshness(
    http_client, auth_headers, http_app
):
    service = http_app.state.config_service
    body = http_client.get(
        "/api/diagnostics/config-preview", headers=auth_headers
    ).json()
    assert body["exists"] is False
    assert body["source"] == "none"
    service.apply()
    body = http_client.get(
        "/api/diagnostics/config-preview", headers=auth_headers
    ).json()
    assert body["exists"] is True
    assert body["source"] == "disk: config.yaml"
    assert body["freshness"] == "current"
    assert "与运行配置一致" in body["note"]
    # Drift the DB: the preview must say the disk file is stale.
    http_app.state.db.set_setting("ss_port", 10002)
    service._fake_client.fail_times = 1
    with pytest.raises(ConfigApplyError):
        service.apply()
    body = http_client.get(
        "/api/diagnostics/config-preview", headers=auth_headers
    ).json()
    assert body["freshness"] == "stale"
    assert "未应用" in body["note"]


def test_settings_put_rolls_db_back_on_genuine_failure(
    http_client, auth_headers, http_app
):
    """H-05/H-06 companion: a non-restart failure restores DB values."""
    service = http_app.state.config_service
    service.apply()
    service._fake_client.fail_times = 1
    body = http_client.put(
        "/api/settings",
        json={"ss_port": 10002},
        headers=auth_headers,
    ).json()
    assert body["reload"]["ok"] is False
    assert body["reload"]["restart_required"] is False
    # The failed apply rolled the DB back: ss_port is 10001 again.
    settings = http_client.get(
        "/api/settings", headers=auth_headers
    ).json()
    assert settings["ss_port"] == 10001
    assert _rev(http_app.state.db, "config_revision_db") == 1


def test_settings_put_keeps_db_on_restart_required(
    http_client, auth_headers, http_app
):
    """A secret change via PUT keeps the new DB value (pending restart).

    Uses the stateful client: the reload would 401 with the new
    secret until mihomo restarts, so the apply must take the
    restart path instead of failing + rolling the DB back.
    """
    db = http_app.state.db
    stateful = StatefulFakeClient(db)
    real_service = ConfigService(
        db, http_app.state.config_service.config_path, lambda: stateful
    )
    real_service._fake_client = stateful
    http_app.state.config_service = real_service
    http_app.dependency_overrides[get_config_service] = lambda: real_service
    real_service.apply()
    body = http_client.put(
        "/api/settings",
        json={"mihomo_secret": "rotated-secret"},
        headers=auth_headers,
    ).json()
    assert body["reload"]["ok"] is False
    assert body["reload"]["restart_required"] is True
    assert body["reload"]["restart_reason"] == "mihomo_secret"
    assert "restart" in body["reload"]["error"].lower()
    # New secret kept in DB and on disk; nothing rolled back.
    assert db.get_setting("mihomo_secret") == "rotated-secret"
    assert "rotated-secret" in real_service.config_path.read_text(
        encoding="utf-8"
    )
    # Operator restarts mihomo, then confirms via the endpoint.
    stateful.restart()
    confirm = http_client.post(
        "/api/diagnostics/confirm-restart", headers=auth_headers
    ).json()
    assert confirm["ok"] is True
    config = _status(http_client, auth_headers)
    assert config["state"] == "running"
    assert config["restart_pending"] is False
