"""Tests for the DB & settings atomicity cluster (audit §2 M-24/M-25/
M-27/M-28/M-29/M-30, §3 L-18/L-19).

Every test uses a temporary database — the real ``data/lanmux.db``
is never touched. Concurrency tests use real threads / processes,
not mocks of the lock.
"""

import logging
import multiprocessing
import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.config_service import ConfigService
from app.database import (
    Database,
    DatabaseCorruptError,
)
from app.main import create_app
from app.routers.nodes import _store_result
from app.models import SpeedtestResult

ADMIN_PASSWORD = "atomicity-test-admin"

SS_URI = "ss://YWVzLTEyOC1nY206ZmFrZS1wYXNzd29yZA@example.com:8388#NodeOne"


class _SucceedingClient:
    """Fake mihomo whose reload always succeeds (happy-path apply)."""

    def reload_config(self, force=True):
        return None

    def get_version(self):
        return {"version": "fake-1.0-test"}

THREADS = 8
JOIN_TIMEOUT = 30


def _run_threads(workers):
    threads = [threading.Thread(target=w, daemon=True) for w in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=JOIN_TIMEOUT)
    hung = [t for t in threads if t.is_alive()]
    assert not hung, f"{len(hung)} thread(s) still running after {JOIN_TIMEOUT}s"


def _make_node(db, name):
    return db.add_node(
        name, SS_URI, {"name": name, "type": "ss", "server": "example.com",
                       "port": 8388, "cipher": "aes-128-gcm",
                       "password": "fake"},
    )


@pytest.fixture
def db(tmp_path):
    handle = Database(tmp_path / "lanmux.db")
    yield handle
    handle.close()


@pytest.fixture
def app(tmp_path):
    application = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    application.state.db.set_setting(
        "admin_password_hash", hash_password(ADMIN_PASSWORD)
    )
    return application


def _authed_client(app):
    client = TestClient(app)
    login = client.post("/api/auth/login", json={"password": ADMIN_PASSWORD})
    assert login.status_code == 200
    return client, {"Authorization": f"Bearer {login.json()['token']}"}


# ------------------------------------------------------------------ L-18
def test_partial_unique_index_exists(db):
    row = db.conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'index'"
        " AND name = 'idx_group_bindings_one_main'"
    ).fetchone()
    assert row is not None
    assert "WHERE role = 'main'" in row["sql"]


def test_partial_unique_index_blocks_double_main(db):
    a = _make_node(db, "A")
    b = _make_node(db, "B")
    db.set_binding("youtube", a, role="main")
    # Bypass the application-level demote to prove the index itself
    # is the backstop: raw SQL for a second main must fail.
    with pytest.raises(sqlite3.IntegrityError):
        db.conn.execute(
            "INSERT INTO group_bindings (group_key, node_id, role, mode)"
            " VALUES ('youtube', ?, 'main', 'fallback')",
            (b,),
        )
    db.conn.rollback()


def test_old_db_migration_dedups_double_main(tmp_path):
    """A pre-fix DB with two mains opens fine; migration keeps one."""
    from app.database import SCHEMA

    path = tmp_path / "lanmux.db"
    raw = sqlite3.connect(str(path))
    raw.executescript(SCHEMA)
    raw.execute(
        "INSERT INTO nodes (name, uri, proxy_json, enabled)"
        " VALUES ('A', 'ss://a', '{\"type\": \"ss\"}', 1)"
    )
    raw.execute(
        "INSERT INTO nodes (name, uri, proxy_json, enabled)"
        " VALUES ('B', 'ss://b', '{\"type\": \"ss\"}', 1)"
    )
    # Legacy double main (the M-24 race, as the audit reproduced it).
    raw.execute(
        "INSERT INTO group_bindings (group_key, node_id, role, mode)"
        " VALUES ('youtube', 1, 'main', 'fallback')"
    )
    raw.execute(
        "INSERT INTO group_bindings (group_key, node_id, role, mode)"
        " VALUES ('youtube', 2, 'main', 'fallback')"
    )
    raw.execute(
        "INSERT INTO settings (key, value) VALUES ('ss_port', '10002')"
    )
    raw.commit()
    raw.close()

    handle = Database(path)
    try:
        bindings = handle.list_bindings("youtube")
        mains = [b for b in bindings if b["role"] == "main"]
        assert len(mains) == 1
        assert mains[0]["node_id"] == 1  # earliest main kept
        assert len(bindings) == 2  # the other row survives as backup
        assert handle.get_node(1)["name"] == "A"  # user data intact
        assert handle.get_node(2)["name"] == "B"
        assert handle.get_settings().ss_port == 10002
        row = handle.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'index'"
            " AND name = 'idx_group_bindings_one_main'"
        ).fetchone()
        assert row is not None
    finally:
        handle.close()


# ------------------------------------------------------------------ M-24
def test_set_binding_demotes_previous_main(db):
    a = _make_node(db, "A")
    b = _make_node(db, "B")
    db.set_binding("youtube", a, role="main")
    db.set_binding("youtube", b, role="main")
    bindings = db.list_bindings("youtube")
    mains = [x for x in bindings if x["role"] == "main"]
    assert [m["node_id"] for m in mains] == [b]
    assert [x["node_id"] for x in bindings if x["role"] == "backup"] == [a]


def test_concurrent_set_binding_single_main(db):
    node_ids = [_make_node(db, f"N{i}") for i in range(THREADS)]
    errors: list[BaseException] = []

    def worker(node_id):
        try:
            db.set_binding("youtube", node_id, role="main")
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            errors.append(exc)

    _run_threads([lambda i=i: worker(i) for i in node_ids])
    assert not errors, f"worker errors: {errors!r}"
    mains = [b for b in db.list_bindings("youtube") if b["role"] == "main"]
    assert len(mains) == 1
    assert len(db.list_bindings("youtube")) == THREADS


def test_concurrent_replace_bindings_single_main(db):
    node_ids = [_make_node(db, f"N{i}") for i in range(THREADS)]
    errors: list[BaseException] = []

    def worker(node_id):
        try:
            db.replace_bindings("youtube", node_id, [], "fallback")
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            errors.append(exc)

    _run_threads([lambda i=i: worker(i) for i in node_ids])
    assert not errors, f"worker errors: {errors!r}"
    bindings = db.list_bindings("youtube")
    assert len([b for b in bindings if b["role"] == "main"]) == 1
    assert len(bindings) == 1


def test_concurrent_binding_put_single_main(app):
    """The audit PoC (concurrent PUT -> mains [3, 1]) must not recur."""
    node_ids = [
        _make_node(app.state.db, f"N{i}") for i in range(THREADS)
    ]
    client, headers = _authed_client(app)
    errors: list[BaseException] = []
    statuses: list[int] = []

    def worker(node_id):
        try:
            response = client.put(
                "/api/rules/bindings/youtube",
                json={"main": node_id, "backups": [], "mode": "fallback"},
                headers=headers,
            )
            statuses.append(response.status_code)
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            errors.append(exc)

    _run_threads([lambda i=i: worker(i) for i in node_ids])
    assert not errors, f"worker errors: {errors!r}"
    assert statuses and all(status == 200 for status in statuses)
    bindings = app.state.db.list_bindings("youtube")
    mains = [b for b in bindings if b["role"] == "main"]
    assert len(mains) == 1
    assert mains[0]["node_id"] in node_ids
    assert len(bindings) == 1


# ------------------------------------------------------------------ L-19
def test_binding_rejects_unknown_group_and_missing_node(db):
    node_id = _make_node(db, "A")
    with pytest.raises(ValueError, match="unknown group_key"):
        db.set_binding("not-a-group", node_id, role="main")
    with pytest.raises(ValueError, match="unknown node id"):
        db.set_binding("youtube", 99999, role="main")
    with pytest.raises(ValueError, match="unknown group_key"):
        db.replace_bindings("not-a-group", node_id, [], "fallback")
    with pytest.raises(ValueError, match="unknown node id"):
        db.replace_bindings("youtube", 99999, [], "fallback")
    with pytest.raises(ValueError, match="must be distinct"):
        db.replace_bindings("youtube", node_id, [node_id], "fallback")
    with pytest.raises(ValueError, match="unknown group_key"):
        db.clear_bindings("not-a-group")
    assert db.list_bindings("youtube") == []


# ------------------------------------------------------------------ M-25
def test_settings_put_400_persists_nothing(app):
    client, headers = _authed_client(app)
    before = client.get("/api/settings", headers=headers).json()
    assert before["ss_port"] == 10001
    assert before["lan_ip"] == "127.0.0.1"

    # Valid field first, invalid field after: the audit PoC persisted
    # the valid one despite the 400. Nothing may persist now.
    response = client.put(
        "/api/settings",
        json={"ss_port": 10002, "controller_port": 70000},
        headers=headers,
    )
    assert response.status_code == 400
    after = client.get("/api/settings", headers=headers).json()
    assert after["ss_port"] == 10001
    assert after["controller_port"] == 9090

    response = client.put(
        "/api/settings",
        json={"lan_ip": "192.168.1.99", "ss_cipher": "not-a-cipher"},
        headers=headers,
    )
    assert response.status_code == 400
    after = client.get("/api/settings", headers=headers).json()
    assert after["lan_ip"] == "127.0.0.1"

    # A fully valid PUT still works (and is itself atomic) — with a
    # reachable controller so the apply succeeds. (With a down
    # controller the H-05/H-06 rollback would revert the DB values;
    # see test_settings_put_rolls_db_back_on_genuine_failure.)
    # The fixture DB has no secrets, so seed the two compile
    # requirements first (as the apply-hardening fixtures do).
    app.state.db.set_setting("ss_password", "fake-ss-pass")
    app.state.db.set_setting("mihomo_secret", "fake-mihomo-secret")
    app.state.config_service = ConfigService(
        app.state.db,
        app.state.config_service.config_path,
        lambda: _SucceedingClient(),
    )
    response = client.put(
        "/api/settings",
        json={"ss_port": 10002, "lan_ip": "192.168.1.99"},
        headers=headers,
    )
    assert response.status_code == 200
    after = client.get("/api/settings", headers=headers).json()
    assert after["ss_port"] == 10002
    assert after["lan_ip"] == "192.168.1.99"


def test_set_settings_bulk_atomic(db):
    db.set_setting("ss_port", 10001)
    with pytest.raises(ValueError, match="invalid controller_port"):
        db.set_settings_bulk(
            {"ss_port": 10002, "controller_port": 70000}
        )
    assert db.get_settings().ss_port == 10001
    assert db.get_settings().controller_port == 9090
    db.set_settings_bulk({"ss_port": 10002, "mixed_port": 7891})
    assert db.get_settings().ss_port == 10002
    assert db.get_settings().mixed_port == 7891


# ------------------------------------------------------------------ M-27
def test_wal_mode_and_busy_timeout(db):
    mode = db.conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"
    timeout = db.conn.execute("PRAGMA busy_timeout").fetchone()[0]
    assert timeout == 5000


def _holder_process(path, ready, done):
    """Hold a write lock for ~2s (BEGIN IMMEDIATE + sleep)."""
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('holder', '1')"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        )
        ready.set()
        time.sleep(2.0)
        conn.commit()
    finally:
        conn.close()
        done.set()


def _writer_process(path, queue):
    """Write through Database while the holder owns the write lock."""
    try:
        handle = Database(path)
        try:
            for step in range(30):
                handle.set_setting("writer", str(step))
            assert handle.get_setting("writer") == "29"
        finally:
            handle.close()
        queue.put(("ok", None))
    except BaseException as exc:  # noqa: BLE001 - reported via queue
        queue.put(("error", repr(exc)))


def test_cross_process_write_waits_not_locked(tmp_path):
    """Cross-process write while another process holds the lock must
    wait (busy_timeout) and succeed — not fail after 5s with
    "database is locked" (M-27 PoC behaviour)."""
    path = tmp_path / "lanmux.db"
    handle = Database(path)
    handle.close()

    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()
    done = ctx.Event()
    queue = ctx.Queue()
    holder = ctx.Process(target=_holder_process, args=(path, ready, done))
    writer = ctx.Process(target=_writer_process, args=(path, queue))
    holder.start()
    assert ready.wait(timeout=10), "holder never took the write lock"
    started = time.monotonic()
    writer.start()
    writer.join(timeout=20)
    elapsed = time.monotonic() - started
    assert not writer.is_alive(), "writer hung"
    assert writer.exitcode == 0
    status, detail = queue.get(timeout=5)
    assert status == "ok", f"writer failed: {detail}"
    assert elapsed >= 1.5, "writer did not actually wait for the lock"
    holder.join(timeout=10)
    assert holder.exitcode == 0


# ------------------------------------------------------------------ M-28
def test_corrupt_db_restored_from_backup(tmp_path, caplog):
    path = tmp_path / "lanmux.db"
    handle = Database(path)
    node_id = _make_node(handle, "KeepMe")
    handle.set_binding("youtube", node_id, role="main")
    handle.set_setting("ss_port", 10002)
    backup_path = handle.backup()
    handle.close()
    assert backup_path.is_file()

    # Corrupt the live file the way a torn write / disk fault would.
    path.write_bytes(b"this is not a sqlite database" * 200)

    with caplog.at_level(logging.WARNING, logger="app.database"):
        recovered = Database(path)
    try:
        assert recovered.recovered_from_backup == backup_path
        assert "restored from backup" in caplog.text
        assert recovered.get_node(node_id)["name"] == "KeepMe"
        mains = [
            b for b in recovered.list_bindings("youtube")
            if b["role"] == "main"
        ]
        assert [m["node_id"] for m in mains] == [node_id]
        assert recovered.get_settings().ss_port == 10002
        assert recovered.get_setting("db_recovered_from_backup")
        # The corrupt file was kept aside, not silently deleted.
        assert list(tmp_path.glob("lanmux.db.corrupt-*"))
        # A reopened, healthy DB stays healthy (no restore loop).
        recovered.close()
        reopened = Database(path)
        assert reopened.recovered_from_backup is None
        assert reopened.get_node(node_id) is not None
        reopened.close()
    finally:
        try:
            recovered.close()
        except Exception:
            pass


def test_corrupt_db_without_backup_raises_clear_error(tmp_path):
    path = tmp_path / "lanmux.db"
    handle = Database(path)
    _make_node(handle, "Doomed")
    handle.close()
    # No usable backup: remove the automatic startup backup.
    for old in handle.list_backups():
        old.unlink()
    path.write_bytes(b"\x00\x01\x02garbage" * 500)
    assert issubclass(DatabaseCorruptError, sqlite3.DatabaseError)
    with pytest.raises(DatabaseCorruptError, match="corrupt"):
        Database(path)
    # The corrupt file is left in place for the operator to inspect.
    assert path.exists()


def test_backup_roundtrip_and_pruning(db, tmp_path):
    _make_node(db, "A")
    first = db.backup()
    assert first.is_file()
    assert first.stat().st_mode & 0o777 == 0o600
    raw = sqlite3.connect(str(first))
    count = raw.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    raw.close()
    assert count == 1
    for _ in range(9):
        db.backup()
    kept = db.list_backups()
    assert len(kept) == 7
    assert first not in kept  # oldest pruned


def test_daily_backup_on_startup(tmp_path):
    path = tmp_path / "lanmux.db"
    handle = Database(path)
    assert len(handle.list_backups()) == 1  # taken at first open
    handle.close()
    for old in handle.list_backups():
        old.unlink()
    reopened = Database(path)
    assert len(reopened.list_backups()) == 1  # re-taken: none today
    reopened.close()


def test_docker_runner_corrupt_db_exits_2(tmp_path, monkeypatch, capsys):
    """M-28: unrecoverable corruption exits fast with FATAL + code 2
    (no children spawned, no silent restart loop)."""
    import app.docker_runner as runner

    monkeypatch.setenv("LANMUX_DB_PATH", str(tmp_path / "lanmux.db"))
    monkeypatch.setenv(
        "LANMUX_CONFIG_PATH", str(tmp_path / "mihomo" / "config.yaml")
    )
    monkeypatch.setenv("LANMUX_ASSETS_DIR", str(tmp_path / "assets"))
    monkeypatch.setenv("LANMUX_WEB_PORT", "18086")

    def _raise(*args, **kwargs):
        raise DatabaseCorruptError("database is corrupt (test)")

    monkeypatch.setattr(runner, "init_lanmux", _raise)
    assert runner.main() == 2
    assert "FATAL" in capsys.readouterr().out


# ------------------------------------------------------------------ M-29
def test_get_settings_bad_values_fall_back_to_defaults(tmp_path, caplog):
    path = tmp_path / "lanmux.db"
    handle = Database(path)
    handle.close()
    raw = sqlite3.connect(str(path))
    raw.execute(
        "INSERT INTO settings (key, value) VALUES ('ss_port', 'abc')"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    )
    raw.execute(
        "INSERT INTO settings (key, value) VALUES ('mixed_port', '99999')"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    )
    raw.execute(
        "INSERT INTO settings (key, value) VALUES "
        "('controller_port', '0')"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    )
    raw.commit()
    raw.close()
    with caplog.at_level(logging.WARNING, logger="app.database"):
        reopened = Database(path)
        settings = reopened.get_settings()  # must not raise
    assert settings.ss_port == 10001
    assert settings.mixed_port == 7890
    assert settings.controller_port == 9090
    assert "invalid setting" in caplog.text
    reopened.close()


def test_set_setting_rejects_bad_port(db):
    db.set_setting("ss_port", 10001)
    for bad in (0, 65536, -1, "abc", "12.5", True, 10002.5):
        with pytest.raises(ValueError, match="invalid ss_port"):
            db.set_setting("ss_port", bad)
    assert db.get_settings().ss_port == 10001
    db.set_setting("ss_port", "10002")  # numeric string is fine
    assert db.get_settings().ss_port == 10002


# ------------------------------------------------------------------ M-30
def test_speedtest_concurrent_writes_no_lost_increments(db):
    node_id = _make_node(db, "Flaky")
    errors: list[BaseException] = []
    per_thread = 25

    def worker():
        try:
            for _ in range(per_thread):
                db.record_speedtest_result(
                    node_id, online=False, delay_ms=None,
                    last_error="timeout",
                )
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            errors.append(exc)

    _run_threads([worker] * THREADS)
    assert not errors, f"worker errors: {errors!r}"
    node = db.get_node(node_id)
    assert node["failure_count"] == THREADS * per_thread
    assert node["consecutive_failures"] == THREADS * per_thread
    assert node["last_online"] is False
    assert node["last_error"] == "timeout"

    # One success resets the streak but keeps the cumulative count.
    db.record_speedtest_result(node_id, online=True, delay_ms=42)
    node = db.get_node(node_id)
    assert node["failure_count"] == THREADS * per_thread
    assert node["consecutive_failures"] == 0
    assert node["last_online"] is True
    assert node["last_error"] is None
    assert node["last_delay_ms"] == 42


def test_store_result_concurrent_no_lost_increments(db):
    """Same guarantee through the router's _store_result path."""
    node_id = _make_node(db, "Flaky")
    errors: list[BaseException] = []
    per_thread = 25

    def worker():
        try:
            for _ in range(per_thread):
                _store_result(
                    db,
                    SpeedtestResult(
                        id=node_id, name="Flaky",
                        online=False, error="timeout",
                    ),
                )
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            errors.append(exc)

    _run_threads([worker] * THREADS)
    assert not errors, f"worker errors: {errors!r}"
    node = db.get_node(node_id)
    assert node["failure_count"] == THREADS * per_thread
    assert node["consecutive_failures"] == THREADS * per_thread
