"""SQLite storage layer for LanMux.

Standard-library ``sqlite3`` only — no ORM, no external services.

Tables
------
nodes
    id, name, uri, proxy_json (mihomo proxy dict, JSON-encoded),
    enabled, created_at
group_bindings
    id, group_key, node_id, role (main/backup), mode (fallback/url-test)
custom_rules
    id, type (DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR), value,
    target (business-group display name, DIRECT or REJECT), enabled,
    created_at
settings
    key, value (all values stored as TEXT; typed on read)
audit_log
    id, created_at, action, node_id, detail (plaintext-reveal audit
    trail for node exports / ss-link, M-05; never holds a secret)
"""

from __future__ import annotations

import functools
import json
import logging
import os
import shutil
import sqlite3
import stat
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import GROUP_DISPLAY_NAMES, Settings

logger = logging.getLogger(__name__)

# M-27: WAL lets readers proceed while a writer holds the database,
# and busy_timeout makes a contended writer wait instead of failing
# at once with "database is locked".
BUSY_TIMEOUT_MS = 5000
# Write retries (M-27): bounded exponential backoff on top of
# busy_timeout, for cross-process contention spikes.
WRITE_RETRY_ATTEMPTS = 3
WRITE_RETRY_BASE_DELAY_S = 0.05

# M-28: automatic backups. Kept next to the database file so they
# survive with the volume; pruned to the newest few.
BACKUP_DIR_NAME = "backups"
BACKUP_KEEP = 7
# A fresh backup is taken at startup when the newest one is older
# than this (the "daily" cadence for a process that restarts daily;
# a long-running process backs up on each restart).
BACKUP_MAX_AGE_S = 24 * 3600


class DatabaseCorruptError(sqlite3.DatabaseError):
    """The database file is corrupt and no usable backup could restore it.

    Raised (instead of a bare ``sqlite3.DatabaseError``) so startup
    code can fail fast with an explicit, actionable message rather
    than crash-looping: see :func:`app.docker_runner.main`.
    """

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    uri TEXT NOT NULL,
    proxy_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_delay_ms INTEGER,
    last_delay_at TEXT,
    last_online INTEGER,
    last_error TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS group_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_key TEXT NOT NULL,
    -- NOTE (H-03 fail-closed): node_id deliberately carries NO foreign
    -- key to nodes(id). An earlier schema had
    -- ``REFERENCES nodes(id) ON DELETE CASCADE``, so deleting the last
    -- bound node also deleted the binding rows and the group silently
    -- read as "never bound" -> DIRECT. Dangling rows must survive node
    -- deletion: a group whose bindings all point at deleted nodes
    -- compiles to REJECT (see config_builder._group_members). Merely
    -- dropping the CASCADE is not enough — the default NO ACTION would
    -- reject deleting a referenced node outright. Write-time validation
    -- (a new binding requires an existing node, L-19) lives at the app
    -- layer: PUT /api/rules/bindings/{group_key} rejects unknown node
    -- ids with 400.
    node_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'backup'
        CHECK (role IN ('main', 'backup')),
    mode TEXT NOT NULL DEFAULT 'fallback'
        CHECK (mode IN ('fallback', 'url-test')),
    UNIQUE (group_key, node_id)
);
CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL
        CHECK (type IN ('DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR')),
    value TEXT NOT NULL,
    target TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    action TEXT NOT NULL,
    node_id INTEGER,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS login_lockouts (
    key TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    lock_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);
"""

# Defaults applied when a settings key has no stored row.
DEFAULT_SETTINGS: dict[str, str] = {
    "lan_ip": "127.0.0.1",
    "ss_port": "10001",
    "ss_cipher": "aes-128-gcm",
    "ss_password": "",
    "mixed_port": "7890",
    "mixed_auth_user": "",
    "mixed_auth_pass": "",
    "mihomo_secret": "",
    "admin_password_hash": "",
    "controller_port": "9090",
    "external_ui": "",
}

_INT_SETTINGS = {"ss_port", "mixed_port", "controller_port"}

_NODE_FIELDS = {
    "name", "uri", "proxy", "enabled",
    "last_delay_ms", "last_delay_at", "last_online", "last_error",
    "failure_count", "consecutive_failures",
}
_RULE_FIELDS = {"type", "value", "target", "enabled", "sort_order"}

# M-08: the DB holds plaintext node credentials, the SS password and
# the mihomo secret, so the file must never be world-readable and the
# data directory must not be listable by other local users.
DB_FILE_MODE = 0o600
DATA_DIR_MODE = 0o700
_DB_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


def _converge_mode(path: Path, mode: int) -> None:
    """Best-effort chmod: tighten ``path`` to ``mode`` if it is looser.

    Only bits *outside* ``mode`` are removed — a file that is already
    stricter (e.g. 0400) is left alone. Never raises: a read-only
    mount or unusual ownership must not break startup; the DB file
    itself is always created 0600 (see ``_ensure_private_db_file``),
    convergence only fixes up files created earlier with a looser
    umask.
    """
    try:
        current = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return
    if current & ~mode:
        try:
            os.chmod(path, current & mode)
        except OSError:
            pass


def _ensure_private_db_file(path: Path) -> None:
    """Create the data dir (0700) and the DB file (0600) if missing.

    The file is pre-created with ``os.open(..., 0o600)`` *before*
    ``sqlite3.connect`` so it is never born 0644 under umask 022; an
    already-existing file keeps its content and is tightened to 0600.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    _converge_mode(path.parent, DATA_DIR_MODE)
    if not path.exists():
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, DB_FILE_MODE)
        os.close(fd)
    else:
        _converge_mode(path, DB_FILE_MODE)


def _row_to_node(row: sqlite3.Row) -> dict[str, Any]:
    node = dict(row)
    node["proxy"] = json.loads(node.pop("proxy_json"))
    node["enabled"] = bool(node["enabled"])
    # last_online is NULL until the first speedtest; never KeyError on
    # pre-Phase-2 databases (the migration in init() adds the column,
    # but be tolerant anyway).
    raw_online = node.get("last_online")
    node["last_online"] = None if raw_online is None else bool(raw_online)
    node.setdefault("last_delay_ms", None)
    node.setdefault("last_delay_at", None)
    node.setdefault("last_error", None)
    node.setdefault("failure_count", 0)
    node.setdefault("consecutive_failures", 0)
    if node.get("failure_count") is None:
        node["failure_count"] = 0
    if node.get("consecutive_failures") is None:
        node["consecutive_failures"] = 0
    return node


def _row_to_node_safe(row: sqlite3.Row) -> dict[str, Any] | None:
    """Parse one node row; return ``None`` (with a warning) when its
    stored ``proxy_json`` is unusable (M-23).

    One corrupt row must never take down the whole node list — the
    row is skipped and the damage is logged for the operator instead
    of raising through every node read path.
    """
    try:
        return _row_to_node(row)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.warning(
            "skipping node id=%s: invalid proxy_json (%s)",
            row["id"] if "id" in row.keys() else "?",
            exc,
        )
        return None


def _validate_proxy_json(proxy: dict[str, Any] | str) -> str:
    """Serialize ``proxy`` to JSON, rejecting anything unusable (M-23).

    A string must be valid JSON encoding an object; a dict is
    serialized as-is. Returns the JSON text to store.
    """
    if isinstance(proxy, str):
        try:
            parsed = json.loads(proxy)
        except json.JSONDecodeError as exc:
            raise ValueError(f"proxy JSON is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("proxy JSON must encode an object")
        return proxy
    if not isinstance(proxy, dict):
        raise ValueError("proxy must be a dict or a JSON string")
    return json.dumps(proxy, ensure_ascii=False)


def _row_to_rule(row: sqlite3.Row) -> dict[str, Any]:
    rule = dict(row)
    rule["enabled"] = bool(rule["enabled"])
    # Pre-L-04 databases gain sort_order via the migration in init();
    # be tolerant anyway so a row read before migration still works.
    rule.setdefault("sort_order", 0)
    return rule


def _locked(method):
    """Run a Database method with the instance lock held.

    The lock is acquired and released inside a single call, so the
    acquiring and releasing thread are always the same. A threading
    lock must NEVER be held across a ``yield`` in a FastAPI
    dependency: FastAPI may run the dependency's teardown on a
    different worker thread than its setup, and releasing an RLock
    from another thread raises ``RuntimeError: cannot release
    un-acquired lock`` — while the lock stays acquired forever,
    hanging every later request (2026-11-24 N1 outage: the login
    burst poisoned the request-scoped lock and the whole panel
    stopped responding, /health included). Locking lives here,
    per operation, not in app.deps.
    """

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


def _is_lock_error(exc: BaseException) -> bool:
    """True for transient SQLite lock contention (never corruption)."""
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def _retry_write(method=None, *, retry_integrity: bool = False):
    """Retry a Database write method on transient lock contention.

    Retries ``sqlite3.OperationalError`` ("database is locked" /
    "database table is locked") up to :data:`WRITE_RETRY_ATTEMPTS`
    times with exponential backoff (M-27). The wrapped method must do
    all of its SQL before its single commit, so a retry re-runs the
    whole unit of work from a clean (rolled-back) state.

    With ``retry_integrity=True`` (binding writes only) a
    ``sqlite3.IntegrityError`` from the partial unique main index is
    also retried: a cross-process race can insert a competing main
    between our demote and our upsert, and re-running demotes the
    winner first, so the retry succeeds instead of surfacing a
    spurious 500. A genuine integrity violation still fails after
    the retries are exhausted (it is re-raised, never swallowed).
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs):
            delay = WRITE_RETRY_BASE_DELAY_S
            for attempt in range(WRITE_RETRY_ATTEMPTS):
                try:
                    return fn(self, *args, **kwargs)
                except sqlite3.OperationalError as exc:
                    if not _is_lock_error(exc):
                        raise
                    try:
                        self.conn.rollback()
                    except sqlite3.Error:
                        pass
                    if attempt == WRITE_RETRY_ATTEMPTS - 1:
                        raise
                    time.sleep(delay)
                    delay *= 2
                except sqlite3.IntegrityError:
                    if not retry_integrity:
                        raise
                    try:
                        self.conn.rollback()
                    except sqlite3.Error:
                        pass
                    if attempt == WRITE_RETRY_ATTEMPTS - 1:
                        raise
                    time.sleep(delay)
                    delay *= 2

        return wrapper

    if method is not None:
        return decorator(method)
    return decorator


class Database:
    """One SQLite file, one connection. Call :meth:`close` when done."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        _ensure_private_db_file(self.path)
        # FastAPI runs sync endpoints in a thread pool, so the shared
        # connection is used from worker threads. Access is serialized
        # by the per-method lock (see _locked): every method acquires
        # and releases it inside one call, on one thread.
        self._lock = threading.RLock()
        # Set by _verify_or_restore when a corrupt file was recovered
        # from a backup (M-28); None on a normal open.
        self.recovered_from_backup: Path | None = None
        self.conn = self._new_connection()
        try:
            self._verify_or_restore()
        except DatabaseCorruptError:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
            raise
        self.init()
        self._converge_permissions()
        if self.recovered_from_backup is not None:
            # Durable marker so the panel / logs can show that a
            # recovery happened; never breaks startup if it fails.
            try:
                self.set_setting(
                    "db_recovered_from_backup",
                    f"{self.recovered_from_backup.name} at "
                    f"{datetime.now(timezone.utc).isoformat()}",
                )
            except Exception as exc:  # noqa: BLE001 - startup must not fail
                logger.warning("could not record db recovery: %s", exc)
        try:
            self._maybe_daily_backup()
        except Exception as exc:  # noqa: BLE001 - backup must not break startup
            logger.warning("automatic database backup failed: %s", exc)


    def _converge_permissions(self) -> None:
        """Tighten DB file, its SQLite sidecars and the data dir (M-08).

        Runs on every startup so files created before this fix (0644
        under umask 022) are pulled back to 0600/0700.
        """
        _converge_mode(self.path.parent, DATA_DIR_MODE)
        _converge_mode(self.path, DB_FILE_MODE)
        for suffix in _DB_SIDECAR_SUFFIXES:
            _converge_mode(
                self.path.with_name(self.path.name + suffix), DB_FILE_MODE
            )
    def _new_connection(self) -> sqlite3.Connection:
        """Open the SQLite connection with the M-27 pragmas applied."""
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # WAL + busy_timeout (M-27): readers no longer block writers
        # and a contended writer waits up to 5s instead of failing
        # at once with "database is locked". journal_mode touches the
        # file header, so on a corrupt file it raises here — swallow
        # that and let _verify_or_restore() diagnose and repair it
        # instead of failing before the integrity gate runs.
        try:
            conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            pass
        conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        return conn

    # -- integrity check / backup / restore (M-28) --------------------
    @property
    def backup_dir(self) -> Path:
        """Directory holding automatic backups (next to the DB file)."""
        return self.path.parent / BACKUP_DIR_NAME

    def _integrity_problems(self) -> list[str]:
        """Run ``PRAGMA integrity_check``; [] means the DB is healthy."""
        rows = self.conn.execute("PRAGMA integrity_check").fetchall()
        return [row[0] for row in rows if row[0] != "ok"]

    def _verify_or_restore(self) -> None:
        """Startup integrity gate (M-28).

        A healthy database passes through untouched. A corrupt one is
        restored automatically from the newest usable backup; only
        when no backup can restore it is :class:`DatabaseCorruptError`
        raised. Lock contention is transient, never corruption, and
        is re-raised unchanged so it is never "repaired" by restore.
        """
        try:
            problems = self._integrity_problems()
        except sqlite3.DatabaseError as exc:
            if _is_lock_error(exc):
                raise
            problems = [str(exc)]
        if not problems:
            return
        shown = "; ".join(problems[:3])
        logger.warning(
            "database %s failed integrity check (%s); "
            "attempting restore from backup",
            self.path, shown,
        )
        backup = self._restore_from_latest_backup()
        if backup is None:
            raise DatabaseCorruptError(
                f"database {self.path} is corrupt ({shown}) and no "
                f"usable backup was found in {self.backup_dir}. "
                "Restore a backup manually to "
                f"{self.path} (or delete the corrupt file to start "
                "fresh — all nodes, bindings and settings will be lost) "
                "and restart."
            )
        self.conn = self._new_connection()
        try:
            problems = self._integrity_problems()
        except sqlite3.DatabaseError as exc:
            if _is_lock_error(exc):
                raise
            problems = [str(exc)]
        if problems:
            raise DatabaseCorruptError(
                f"database {self.path} is still corrupt after restoring "
                f"from backup {backup} ({'; '.join(problems[:3])}). "
                "Replace the database file manually and restart."
            )
        self.recovered_from_backup = backup
        logger.warning(
            "ALERT: database %s was corrupt and was restored from "
            "backup %s. The corrupt file was kept aside as "
            "%s.corrupt-* for inspection.",
            self.path, backup, self.path,
        )

    @staticmethod
    def _backup_is_usable(path: Path) -> bool:
        """True if ``path`` opens, passes integrity_check and has the
        LanMux tables. Read-only: a candidate backup is never modified."""
        try:
            conn = sqlite3.connect(str(path))
            try:
                conn.execute("PRAGMA query_only = ON")
                problems = [
                    row[0]
                    for row in conn.execute("PRAGMA integrity_check")
                    if row[0] != "ok"
                ]
                if problems:
                    return False
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                return {"nodes", "group_bindings", "custom_rules",
                        "settings"} <= tables
            finally:
                conn.close()
        except sqlite3.Error:
            return False

    def _restore_from_latest_backup(self) -> Path | None:
        """Replace the corrupt DB file with the newest usable backup.

        The corrupt file is kept aside (``<name>.corrupt-<ts>``),
        never deleted, so no data is silently destroyed. Returns the
        backup used, or None when no usable backup exists.
        """
        try:
            self.conn.close()
        except sqlite3.Error:
            pass
        candidates = self.list_backups()
        for candidate in candidates:
            if not self._backup_is_usable(candidate):
                logger.warning("skipping unusable backup %s", candidate)
                continue
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            sidecar = self.path.with_name(
                f"{self.path.name}.corrupt-{stamp}"
            )
            try:
                if self.path.exists():
                    os.replace(self.path, sidecar)
            except OSError as exc:
                logger.warning(
                    "could not set aside corrupt db %s: %s",
                    self.path, exc,
                )
            for suffix in ("-wal", "-shm", "-journal"):
                try:
                    self.path.with_name(self.path.name + suffix).unlink(
                        missing_ok=True
                    )
                except OSError:
                    pass
            shutil.copy2(candidate, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            return candidate
        return None

    def list_backups(self) -> list[Path]:
        """Usable backup files, newest first (by modification time)."""
        if not self.backup_dir.is_dir():
            return []
        files = sorted(
            self.backup_dir.glob("lanmux-*.db"),
            # mtime_ns (not seconds): several backups can land in the
            # same second, and pruning must drop the truly oldest.
            key=lambda p: (p.stat().st_mtime_ns, p.name),
            reverse=True,
        )
        return files

    @_locked
    def backup(self) -> Path:
        """Write a timestamped backup of the live database (M-28).

        Uses the SQLite online backup API, so it is safe while the
        database is in use. Keeps the newest :data:`BACKUP_KEEP`
        backups and prunes older ones. Returns the backup path.

        This is the hook the apply flow calls before writing a new
        config: ``db.backup()`` — the wiring point lives in
        ``ConfigService.apply()`` (owned by the apply-lock cluster).
        """
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        # Microsecond timestamp: backup names are never recycled, so
        # pruning the oldest file can never make a later backup reuse
        # the same name (which would confuse "newest N" bookkeeping).
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        dest = self.backup_dir / f"lanmux-{stamp}.db"
        counter = 2
        while dest.exists():
            dest = self.backup_dir / f"lanmux-{stamp}-{counter}.db"
            counter += 1
        target = sqlite3.connect(str(dest))
        try:
            self.conn.backup(target)
        finally:
            target.close()
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        for stale in self.list_backups()[BACKUP_KEEP:]:
            try:
                stale.unlink()
            except OSError:
                pass
        return dest

    def _maybe_daily_backup(self) -> None:
        """Take a backup at startup when the newest one is stale.

        This is the "daily" cadence for a service that restarts
        regularly: at most one automatic backup per 24h, taken on
        open, never more often. Explicit :meth:`backup` calls (e.g.
        before apply) are unaffected.
        """
        newest = self.list_backups()
        if newest:
            age = time.time() - newest[0].stat().st_mtime
            if age < BACKUP_MAX_AGE_S:
                return
        self.backup()
    @_locked
    def init(self) -> None:
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    @_locked
    def _migrate(self) -> None:
        """Add columns that newer versions introduced (idempotent)."""
        columns = {
            row[1]
            for row in self.conn.execute("PRAGMA table_info(nodes)")
        }
        for column, ddl in (
            ("last_delay_ms", "ALTER TABLE nodes ADD COLUMN last_delay_ms INTEGER"),
            ("last_delay_at", "ALTER TABLE nodes ADD COLUMN last_delay_at TEXT"),
            ("last_online", "ALTER TABLE nodes ADD COLUMN last_online INTEGER"),
            ("last_error", "ALTER TABLE nodes ADD COLUMN last_error TEXT"),
            ("failure_count", "ALTER TABLE nodes ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0"),
            ("consecutive_failures", "ALTER TABLE nodes ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0"),
        ):
            if column not in columns:
                self.conn.execute(ddl)
        self._migrate_group_bindings_fk()

        # L-18: one main binding per group, enforced by the database
        # itself (partial unique index — SQLite supports it). Additive
        # only: no table is rebuilt, no rows are dropped, old
        # databases open and migrate in place.
        # Legacy databases may already hold two mains for a group
        # (the M-24 race); the index creation would fail on those
        # rows, so demote every main but the earliest per group to
        # backup first. The earliest main is kept — the newest main
        # a user set by hand is ambiguous, the oldest is the stable
        # choice and the panel shows the result.
        rows = self.conn.execute(
            "SELECT group_key, id FROM group_bindings "
            "WHERE role = 'main' ORDER BY group_key, id"
        ).fetchall()
        seen: set[str] = set()
        extra_main_ids: list[int] = []
        for row in rows:
            if row["group_key"] in seen:
                extra_main_ids.append(row["id"])
            else:
                seen.add(row["group_key"])
        if extra_main_ids:
            logger.warning(
                "migrating legacy database: demoting %d extra main "
                "binding(s) to backup (one main per group): %s",
                len(extra_main_ids), extra_main_ids,
            )
            self.conn.executemany(
                "UPDATE group_bindings SET role = 'backup' WHERE id = ?",
                [(i,) for i in extra_main_ids],
            )
        self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "idx_group_bindings_one_main ON group_bindings(group_key) "
            "WHERE role = 'main'"
        )

        # L-04: custom-rule ordering. Additive migration only: add the
        # column, then backfill sort_order from the row id (creation
        # order) so existing rules keep exactly their old order. No
        # destructive migration — the column and its values are never
        # dropped or rewritten afterwards.
        rule_columns = {
            row[1]
            for row in self.conn.execute("PRAGMA table_info(custom_rules)")
        }
        if "sort_order" not in rule_columns:
            self.conn.execute(
                "ALTER TABLE custom_rules ADD COLUMN"
                " sort_order INTEGER NOT NULL DEFAULT 0"
            )
            self.conn.execute(
                "UPDATE custom_rules SET sort_order = id"
            )

    def _migrate_group_bindings_fk(self) -> None:
        """Drop the FK on group_bindings.node_id (H-03, fail-closed).

        Old databases carry ``node_id ... REFERENCES nodes(id) ON
        DELETE CASCADE``. With ``PRAGMA foreign_keys = ON``, deleting
        a node deleted its binding rows, so a group whose last node
        was deleted read as "never bound" and silently compiled to
        DIRECT. The new schema has no FK on that column, so binding
        rows survive as dangling rows and the group compiles to REJECT
        (see :func:`app.config_builder.dead_group_keys`).

        SQLite cannot drop a foreign key with ALTER TABLE, so a table
        still carrying the FK is rebuilt: create the new table, copy
        every row verbatim (ids included), drop the old table, rename.
        Idempotent: a table with no FK to ``nodes`` is left alone, so
        fresh databases (built from the new SCHEMA) and already
        migrated ones are no-ops. Only this migration touches
        ``group_bindings``; other ``_migrate`` work (e.g. the
        db-settings cluster's indexes) is untouched.
        """
        fk_rows = self.conn.execute(
            "PRAGMA foreign_key_list(group_bindings)"
        ).fetchall()
        if not any(row["table"] == "nodes" for row in fk_rows):
            return
        # PRAGMA foreign_keys is a no-op inside a transaction, so
        # close any pending one first (e.g. the column adds above).
        self.conn.commit()
        self.conn.execute("PRAGMA foreign_keys = OFF")
        try:
            self.conn.execute(
                "CREATE TABLE group_bindings_new ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " group_key TEXT NOT NULL,"
                " node_id INTEGER NOT NULL,"
                " role TEXT NOT NULL DEFAULT 'backup'"
                " CHECK (role IN ('main', 'backup')),"
                " mode TEXT NOT NULL DEFAULT 'fallback'"
                " CHECK (mode IN ('fallback', 'url-test')),"
                " UNIQUE (group_key, node_id)"
                ")"
            )
            self.conn.execute(
                "INSERT INTO group_bindings_new"
                " (id, group_key, node_id, role, mode)"
                " SELECT id, group_key, node_id, role, mode"
                " FROM group_bindings"
            )
            self.conn.execute("DROP TABLE group_bindings")
            self.conn.execute(
                "ALTER TABLE group_bindings_new RENAME TO group_bindings"
            )
            violations = self.conn.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            if violations:
                raise sqlite3.DatabaseError(
                    "group_bindings FK rebuild left violations: "
                    f"{[dict(v) for v in violations]}"
                )
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        finally:
            # No transaction is open here (committed above, or rolled
            # back), so this takes effect on this connection.
            self.conn.execute("PRAGMA foreign_keys = ON")

    @_locked
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- nodes ---------------------------------------------------------
    @_locked
    def add_node(
        self,
        name: str,
        uri: str,
        proxy: dict[str, Any] | str,
        enabled: bool = True,
    ) -> int:
        proxy_json = _validate_proxy_json(proxy)
        cur = self.conn.execute(
            "INSERT INTO nodes (name, uri, proxy_json, enabled)"
            " VALUES (?, ?, ?, ?)",
            (name, uri, proxy_json, 1 if enabled else 0),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    @_locked
    def get_node(self, node_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM nodes WHERE id = ?", (node_id,)
        ).fetchone()
        return _row_to_node_safe(row) if row is not None else None

    @_locked
    def list_nodes(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM nodes"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY id"
        nodes = []
        for row in self.conn.execute(sql):
            node = _row_to_node_safe(row)
            if node is not None:
                nodes.append(node)
        return nodes

    @_locked
    @_retry_write
    def update_node(self, node_id: int, **fields: Any) -> None:
        unknown = set(fields) - _NODE_FIELDS
        if unknown:
            raise ValueError(f"unknown node field(s): {sorted(unknown)}")
        if not fields:
            return
        if "proxy" in fields:
            fields["proxy_json"] = _validate_proxy_json(fields.pop("proxy"))
        if "enabled" in fields:
            fields["enabled"] = 1 if fields["enabled"] else 0
        if "last_online" in fields and fields["last_online"] is not None:
            fields["last_online"] = 1 if fields["last_online"] else 0
        assignments = ", ".join(f"{k} = ?" for k in fields)
        self.conn.execute(
            f"UPDATE nodes SET {assignments} WHERE id = ?",
            (*fields.values(), node_id),
        )
        self.conn.commit()

    @_locked
    @_retry_write
    def delete_node(self, node_id: int) -> None:
        # Binding rows for this node are INTENTIONALLY kept (H-03):
        # group_bindings.node_id has no FK, so deleting a node leaves
        # dangling rows behind and a group whose last node was deleted
        # still resolves to REJECT instead of silently reading as
        # "never bound" -> DIRECT. Only an explicit clear (PUT
        # /api/rules/bindings/{group_key} with no nodes, or
        # clear_bindings()) removes binding rows.
        self.conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        self.conn.commit()

    @_locked
    @_retry_write
    def record_speedtest_result(
        self,
        node_id: int,
        *,
        online: bool,
        delay_ms: int | None,
        last_error: str | None = None,
        last_delay_at: str | None = None,
    ) -> None:
        """Persist one speedtest result with a single atomic UPDATE (M-30).

        The old path read the row, added 1 to ``failure_count`` /
        ``consecutive_failures`` in Python and wrote them back, so
        concurrent speedtests lost increments. Here the counters move
        inside the UPDATE itself (``failure_count = failure_count + 1``),
        which SQLite executes atomically — no read, no lost update.
        A success clears ``last_error`` and the consecutive streak;
        the cumulative ``failure_count`` is history and is kept.
        """
        at = last_delay_at or datetime.now(timezone.utc).isoformat()
        if online:
            self.conn.execute(
                "UPDATE nodes SET last_delay_ms = ?, last_delay_at = ?,"
                " last_online = 1, last_error = NULL,"
                " consecutive_failures = 0 WHERE id = ?",
                (delay_ms, at, node_id),
            )
        else:
            self.conn.execute(
                "UPDATE nodes SET last_delay_ms = ?, last_delay_at = ?,"
                " last_online = 0, last_error = ?,"
                " failure_count = failure_count + 1,"
                " consecutive_failures = consecutive_failures + 1"
                " WHERE id = ?",
                (delay_ms, at, last_error, node_id),
            )
        self.conn.commit()

    # -- group bindings -------------------------------------------------
    def _validate_binding_target(self, group_key: str, node_id: int) -> None:
        """L-19: a binding may only name a real group and a real node.

        ``group_key`` must be one of the business groups and the node
        must exist; anything else is rejected here (``ValueError``) so
        the user-facing write paths can never create an orphan binding.
        Orphan (dangling) rows can still exist in stored state — since
        H-03, deleting a node deliberately keeps its binding rows so
        the group resolves to REJECT instead of silently DIRECT — but
        no write path may create one except the migration inheritance
        in :func:`app.init_lanmux.migrate_groups`, which copies an
        already-stored (possibly dangling) Default row verbatim.
        """
        if group_key not in GROUP_DISPLAY_NAMES:
            raise ValueError(
                f"unknown group_key: {group_key!r} "
                f"(valid: {sorted(GROUP_DISPLAY_NAMES)})"
            )
        row = self.conn.execute(
            "SELECT 1 FROM nodes WHERE id = ?", (node_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown node id: {node_id}")

    @_locked
    @_retry_write(retry_integrity=True)
    def set_binding(
        self,
        group_key: str,
        node_id: int,
        role: str = "backup",
        mode: str = "fallback",
        *,
        validate: bool = True,
    ) -> int:
        """Upsert one binding. ``validate=False`` is for internal use
        only (migration inheritance, which copies an already-stored
        Default row verbatim — possibly dangling after its node was
        deleted); every user-facing write keeps validation on.
        """
        if role not in ("main", "backup"):
            raise ValueError(f"invalid binding role: {role!r}")
        if mode not in ("fallback", "url-test"):
            raise ValueError(f"invalid binding mode: {mode!r}")
        if validate:
            self._validate_binding_target(group_key, node_id)
        # M-24: demoting the previous main and inserting the new one
        # happen in this single locked call with one commit, so two
        # concurrent writers can never leave two mains behind. The
        # L-18 partial unique index is the second line of defence
        # (cross-process races retry via retry_integrity=True).
        if role == "main":
            self.conn.execute(
                "UPDATE group_bindings SET role = 'backup'"
                " WHERE group_key = ? AND role = 'main'"
                " AND node_id != ?",
                (group_key, node_id),
            )
        cur = self.conn.execute(
            "INSERT INTO group_bindings (group_key, node_id, role, mode)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(group_key, node_id) DO UPDATE"
            " SET role = excluded.role, mode = excluded.mode",
            (group_key, node_id, role, mode),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    @_locked
    @_retry_write(retry_integrity=True)
    def replace_bindings(
        self,
        group_key: str,
        main: int | None,
        backups: list[int],
        mode: str = "fallback",
    ) -> None:
        """Replace a whole group's bindings in one transaction (M-24).

        This is what ``PUT /api/rules/bindings/{group}`` uses: the
        old clear-then-set-in-separate-calls sequence interleaved
        between concurrent requests, which is exactly how the audit
        produced two mains. Here clear + inserts share one lock hold
        and one commit, so a concurrent PUT either runs fully before
        or fully after — never in the middle.
        """
        if mode not in ("fallback", "url-test"):
            raise ValueError(f"invalid binding mode: {mode!r}")
        node_ids = [main] if main is not None else []
        node_ids += list(backups)
        if len(set(node_ids)) != len(node_ids):
            raise ValueError(
                "main node and backup nodes must be distinct"
            )
        if group_key not in GROUP_DISPLAY_NAMES:
            raise ValueError(
                f"unknown group_key: {group_key!r} "
                f"(valid: {sorted(GROUP_DISPLAY_NAMES)})"
            )
        for node_id in node_ids:
            self._validate_binding_target(group_key, node_id)
        self.conn.execute(
            "DELETE FROM group_bindings WHERE group_key = ?", (group_key,)
        )
        if main is not None:
            self.conn.execute(
                "INSERT INTO group_bindings (group_key, node_id, role, mode)"
                " VALUES (?, ?, 'main', ?)",
                (group_key, main, mode),
            )
        for node_id in backups:
            self.conn.execute(
                "INSERT INTO group_bindings (group_key, node_id, role, mode)"
                " VALUES (?, ?, 'backup', ?)",
                (group_key, node_id, mode),
            )
        self.conn.commit()

    @_locked
    def list_bindings(
        self, group_key: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM group_bindings"
        args: tuple[Any, ...] = ()
        if group_key is not None:
            sql += " WHERE group_key = ?"
            args = (group_key,)
        # Main binding(s) first, then backups, each in insertion order.
        sql += (" ORDER BY group_key,"
                " CASE role WHEN 'main' THEN 0 ELSE 1 END, id")
        return [dict(r) for r in self.conn.execute(sql, args)]

    @_locked
    @_retry_write
    def clear_bindings(self, group_key: str) -> None:
        if group_key not in GROUP_DISPLAY_NAMES:
            raise ValueError(
                f"unknown group_key: {group_key!r} "
                f"(valid: {sorted(GROUP_DISPLAY_NAMES)})"
            )
        self.conn.execute(
            "DELETE FROM group_bindings WHERE group_key = ?", (group_key,)
        )
        self.conn.commit()

    # -- custom rules ---------------------------------------------------
    @_locked
    @_retry_write
    def add_custom_rule(
        self, type: str, value: str, target: str, enabled: bool = True
    ) -> int:
        if type not in ("DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR"):
            raise ValueError(f"invalid custom rule type: {type!r}")
        # New rules go last in generation order (L-04).
        row = self.conn.execute(
            "SELECT COALESCE(MAX(sort_order), 0) FROM custom_rules"
        ).fetchone()
        sort_order = int(row[0]) + 1
        cur = self.conn.execute(
            "INSERT INTO custom_rules (type, value, target, enabled,"
            " sort_order) VALUES (?, ?, ?, ?, ?)",
            (type, value, target, 1 if enabled else 0, sort_order),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    @_locked
    def get_custom_rule(self, rule_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM custom_rules WHERE id = ?", (rule_id,)
        ).fetchone()
        return _row_to_rule(row) if row is not None else None

    @_locked
    def list_custom_rules(
        self, enabled_only: bool = False
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM custom_rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        # L-04: generation order is sort_order, then id (stable).
        sql += " ORDER BY sort_order, id"
        return [_row_to_rule(r) for r in self.conn.execute(sql)]

    @_locked
    @_retry_write
    def move_custom_rule(self, rule_id: int, direction: str) -> bool:
        """Move a custom rule one step up/down in generation order.

        Swaps ``sort_order`` with the adjacent rule; returns False
        when the rule is already at that edge (no-op, not an error).
        """
        if direction not in ("up", "down"):
            raise ValueError(f"invalid direction: {direction!r}")
        rule = self.get_custom_rule(rule_id)
        if rule is None:
            return False
        if direction == "up":
            neighbor = self.conn.execute(
                "SELECT * FROM custom_rules"
                " WHERE sort_order < ? OR (sort_order = ? AND id < ?)"
                " ORDER BY sort_order DESC, id DESC LIMIT 1",
                (rule["sort_order"], rule["sort_order"], rule_id),
            ).fetchone()
        else:
            neighbor = self.conn.execute(
                "SELECT * FROM custom_rules"
                " WHERE sort_order > ? OR (sort_order = ? AND id > ?)"
                " ORDER BY sort_order ASC, id ASC LIMIT 1",
                (rule["sort_order"], rule["sort_order"], rule_id),
            ).fetchone()
        if neighbor is None:
            return False
        self.conn.execute(
            "UPDATE custom_rules SET sort_order = ? WHERE id = ?",
            (dict(neighbor)["sort_order"], rule_id),
        )
        self.conn.execute(
            "UPDATE custom_rules SET sort_order = ? WHERE id = ?",
            (rule["sort_order"], dict(neighbor)["id"]),
        )
        self.conn.commit()
        return True

    @_locked
    @_retry_write
    def update_custom_rule(self, rule_id: int, **fields: Any) -> None:
        unknown = set(fields) - _RULE_FIELDS
        if unknown:
            raise ValueError(f"unknown custom rule field(s): {sorted(unknown)}")
        if not fields:
            return
        if "type" in fields and fields["type"] not in (
            "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR",
        ):
            raise ValueError(f"invalid custom rule type: {fields['type']!r}")
        if "enabled" in fields:
            fields["enabled"] = 1 if fields["enabled"] else 0
        assignments = ", ".join(f"{k} = ?" for k in fields)
        self.conn.execute(
            f"UPDATE custom_rules SET {assignments} WHERE id = ?",
            (*fields.values(), rule_id),
        )
        self.conn.commit()

    @_locked
    @_retry_write
    def delete_custom_rule(self, rule_id: int) -> None:
        self.conn.execute(
            "DELETE FROM custom_rules WHERE id = ?", (rule_id,)
        )
        self.conn.commit()

    # -- settings -------------------------------------------------------
    @_locked
    def has_setting(self, key: str) -> bool:
        """True if ``key`` has an explicitly stored row.

        Unlike :meth:`get_setting`, this distinguishes a stored value
        from a built-in default — the installer uses it to seed a
        setting only when the user has never set it (so an upgrade
        never clobbers a value changed via the web UI).
        """
        row = self.conn.execute(
            "SELECT 1 FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row is not None

    @_locked
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        if row is not None:
            return row["value"]
        if key in DEFAULT_SETTINGS:
            return DEFAULT_SETTINGS[key]
        return default

    @staticmethod
    def _validate_setting_value(key: str, value: Any) -> None:
        """Reject an out-of-range port at write time (M-29/M-25).

        Port settings must be integers in 1–65535; anything else
        raises ``ValueError`` before anything is written. Non-port
        settings are unvalidated here (their validation lives in the
        routers / seed helpers that own them).
        """
        if key not in _INT_SETTINGS:
            return
        if isinstance(value, bool):
            raise ValueError(
                f"invalid {key}: {value!r} (must be an integer 1-65535)"
            )
        if isinstance(value, int):
            port = value
        elif isinstance(value, float):
            if not value.is_integer():
                raise ValueError(
                    f"invalid {key}: {value!r} "
                    "(must be an integer 1-65535)"
                )
            port = int(value)
        else:
            try:
                port = int(str(value).strip(), 10)
            except (TypeError, ValueError):
                raise ValueError(
                    f"invalid {key}: {value!r} "
                    "(must be an integer 1-65535)"
                ) from None
        if not 1 <= port <= 65535:
            raise ValueError(
                f"invalid {key}: {value!r} (must be an integer 1-65535)"
            )

    @_locked
    @_retry_write
    def set_setting(self, key: str, value: Any) -> None:
        self._validate_setting_value(key, value)
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
        self.conn.commit()

    @_locked
    @_retry_write
    def set_settings_bulk(self, settings: dict[str, Any]) -> None:
        """Write many settings in a single transaction (M-25).

        Every value is validated first; only then is anything
        written, and the whole batch commits (or rolls back) as one
        unit — so a ``PUT /api/settings`` that fails validation can
        never leave earlier fields persisted.
        """
        for key, value in settings.items():
            self._validate_setting_value(key, value)
        for key, value in settings.items():
            self.conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )
        self.conn.commit()

    @_locked
    @_retry_write
    def set_admin_password_if_unset(self, password_hash: str) -> bool:
        """Atomically set the admin password hash iff none is stored.

        Single locked check-and-set: concurrent first-run setups (web
        setup endpoint vs ``ADMIN_PASSWORD`` seeding) create exactly
        one admin. Returns False if a hash was already stored.
        """
        row = self.conn.execute(
            "SELECT value FROM settings WHERE key = 'admin_password_hash'"
        ).fetchone()
        if row is not None and row["value"]:
            return False
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("admin_password_hash", str(password_hash)),
        )
        self.conn.commit()
        return True

    # -- login lockouts (H-01) -----------------------------------------
    @_locked
    def get_login_lockout(self, key: str) -> dict[str, Any] | None:
        """One lockout row: ``{failures, lock_count, locked_until}``."""
        row = self.conn.execute(
            "SELECT failures, lock_count, locked_until"
            " FROM login_lockouts WHERE key = ?",
            (key,),
        ).fetchone()
        return dict(row) if row is not None else None

    @_locked
    @_retry_write
    def note_login_failure(
        self,
        key: str,
        max_failures: int = 5,
        base_lock_seconds: int = 900,
        max_lock_seconds: int = 7200,
        now: Any = None,
    ) -> Any | None:
        """Count one failed login for ``key`` (atomic read-modify-write).

        On reaching ``max_failures`` a lock is imposed: the lock
        duration doubles with each successive lock
        (``base, 2*base, 4*base, ...`` capped at ``max_lock_seconds``),
        the failure counter resets, and the lock expiry (ISO string)
        is returned. While already locked, the call is a no-op and
        returns the current expiry. Otherwise returns None.
        """
        from datetime import datetime, timedelta, timezone

        now_dt = now or datetime.now(timezone.utc)
        row = self.conn.execute(
            "SELECT failures, lock_count, locked_until"
            " FROM login_lockouts WHERE key = ?",
            (key,),
        ).fetchone()
        failures = int(row["failures"]) if row is not None else 0
        lock_count = int(row["lock_count"]) if row is not None else 0
        locked_until = row["locked_until"] if row is not None else None
        if locked_until:
            locked_dt = datetime.fromisoformat(locked_until)
            if locked_dt.tzinfo is None:
                locked_dt = locked_dt.replace(tzinfo=timezone.utc)
            if locked_dt > now_dt:
                return locked_until
        failures += 1
        if failures < max_failures:
            self.conn.execute(
                "INSERT INTO login_lockouts"
                " (key, failures, lock_count, locked_until)"
                " VALUES (?, ?, ?, NULL)"
                " ON CONFLICT(key) DO UPDATE SET"
                " failures = excluded.failures,"
                " lock_count = excluded.lock_count,"
                " locked_until = NULL",
                (key, failures, lock_count),
            )
            self.conn.commit()
            return None
        lock_count += 1
        duration = min(
            base_lock_seconds * (2 ** (lock_count - 1)), max_lock_seconds
        )
        until = (now_dt + timedelta(seconds=duration)).isoformat()
        self.conn.execute(
            "INSERT INTO login_lockouts"
            " (key, failures, lock_count, locked_until)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET"
            " failures = 0,"
            " lock_count = excluded.lock_count,"
            " locked_until = excluded.locked_until",
            (key, 0, lock_count, until),
        )
        self.conn.commit()
        return until

    @_locked
    @_retry_write
    def clear_login_lockout(self, key: str) -> None:
        self.conn.execute(
            "DELETE FROM login_lockouts WHERE key = ?", (key,)
        )
        self.conn.commit()

    @_locked
    def get_settings(self) -> Settings:
        data: dict[str, Any] = dict(DEFAULT_SETTINGS)
        for row in self.conn.execute("SELECT key, value FROM settings"):
            data[row["key"]] = row["value"]
        for key in _INT_SETTINGS:
            # M-29: a damaged row (non-numeric, out of range) must
            # never take down every endpoint that reads settings.
            # Fall back to the default for that key and warn.
            raw = data[key]
            try:
                value = int(raw)  # type: ignore[arg-type]
                if not 1 <= value <= 65535:
                    raise ValueError(f"out of range: {raw!r}")
            except (TypeError, ValueError):
                logger.warning(
                    "ignoring invalid setting %s=%r, falling back to "
                    "default %s",
                    key, raw, DEFAULT_SETTINGS[key],
                )
                value = int(DEFAULT_SETTINGS[key])
            data[key] = value
        # Ignore any unknown keys a future version may have stored.
        known = {k: v for k, v in data.items() if k in Settings.model_fields}
        return Settings(**known)

    # -- audit log ------------------------------------------------------
    # Plaintext reveals (node export, ss-link) are recorded here so a
    # credential disclosure can be traced back to when it happened
    # (M-05). Details never contain a secret value, only ids/names.
    @_locked
    def log_audit(
        self,
        action: str,
        node_id: int | None = None,
        detail: str = "",
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO audit_log (action, node_id, detail)"
            " VALUES (?, ?, ?)",
            (action, node_id, detail),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    @_locked
    def list_audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            )
        ]


def init_db(path: str | Path) -> Database:
    """Open (creating if needed) the LanMux database at ``path``."""
    return Database(path)
