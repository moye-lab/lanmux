"""Safe mihomo config apply: compile -> validate -> swap -> reload.

The apply pipeline guarantees a failed reload never leaves a broken
live config:

1. Compile the DB state with :mod:`app.config_builder` — from a
   single consistent snapshot (one lock hold across all four reads,
   so no concurrent writer can tear the config).
2. Render YAML and deep-validate it (ports, proxy fields, rule
   targets — see :func:`app.config_builder.validate_config_dict`).
3. Write atomically: uniquely-named tmp file (pid + randomness, so
   concurrent applies never share it) → fsync → chmod 0600 →
   ``os.replace`` → fsync the directory. A failed write leaves no
   ``.tmp`` behind and is logged + flagged as drift (never swallowed).
4. Rotate backups first (``.bak`` … ``.bak.4``, five generations),
   then write the previous live config to ``.bak`` the same atomic
   way, so a rollback baseline survives repeated bad applies.
5. Hot reload via ``PUT /configs?force=true`` — unless the new
   config changes the controller ``secret`` or the external
   controller port. Real mihomo v1.19.34 does **not** hot-reload
   either of those (reload returns 204 but the running process
   keeps the old secret/port), so such a change takes the
   restart-required path instead: the new file stays on disk, a
   ``config_restart_pending`` flag is set, and apply reports
   ``restart_required`` — it never attempts a reload that could
   only 401 and self-lock, and it never reports success before
   the restart is confirmed.
6. On reload failure: validate a backup generation (YAML parses,
   required sections present) and restore the newest valid one;
   a missing or corrupt backup refuses the rollback outright and
   the live file is left untouched. Every exception from the
   reload — not just :class:`MihomoError` — takes this path.

Revision tracking (``config_revision_db`` /
``config_revision_running`` / ``last_apply_stage``) records which
compiled generation the DB holds vs. which one mihomo is actually
running. The DB revision is bumped with a single atomic SQL
``UPDATE ... SET revision = revision + 1`` and **only after** the
write + reload (or restart confirmation) succeeded — a failed
apply never touches it, so a failed apply can no longer fake
drift. Genuine drift after a failed reload is instead recorded
explicitly (``config_drift_flag``); a down controller is recorded
separately (``controller_unreachable``) and is not counted as
drift.

``apply()`` is serialized by a process-wide :class:`threading.Lock`
(FastAPI runs sync endpoints in a thread pool); the lock is held
for the whole pipeline, never across a ``yield``.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from .config_builder import (
    REQUIRED_SECTIONS,
    atomic_write_bytes,
    atomic_write_text,
    build_from_db,
    default_apply_gate,
    dump_yaml,
    validate_config_dict,
)
from .database import Database
from .masking import mask_value
from .mihomo_client import MihomoClient, MihomoError

__all__ = [
    "REQUIRED_SECTIONS",
    "ConfigApplyError",
    "ConfigService",
    "mask_config_text",
    "validate_config_dict",
    "validate_config_yaml",
]

logger = logging.getLogger("lanmux.config_service")

# (The masking allowlist lives in masking.py now; _mask_value
# delegates to it. The constants below are config-apply's.)

# Backup generations kept: config.yaml.bak (.bak) is the newest,
# .bak.1 … .bak.4 are older (5 generations total, L-28).
MAX_BACKUP_GENERATIONS = 5

# How much of a sanitized error string may reach the DB / API.
_MAX_ERROR_LEN = 300

# Text shown when a restart is required (also surfaced in the UI).
RESTART_INSTRUCTIONS = (
    "restart mihomo to apply it (All-in-One Docker: "
    "`docker restart <container>`; systemd: "
    "`systemctl restart lanmux-mihomo`), then confirm with "
    "POST /api/diagnostics/confirm-restart or re-apply"
)


class ConfigApplyError(Exception):
    """A config apply failed.

    ``rolled_back`` is True when the previous live config was restored
    (or, when there was no previous config, the new file was removed).
    It says only that the ON-DISK config is safe — whether the running
    mihomo also reloaded the restored config is reported in the
    message, not in this flag (a downed mihomo must not make a
    successful file restore look like a failed rollback).
    ``stage`` names where it failed: ``compile`` / ``validate`` /
    ``write`` / ``reload`` / ``restart_required``.
    ``restart_required`` is True when the new config changes the
    controller secret or port: the file was written, but mihomo must
    be restarted before the change takes effect, so the apply is
    deliberately reported as not-ok until the restart is confirmed.
    """

    def __init__(
        self,
        message: str,
        stage: str,
        rolled_back: bool = False,
        restart_required: bool = False,
        restart_reason: str = "",
    ):
        super().__init__(message)
        self.message = message
        self.stage = stage
        self.rolled_back = rolled_back
        self.restart_required = restart_required
        self.restart_reason = restart_reason


def _yaml_error_summary(exc: yaml.YAMLError) -> str:
    """Line/column + error type only — never the source line text.

    PyYAML's ``str(exc)`` embeds the offending source line, which in
    a config file is usually the line holding a credential, so it
    must never reach an API error response, a stored error string or
    a log (M-02).
    """
    problem = getattr(exc, "problem", None) or exc.__class__.__name__
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:
        return f"{problem} (line {mark.line + 1}, column {mark.column + 1})"
    return str(problem)


def validate_config_yaml(text: str) -> dict[str, Any]:
    """Parse YAML text and validate the resulting config dict."""
    try:
        config = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(
            f"generated YAML does not parse: {_yaml_error_summary(exc)}"
        ) from exc
    validate_config_dict(config)
    return config


def _mask_value(obj: Any) -> Any:
    """Recursively mask sensitive keys (see :mod:`app.masking`)."""
    return mask_value(obj)


def mask_config_text(text: str) -> str:
    """Render YAML with secrets masked (passwords / secret / uuids).

    A file that does not parse is NEVER returned raw (M-02): its
    lines may hold plaintext credentials, so the caller only gets
    the parse failure's line/column and error type. The same holds
    for YAML that does not parse to a mapping.
    """
    try:
        config = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return (
            "# config.yaml failed to parse; raw content withheld to"
            " avoid leaking credentials"
            f" ({_yaml_error_summary(exc)})"
        )
    if not isinstance(config, dict):
        return (
            "# config.yaml did not parse to a mapping; raw content"
            " withheld to avoid leaking credentials"
        )
    return yaml.safe_dump(
        _mask_value(config),
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )


class ConfigService:
    """Applies compiled configs to disk + mihomo with rollback."""

    def __init__(
        self,
        db: Database,
        config_path: str | Path,
        client_factory: Callable[[], MihomoClient] | None = None,
    ):
        self.db = db
        self.config_path = Path(config_path)
        self._apply_lock = threading.Lock()
        self._client_factory = client_factory or (
            lambda: MihomoClient(
                base_url="http://127.0.0.1:"
                f"{db.get_settings().controller_port}",
                secret=db.get_settings().mihomo_secret,
            )
        )

    # -- flags ----------------------------------------------------------
    def _flag(self, key: str) -> bool:
        try:
            return (self.db.get_setting(key, "0") or "0") == "1"
        except Exception:
            return False

    def _set_flag(self, key: str, value: bool) -> None:
        try:
            self.db.set_setting(key, "1" if value else "0")
        except Exception:
            logger.warning(
                "could not persist flag %s=%s", key, value, exc_info=True
            )

    def _clear_apply_flags(self) -> None:
        """Clear drift / unreachable / restart-pending after success."""
        self._set_flag("config_drift_flag", False)
        self._set_flag("controller_unreachable", False)
        self._set_flag("config_restart_pending", False)
        try:
            self.db.set_setting("config_restart_reason", "")
        except Exception:
            logger.warning(
                "could not clear config_restart_reason", exc_info=True
            )

    def restart_status(self) -> dict[str, Any]:
        """Current restart-pending state (for status / settings UI)."""
        try:
            reason = self.db.get_setting("config_restart_reason") or ""
        except Exception:
            reason = ""
        return {
            "pending": self._flag("config_restart_pending"),
            "reason": reason or None,
            "changed": [r for r in reason.split(",") if r],
        }

    # -- error sanitizing ----------------------------------------------
    def _sanitize_text(self, text: str) -> str:
        """Strip stored secrets from an error string, then truncate.

        ``last_apply_error`` is shown in the panel, so it must never
        carry a secret or an unbounded internal traceback.
        """
        try:
            settings = self.db.get_settings()
            for secret in (
                settings.mihomo_secret,
                settings.ss_password,
                settings.mixed_auth_pass,
            ):
                if secret and len(secret) >= 4 and secret in text:
                    text = text.replace(secret, "********")
        except Exception:
            pass
        return text[:_MAX_ERROR_LEN]

    def _reload_error_detail(self, exc: BaseException) -> str:
        """One sanitized line describing a reload failure."""
        if isinstance(exc, MihomoError):
            return self._sanitize_text(exc.message or str(exc))
        # Non-MihomoError exceptions (connection/timeout/config bugs
        # from the client factory): class name + sanitized detail,
        # never a traceback or raw internals.
        return self._sanitize_text(f"unexpected {type(exc).__name__}: {exc}")

    @staticmethod
    def _is_connection_error(exc: BaseException) -> bool:
        """True when mihomo was unreachable (vs. rejecting the config).

        Unreachable reloads are recorded as ``controller_unreachable``
        and are NOT counted as drift (L-29); rejections are drift.
        """
        if isinstance(exc, MihomoError):
            return exc.connection_error
        return isinstance(exc, (ConnectionError, TimeoutError, OSError))

    # -- apply ----------------------------------------------------------
    def apply(self) -> None:
        """Compile, validate, swap and reload. Raises ConfigApplyError.

        Serialized by the instance lock: concurrent applies run one
        after another, never on the same tmp file or revision.
        """
        with self._apply_lock:
            self._apply_locked()

    def _compile_validated(
        self, *, enforce_default_gate: bool = True
    ) -> tuple[dict[str, Any], str]:
        """Snapshot-compile + deep-validate. Raises ConfigApplyError.

        ``enforce_default_gate`` is True for the user-triggered
        :meth:`apply` (H-04: refuse to apply when nodes exist but
        Default was never bound). Startup (:meth:`apply_initial`)
        passes False: refusing at boot would leave an upgrading
        install with no config at all — strictly worse than the old
        all-DIRECT Default — and the condition is still surfaced by
        ``/api/diagnostics/status`` (``default_unbound``) + the
        panel's strong warning banner, which is the H-04 guidance.
        """
        self._set_stage("saved")
        # H-04 fail-closed gate: nodes exist but Default was never
        # bound — applying would leave ALL unmatched traffic DIRECT
        # while the panel looks configured. Refuse before anything is
        # compiled or written: the live config stays untouched and the
        # revision does not move. A library with zero nodes passes —
        # a fresh install cannot complete its first config otherwise.
        if enforce_default_gate:
            gate_error = default_apply_gate(
                self.db.list_nodes(), self.db.list_bindings()
            )
            if gate_error is not None:
                self._set_stage("compile")
                self._record_apply(False, f"apply refused: {gate_error}")
                raise ConfigApplyError(gate_error, stage="compile")
        try:
            config = build_from_db(self.db)
        except ValueError as exc:
            self._set_stage("compile")
            self._record_apply(False, f"compile failed: {exc}")
            raise ConfigApplyError(
                f"compile failed: {exc}", stage="compile"
            ) from exc
        try:
            text = dump_yaml(config)
            validate_config_yaml(text)
        except ValueError as exc:
            self._set_stage("validate")
            self._record_apply(False, f"validation failed: {exc}")
            raise ConfigApplyError(
                f"validation failed: {exc}", stage="validate"
            ) from exc
        self._set_stage("validated")
        return config, text

    def _apply_locked(self) -> None:
        # M-28 hookup: snapshot the database before writing a new
        # config, so the newest backup always predates the latest
        # applied change and a bad apply can be undone by restoring
        # the DB. A backup failure must never fail the apply itself —
        # it is only a safety net — so it is logged and the apply
        # continues.
        try:
            self.db.backup()
        except Exception as exc:  # noqa: BLE001 - best-effort safety net
            logger.warning("pre-apply database backup failed: %s", exc)
        config, text = self._compile_validated()

        had_previous = self.config_path.exists()
        live_secret, live_port = self._live_controller_identity()
        new_secret = str(config.get("secret") or "")
        new_port = self._controller_port_from_config(config)
        restart_reasons: list[str] = []
        if live_secret is not None and new_secret != live_secret:
            restart_reasons.append("mihomo_secret")
        if (
            live_port is not None
            and new_port is not None
            and new_port != live_port
        ):
            restart_reasons.append("controller_port")
        was_pending = self._flag("config_restart_pending")
        if was_pending and not restart_reasons:
            try:
                stored = self.db.get_setting("config_restart_reason") or ""
            except Exception:
                stored = ""
            restart_reasons = [r for r in stored.split(",") if r] or [
                "mihomo_secret/controller_port"
            ]
        restart_needed = bool(restart_reasons) or was_pending

        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_live_config(text, had_previous)
        except OSError as exc:
            # Persistence failure: log it, flag drift, stage failed —
            # never swallow it (M-37). The live file is untouched
            # (atomic write) and the revision is not bumped (M-26).
            self._mark_persist_failed(f"write failed: {exc}")
            raise ConfigApplyError(
                f"write failed: {exc}", stage="write"
            ) from exc
        self._set_stage("applied")

        if restart_needed:
            self._apply_restart_path(restart_reasons, was_pending)
            return

        try:
            self._client_factory().reload_config(force=True)
        except Exception as exc:  # noqa: BLE001 - every failure rolls back
            logger.exception("mihomo reload failed")
            file_restored, reloaded, rb_error = self._rollback(had_previous)
            # H-09: a failed reload is stage "failed", with a
            # sanitized error recorded for the panel.
            self._set_stage("failed")
            if self._is_connection_error(exc):
                self._set_flag("controller_unreachable", True)
                self._set_flag("config_drift_flag", False)
            else:
                self._set_flag("config_drift_flag", True)
                self._set_flag("controller_unreachable", False)
            detail = self._reload_error_detail(exc)
            if not file_restored:
                outcome = (
                    "rollback refused — "
                    f"{rb_error or 'no valid backup'}; "
                    "the new config file was left in place"
                )
            elif not had_previous:
                outcome = (
                    "new config removed (no previous config existed); "
                    "mihomo keeps its in-memory config"
                )
            elif reloaded:
                outcome = "previous config restored"
            else:
                outcome = (
                    "previous config file restored, but the live reload "
                    "failed (mihomo is unreachable); the restored config "
                    "takes effect when mihomo restarts"
                )
            error_line = f"reload failed, rolled back: {detail}; {outcome}"
            self._record_apply(False, error_line)
            raise ConfigApplyError(
                f"mihomo reload failed ({detail}); {outcome}",
                stage="reload",
                rolled_back=file_restored,
            ) from exc
        # Reload succeeded: mihomo now runs the generation the DB holds.
        self._clear_apply_flags()
        revision = self._bump_db_revision()
        self._set_revision("config_revision_running", revision)
        self._set_stage("running")
        self._record_apply(True, "")

    def _apply_restart_path(
        self, restart_reasons: list[str], was_pending: bool
    ) -> None:
        """Secret/port change: write is done, hot reload is impossible.

        Real mihomo does not hot-reload the controller secret or the
        listening port (reload returns 204, running state unchanged),
        so attempting a reload here could only 401 / refuse and
        self-lock (H-05/H-06). Instead the new file stays on disk,
        the restart-pending flag is set, and the apply reports
        ``restart_required`` until the restart is confirmed.

        When a restart was already pending, this apply is a re-apply
        after the operator may have restarted mihomo: probe the
        controller with the NEW secret/port (a reload of the on-disk
        file). Success means the restart happened — clear the flags
        and finish the apply. Failure keeps the pending state and
        the new file in place (no rollback: the new file is exactly
        what mihomo must load at restart).
        """
        reason = ",".join(restart_reasons)
        if was_pending:
            try:
                self._client_factory().reload_config(force=True)
            except Exception as exc:  # noqa: BLE001 - probe outcome is data
                logger.warning(
                    "restart probe failed; mihomo still runs the old "
                    "secret/port: %s",
                    self._reload_error_detail(exc),
                )
                self._set_flag("config_restart_pending", True)
                try:
                    self.db.set_setting("config_restart_reason", reason)
                except Exception:
                    logger.warning(
                        "could not persist config_restart_reason",
                        exc_info=True,
                    )
                self._set_stage("restart_pending")
                message = self._restart_required_message(reason)
                self._record_apply(False, message)
                raise ConfigApplyError(
                    message,
                    stage="restart_required",
                    rolled_back=False,
                    restart_required=True,
                    restart_reason=reason,
                ) from exc
            self._clear_apply_flags()
            revision = self._bump_db_revision()
            self._set_revision("config_revision_running", revision)
            self._set_stage("running")
            self._record_apply(True, "")
            return
        self._set_flag("config_restart_pending", True)
        try:
            self.db.set_setting("config_restart_reason", reason)
        except Exception:
            logger.warning(
                "could not persist config_restart_reason", exc_info=True
            )
        self._set_stage("restart_pending")
        message = self._restart_required_message(reason)
        self._record_apply(False, message)
        raise ConfigApplyError(
            message,
            stage="restart_required",
            rolled_back=False,
            restart_required=True,
            restart_reason=reason,
        )

    @staticmethod
    def _restart_required_message(reason: str) -> str:
        return (
            f"mihomo restart required: {reason} changed — the new "
            "config is written to disk, but the running mihomo still "
            "uses the old value (mihomo cannot hot-reload the "
            "controller secret or port); "
            f"{RESTART_INSTRUCTIONS}"
        )

    def confirm_restart(self) -> dict[str, Any]:
        """Confirm a pending mihomo restart took effect.

        Probes the controller with the NEW secret/port (a reload of
        the on-disk config). Success clears the pending/drift flags,
        bumps the DB revision atomically and marks the config
        running. Failure leaves the pending state untouched.
        """
        with self._apply_lock:
            if not self._flag("config_restart_pending"):
                return {
                    "ok": False,
                    "restart_pending": False,
                    "error": "no mihomo restart is pending",
                }
            try:
                self._client_factory().reload_config(force=True)
            except Exception as exc:  # noqa: BLE001 - probe outcome is data
                detail = self._reload_error_detail(exc)
                logger.warning("restart confirmation failed: %s", detail)
                if self._is_connection_error(exc):
                    self._set_flag("controller_unreachable", True)
                self._record_apply(False, f"restart not confirmed: {detail}")
                return {
                    "ok": False,
                    "restart_pending": True,
                    "error": (
                        "mihomo is not reachable with the new "
                        f"secret/port yet ({detail}); restart mihomo "
                        "first, then confirm again"
                    ),
                }
            self._clear_apply_flags()
            revision = self._bump_db_revision()
            self._set_revision("config_revision_running", revision)
            self._set_stage("running")
            self._record_apply(True, "")
            return {
                "ok": True,
                "restart_pending": False,
                "error": None,
                "db_revision": revision,
            }

    def apply_initial(self) -> Path:
        """Write the initial/upgrade config without a hot reload (M-51).

        The same safe path as :meth:`apply` — lock, snapshot compile,
        deep validation, atomic write + multi-generation backup,
        mode 0600 — but no reload is attempted (mihomo may not be
        running yet at install time). Returns the config path.

        On success the DB revision bumps atomically. When there was
        no previous live file (cold start) the running revision
        catches up too, because mihomo will load exactly this file
        at startup. On an upgrade a previous file existed, so the
        running revision is left alone — mihomo still runs the old
        config until it is restarted/reloaded, which surfaces as
        drift (or restart-pending when the secret/port changed).
        """
        with self._apply_lock:
            # Startup skips the H-04 Default gate (see
            # _compile_validated): a refused boot leaves no config at
            # all, so the unbound-Default state is compiled (DIRECT)
            # and surfaced via diagnostics + the panel warning instead.
            _config, text = self._compile_validated(
                enforce_default_gate=False
            )
            had_previous = self.config_path.exists()
            live_secret, live_port = self._live_controller_identity()
            new_secret = str(_config.get("secret") or "")
            new_port = self._controller_port_from_config(_config)
            restart_reasons: list[str] = []
            if live_secret is not None and new_secret != live_secret:
                restart_reasons.append("mihomo_secret")
            if (
                live_port is not None
                and new_port is not None
                and new_port != live_port
            ):
                restart_reasons.append("controller_port")
            try:
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                self._write_live_config(text, had_previous)
            except OSError as exc:
                self._mark_persist_failed(f"write failed: {exc}")
                raise ConfigApplyError(
                    f"write failed: {exc}", stage="write"
                ) from exc
            revision = self._bump_db_revision()
            if not had_previous:
                self._set_revision("config_revision_running", revision)
            if restart_reasons:
                self._set_flag("config_restart_pending", True)
                try:
                    self.db.set_setting(
                        "config_restart_reason", ",".join(restart_reasons)
                    )
                except Exception:
                    logger.warning(
                        "could not persist config_restart_reason",
                        exc_info=True,
                    )
            self._set_stage("applied")
            self._record_apply(True, "")
            return self.config_path

    # -- disk writes ----------------------------------------------------
    def _bak_path(self, generation: int) -> Path:
        """Backup path: gen 0 is ``config.yaml.bak``, then ``.bak.1``…"""
        suffix = ".yaml.bak" if generation == 0 else f".yaml.bak.{generation}"
        return self.config_path.with_suffix(suffix)

    def _write_live_config(self, text: str, had_previous: bool) -> None:
        """Rotate backups, write the new .bak, then atomically swap live.

        Backup rotation happens first (pure renames, no data loss on
        crash); the previous live bytes are then written to ``.bak``
        atomically (tmp → fsync → replace → fsync dir, mode 0600);
        only then is the new config swapped in the same atomic way.
        Any failure aborts before the live file is touched, and no
        ``.tmp`` file is left behind (L-27).
        """
        if had_previous:
            for generation in range(MAX_BACKUP_GENERATIONS - 2, -1, -1):
                src = self._bak_path(generation)
                if src.exists():
                    os.replace(src, self._bak_path(generation + 1))
            old_bytes = self.config_path.read_bytes()
            atomic_write_bytes(self._bak_path(0), old_bytes)
        atomic_write_text(self.config_path, text)

    def _live_controller_identity(self) -> tuple[str | None, int | None]:
        """(secret, controller port) of the live file, or (None, None).

        Unparsable / missing live file yields unknowns — the caller
        then treats the change as undetectable and takes the normal
        reload path rather than guessing.
        """
        try:
            data = yaml.safe_load(
                self.config_path.read_text(encoding="utf-8")
            )
        except (OSError, yaml.YAMLError):
            return (None, None)
        if not isinstance(data, dict):
            return (None, None)
        secret = data.get("secret")
        secret = secret if isinstance(secret, str) and secret else None
        port = self._controller_port_from_config(data)
        return (secret, port)

    @staticmethod
    def _controller_port_from_config(
        config: dict[str, Any],
    ) -> int | None:
        controller = config.get("external-controller")
        if not isinstance(controller, str) or ":" not in controller:
            return None
        try:
            port = int(controller.rsplit(":", 1)[1])
        except ValueError:
            return None
        return port if 1 <= port <= 65535 else None

    # -- rollback -------------------------------------------------------
    def _validate_backup(self, bak_path: Path) -> str | None:
        """Check a backup file is present and holds a valid config.

        Returns an error string, or None when the backup is usable.
        Never returns file contents (H-08/M-36, and no secret leak
        into logs or error responses).
        """
        if not bak_path.exists():
            return f"backup file {bak_path.name} is missing"
        try:
            text = bak_path.read_text(encoding="utf-8")
        except OSError as exc:
            return f"backup file {bak_path.name} is unreadable: {exc}"
        try:
            validate_config_yaml(text)
        except ValueError as exc:
            return (
                f"backup file {bak_path.name} is invalid "
                f"({exc}); refusing rollback"
            )
        return None

    def _find_valid_backup(self) -> tuple[Path | None, str | None]:
        """Newest valid backup generation, or (None, reason)."""
        first_error: str | None = None
        for generation in range(MAX_BACKUP_GENERATIONS):
            bak_path = self._bak_path(generation)
            error = self._validate_backup(bak_path)
            if error is None:
                return (bak_path, None)
            if first_error is None:
                first_error = error
        return (None, first_error or "no backup file exists")

    def _rollback(
        self, had_previous: bool
    ) -> tuple[bool, bool, str | None]:
        """Restore the newest valid backup and reload it. Best effort.

        Returns ``(file_restored, reloaded, rollback_error)`` — the
        file step and the live reload step are reported separately.
        When mihomo is down the file is still restored (the safe
        outcome); only the reload fails, and the caller must not
        report that as a failed rollback. When there was no previous
        config nothing is reloaded, so the second element is False.

        A missing or corrupt backup REFUSES the rollback: the live
        file is left untouched and ``file_restored`` is False (H-08).
        """
        if not had_previous:
            try:
                # No previous config: remove the new file so the next
                # apply starts clean; mihomo keeps its in-memory config.
                self.config_path.unlink(missing_ok=True)
            except OSError as exc:
                return (False, False, f"could not remove new config: {exc}")
            return (True, False, None)
        bak_path, error = self._find_valid_backup()
        if bak_path is None:
            logger.error("rollback refused: %s", error)
            return (False, False, error)
        try:
            os.replace(bak_path, self.config_path)
            os.chmod(self.config_path, 0o600)
        except OSError as exc:
            logger.error("rollback restore failed: %s", exc)
            return (False, False, f"could not restore backup: {exc}")
        try:
            self._client_factory().reload_config(force=True)
            return (True, True, None)
        except Exception:
            # File restored; only the live reload of it failed.
            return (True, False, None)

    # -- persistence-failure handling (M-37) ---------------------------
    def _mark_persist_failed(self, error: str) -> None:
        """Log a persistence failure, flag drift, stage it failed.

        The panel surfaces this via ``config_drift_flag`` /
        ``last_apply_error`` in ``GET /api/diagnostics/status`` —
        a failed write is never silent.
        """
        logger.error("config persistence failed: %s", error)
        self._set_flag("config_drift_flag", True)
        self._set_stage("failed")
        self._record_apply(False, error)

    def _record_apply(self, ok: bool, error: str) -> None:
        try:
            self.db.set_setting("last_apply_ok", "1" if ok else "0")
            self.db.set_setting("last_apply_error", error)
            self.db.set_setting(
                "last_apply_at",
                datetime.now(timezone.utc).isoformat(),
            )
        except Exception:
            # Apply outcome bookkeeping must never break the apply —
            # but it must never be silent either (M-37).
            logger.error(
                "could not record apply outcome (ok=%s)", ok, exc_info=True
            )

    # -- revision bookkeeping -------------------------------------------
    def _get_revision(self, key: str) -> int:
        try:
            return int(self.db.get_setting(key, "0") or "0")
        except (TypeError, ValueError):
            return 0

    def _set_revision(self, key: str, value: int) -> None:
        try:
            self.db.set_setting(key, str(value))
        except Exception:
            logger.warning(
                "could not persist revision %s=%s", key, value, exc_info=True
            )

    def _set_stage(self, stage: str) -> None:
        try:
            self.db.set_setting("last_apply_stage", stage)
        except Exception:
            logger.warning(
                "could not persist last_apply_stage=%s", stage, exc_info=True
            )

    def _bump_db_revision(self) -> int:
        """Atomically increment ``config_revision_db`` by 1 (H-07/M-26).

        A single SQL upsert (``... SET value = CAST(value AS
        INTEGER) + 1 ... RETURNING value``) — no read-modify-write,
        so concurrent applies can never lose an increment. The
        fallback (plain read + set) is only used when the DB handle
        has no raw connection (e.g. a test double); the apply lock
        still serializes applies in-process in that case.
        """
        conn = getattr(self.db, "conn", None)
        lock = getattr(self.db, "_lock", None)
        if conn is not None:
            try:
                ctx = lock if lock is not None else _nullcontext()
                with ctx:
                    cur = conn.execute(
                        "INSERT INTO settings (key, value)"
                        " VALUES ('config_revision_db', '1')"
                        " ON CONFLICT(key) DO UPDATE SET value ="
                        " CAST(settings.value AS INTEGER) + 1"
                        " RETURNING value"
                    )
                    row = cur.fetchone()
                    conn.commit()
                    if row is not None:
                        return int(row[0])
            except Exception:
                logger.warning(
                    "atomic revision bump failed; falling back",
                    exc_info=True,
                )
                try:
                    conn.rollback()
                except Exception:
                    pass
        revision = self._get_revision("config_revision_db") + 1
        self._set_revision("config_revision_db", revision)
        return revision

    # -- reads ----------------------------------------------------------
    def read_config_text(self) -> str | None:
        """Current live config.yaml text, or None if none exists yet."""
        if not self.config_path.exists():
            return None
        return self.config_path.read_text(encoding="utf-8")

    def read_masked_config_text(self) -> str | None:
        """Current live config.yaml with secrets masked, or None."""
        text = self.read_config_text()
        return mask_config_text(text) if text is not None else None


class _nullcontext:
    """Minimal nullcontext (avoids importing contextlib for one use)."""

    def __enter__(self) -> "_nullcontext":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False
