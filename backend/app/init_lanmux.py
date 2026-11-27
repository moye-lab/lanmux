"""One-shot installer helper: seed settings, compile the initial config.

Called by ``install.sh`` (fresh install and upgrade), by the Docker
entrypoint (:mod:`app.docker_runner`) and by the Docker runner's
cold-start path. Reads everything from the environment:

* ``LANMUX_DB_PATH`` / ``LANMUX_CONFIG_PATH`` — same defaults as
  :mod:`app.main` (``./data/lanmux.db`` / ``./data/mihomo/config.yaml``)
* ``ADMIN_PASSWORD`` — seeded via :func:`app.auth.ensure_admin_password`
* ``MIHOMO_SECRET`` / ``SS_PASSWORD`` / ``SS_CIPHER`` /
  ``LANMUX_LAN_IP`` / ``LANMUX_SS_PORT`` / ``LANMUX_MIXED_PORT`` /
  ``LANMUX_CONTROLLER_PORT`` / ``LANMUX_MIXED_AUTH_USER`` /
  ``LANMUX_MIXED_AUTH_PASS`` / ``LANMUX_EXTERNAL_UI`` — LanMux settings

The ``FENLIU_*`` and ``HUB_*`` spellings of the prefixed variables
(``FENLIU_LAN_IP`` / ``HUB_LAN_IP``, ``FENLIU_SS_PORT`` /
``HUB_SS_PORT``, ``FENLIU_DB_PATH`` / ``HUB_DB_PATH`` …) are accepted
as legacy aliases: ``LANMUX_*`` wins when set, otherwise ``FENLIU_*``,
otherwise ``HUB_*``. The ``FENLIU_*`` alias keeps pre-v1.0.0 systemd
installs working unchanged; the ``HUB_*`` alias keeps the Docker
deployment's existing ``.env`` files working unchanged.

Idempotency contract (upgrade = re-run install, data must survive)
------------------------------------------------------------------
Default mode (no flags): a setting is only seeded when **no row is
stored yet** — see :meth:`app.database.Database.has_setting`. Values
the user changed via the web UI are therefore never clobbered. The
Docker entrypoint uses this mode.

``--apply-env`` mode (used by ``install.sh``): non-secret settings
from the environment **overwrite** stored values, so a reinstall can
change ports / LAN IP / cipher / external-ui. Secrets
(``mihomo_secret``, ``ss_password``) are **still seed-only** in this
mode, and the admin password is never overwritten either — password
changes happen via the web UI only, never via reinstall.

``--auto-secrets`` mode (used by the All-in-One Docker container):
if ``mihomo_secret`` or ``ss_password`` is still empty after seeding
from the environment, cryptographically random values are generated
and persisted in SQLite so the container can cold-start with zero
mandatory secret configuration (the admin password can then be set
on the web first-run wizard).

The config file is always (re)generated from the current DB state, so
an upgrade picks up compiler changes. It is written through the same
safe path as the panel's apply (:meth:`app.config_service.ConfigService.apply_initial`):
process lock, snapshot compile, deep validation, atomic write with
multi-generation backup, mode 0600 — never a direct overwrite of the
live file. No mihomo reload is attempted (mihomo may not be running
yet at install time); when the secret / controller port changed
against the live file, a restart-pending flag is recorded instead.
With zero nodes the compiler emits the cold-start config:
every proxy group points at ``DIRECT``, so mihomo starts cleanly.

Exit codes: 0 on success, 2 on bad input (e.g. an invalid port), 1 on
any other failure. All errors are printed to stderr as one line.
"""

from __future__ import annotations

import base64
import os
import secrets
import sys
from pathlib import Path

from .auth import ensure_admin_password
from .config_service import ConfigApplyError, ConfigService
from .database import Database
from .models import DIRECT_GROUPS, GROUP_DISPLAY_NAMES

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "lanmux.db"
DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "mihomo" / "config.yaml"
)

# (env var, legacy aliases in priority order, settings key, is_port).
# Ports are validated as integers in range before they are stored.
# Resolution order is LANMUX_* > FENLIU_* > HUB_*: the FENLIU_*
# spelling keeps pre-v1.0.0 systemd installs working unchanged, and
# the HUB_* spelling keeps the Docker deployment's existing .env
# files working unchanged.
_ENV_SETTINGS: tuple[tuple[str, tuple[str, ...], str, bool], ...] = (
    ("MIHOMO_SECRET", (), "mihomo_secret", False),
    ("SS_PASSWORD", (), "ss_password", False),
    ("SS_CIPHER", (), "ss_cipher", False),
    ("LANMUX_LAN_IP", ("FENLIU_LAN_IP", "HUB_LAN_IP"), "lan_ip", False),
    ("LANMUX_SS_PORT", ("FENLIU_SS_PORT", "HUB_SS_PORT"), "ss_port", True),
    ("LANMUX_MIXED_PORT", ("FENLIU_MIXED_PORT", "HUB_MIXED_PORT"), "mixed_port", True),
    ("LANMUX_CONTROLLER_PORT", ("FENLIU_CONTROLLER_PORT", "HUB_CONTROLLER_PORT"), "controller_port", True),
    ("LANMUX_MIXED_AUTH_USER", ("FENLIU_MIXED_AUTH_USER", "HUB_MIXED_AUTH_USER"), "mixed_auth_user", False),
    ("LANMUX_MIXED_AUTH_PASS", ("FENLIU_MIXED_AUTH_PASS", "HUB_MIXED_AUTH_PASS"), "mixed_auth_pass", False),
    ("LANMUX_EXTERNAL_UI", ("FENLIU_EXTERNAL_UI", "HUB_EXTERNAL_UI"), "external_ui", False),
)


def _resolve_env(source: dict[str, str], primary: str, aliases: tuple[str, ...] = ()) -> tuple[str, str]:
    """Resolve ``primary`` with ``aliases`` as fallbacks, in order.

    Returns ``(value, name_used)``; ``value`` is ``""`` when nothing
    is set. ``name_used`` is the canonical name for error messages.
    """
    raw = source.get(primary, "")
    if raw != "":
        return raw, primary
    for alias in aliases:
        raw = source.get(alias, "")
        if raw != "":
            return raw, alias
    return "", primary


def _validate_port(env_name: str, raw: str) -> int:
    try:
        port = int(raw, 10)
    except ValueError:
        raise ValueError(
            f"{env_name}={raw!r} is not a number"
        ) from None
    if not 1 <= port <= 65535:
        raise ValueError(
            f"{env_name}={port} is out of range (1-65535)"
        )
    return port


# Secrets are seed-only in every mode: a reinstall must never
# overwrite a password the user changed via the web UI.
_SECRET_KEYS = {"mihomo_secret", "ss_password"}


def seed_settings(db: Database, env: dict[str, str] | None = None) -> list[str]:
    """Seed settings from ``env`` (default: ``os.environ``).

    Only settings with no stored row are written. Returns the list of
    settings keys that were seeded. Raises :class:`ValueError` on an
    invalid port value.
    """
    source = os.environ if env is None else env
    seeded: list[str] = []
    for env_name, alias, key, is_port in _ENV_SETTINGS:
        raw, used_name = _resolve_env(source, env_name, alias)
        if raw == "" or db.has_setting(key):
            continue
        if is_port:
            _validate_port(used_name, raw)
        db.set_setting(key, raw)
        seeded.append(key)
    return seeded


def apply_settings(db: Database, env: dict[str, str] | None = None) -> list[str]:
    """Apply settings from ``env`` (default: ``os.environ``).

    Non-secret settings overwrite stored values; secrets are still
    seed-only (see :data:`_SECRET_KEYS`). Returns the list of settings
    keys that were written. Raises :class:`ValueError` on an invalid
    port value.
    """
    source = os.environ if env is None else env
    applied: list[str] = []
    for env_name, alias, key, is_port in _ENV_SETTINGS:
        raw, used_name = _resolve_env(source, env_name, alias)
        if raw == "":
            continue
        if key in _SECRET_KEYS and db.has_setting(key):
            continue
        if is_port:
            _validate_port(used_name, raw)
        db.set_setting(key, raw)
        applied.append(key)
    return applied


def _generate_ss_password(cipher: str) -> str:
    """Generate a valid random Shadowsocks password for ``cipher``.

    Shadowsocks 2022 ciphers require a base64-encoded fixed-length PSK
    (16 bytes for aes-128, 32 bytes for aes-256 / chacha20). Classic
    AEAD ciphers accept any high-entropy URL-safe string.
    """
    normalized = (cipher or "").strip().lower()
    if normalized == "2022-blake3-aes-128-gcm":
        return base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    if normalized in (
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ):
        return base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    return secrets.token_urlsafe(18)


def ensure_generated_secrets(db: Database) -> list[str]:
    """Generate and persist missing ``mihomo_secret`` / ``ss_password``.

    Only populates keys whose current stored value is empty. Returns
    the list of keys that were auto-generated.
    """
    generated: list[str] = []
    if not (db.get_setting("mihomo_secret") or "").strip():
        db.set_setting("mihomo_secret", secrets.token_urlsafe(24))
        generated.append("mihomo_secret")
    if not (db.get_setting("ss_password") or "").strip():
        cipher = db.get_setting("ss_cipher") or "aes-128-gcm"
        db.set_setting("ss_password", _generate_ss_password(cipher))
        generated.append("ss_password")
    return generated


# v0.8.0 renamed three group display names to English (all group names
# are English now). Custom rules store the display name as their target,
# so stored targets must be rewritten or the compiled config would point
# at proxy groups that no longer exist.
RENAMED_DISPLAY_NAMES: dict[str, str] = {
    "流媒体": "Streaming",
    "AI 服务": "AI",
    "默认代理": "Default",
}

# Proxy groups that inherit the default group's binding when they have
# none: every group except the DIRECT groups and default itself.
_INHERIT_GROUP_KEYS = [
    key
    for key in GROUP_DISPLAY_NAMES
    if key not in DIRECT_GROUPS and key != "default"
]


def migrate_groups(db: Database) -> dict[str, list[str]]:
    """One-time, idempotent v0.8.0 group migrations.

    1. Empty proxy groups inherit the default group's bindings, so new
       groups work right after an upgrade instead of falling back to
       DIRECT (which would break e.g. Netflix from China). Groups that
       already have bindings are never touched; DIRECT groups
       (Apple/Microsoft/Bilibili) are excluded on purpose and stay
       unbound (= DIRECT).
    2. Custom-rule targets using pre-v0.8.0 Chinese display names are
       rewritten to the new English names.

    Returns what changed (``{"inherited": [...], "renamed": [...]}``);
    a second run returns empty lists.
    """
    inherited: list[str] = []
    default_rows = db.list_bindings("default")
    if default_rows:
        for key in _INHERIT_GROUP_KEYS:
            if db.list_bindings(key):
                continue
            for row in default_rows:
                # validate=False: the Default row being copied may be
                # dangling (its node was deleted — H-03 keeps the row
                # so the group resolves to REJECT). Copying it verbatim
                # keeps the inheriting group fail-closed too; raising
                # here would crash-loop init_lanmux at every startup.
                db.set_binding(
                    key,
                    row["node_id"],
                    role=row["role"],
                    mode=row["mode"],
                    validate=False,
                )
            inherited.append(key)
    renamed: list[str] = []
    for rule in db.list_custom_rules():
        new_target = RENAMED_DISPLAY_NAMES.get(str(rule.get("target", "")))
        if new_target:
            db.update_custom_rule(rule["id"], target=new_target)
            renamed.append(f"{rule['id']}:{rule['target']}->{new_target}")
    return {"inherited": inherited, "renamed": renamed}


def init_lanmux(
    env: dict[str, str] | None = None,
    apply_env: bool = False,
    auto_secrets: bool = False,
) -> Path:
    """Seed/apply settings and (re)generate the config file.

    ``auto_secrets`` generates missing ``mihomo_secret`` /
    ``ss_password`` so a container can cold-start with no secrets in
    its environment. Returns the config path written. Raises
    :class:`ValueError` (bad input / missing secrets) or
    :class:`OSError` (unwritable paths).
    """
    source = os.environ if env is None else env
    db_path = Path(
        source.get("LANMUX_DB_PATH")
        or source.get("FENLIU_DB_PATH")
        or source.get("HUB_DB_PATH")
        or str(DEFAULT_DB_PATH)
    )
    config_path = Path(
        source.get("LANMUX_CONFIG_PATH")
        or source.get("FENLIU_CONFIG_PATH")
        or source.get("HUB_CONFIG_PATH")
        or str(DEFAULT_CONFIG_PATH)
    )
    db = Database(db_path)
    try:
        ensure_admin_password(db, source.get("ADMIN_PASSWORD", ""))
        if apply_env:
            apply_settings(db, source)
        else:
            seed_settings(db, source)
        if auto_secrets:
            generated = ensure_generated_secrets(db)
            if generated:
                print(
                    "init_lanmux: auto-generated secrets: "
                    + ",".join(generated)
                )
        migrated = migrate_groups(db)
        if migrated["inherited"] or migrated["renamed"]:
            print(
                "init_lanmux: migrated groups: inherited="
                f"{','.join(migrated['inherited']) or '-'} "
                f"renamed={','.join(migrated['renamed']) or '-'}"
            )
        # Safe write path (M-51): lock + snapshot compile + deep
        # validation + atomic write + backup rotation, no reload.
        # Compile/validation failures keep the old ValueError
        # contract (missing secrets, bad rules); write failures
        # surface as ConfigApplyError (OSError-like).
        service = ConfigService(db, config_path)
        try:
            return service.apply_initial()
        except ConfigApplyError as exc:
            if exc.stage in ("compile", "validate"):
                raise ValueError(exc.message) from exc
            raise
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    apply_env = False
    auto_secrets = False
    for arg in argv:
        if arg in ("-h", "--help"):
            print(
                "usage: python -m app.init_lanmux [--apply-env] "
                "[--auto-secrets]\n"
                "Seeds LanMux settings from the environment and generates\n"
                "the initial mihomo config.yaml. With --apply-env,\n"
                "non-secret settings overwrite stored values (secrets\n"
                "stay seed-only). With --auto-secrets, missing\n"
                "mihomo_secret / ss_password are generated so the app can\n"
                "cold-start with no secrets in the environment. See\n"
                "app/init_lanmux.py for the environment variables."
            )
            return 0
        if arg == "--apply-env":
            apply_env = True
        elif arg == "--auto-secrets":
            auto_secrets = True
        else:
            print(f"init_lanmux: error: unknown argument: {arg}",
                  file=sys.stderr)
            return 2
    try:
        config_path = init_lanmux(apply_env=apply_env, auto_secrets=auto_secrets)
    except ValueError as exc:
        print(f"init_lanmux: error: {exc}", file=sys.stderr)
        return 2
    except ConfigApplyError as exc:
        print(f"init_lanmux: error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"init_lanmux: error: {exc}", file=sys.stderr)
        return 1
    print(f"init_lanmux: wrote {config_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
