"""All-in-One Docker container entrypoint & dual-process supervisor.

Runs both ``mihomo`` and ``uvicorn`` (FastAPI + Web UI) inside a single
container without needing external process managers (no supervisord):

1. Provisions bundled geodata (``GeoIP.dat``, ``GeoSite.dat``,
   ``Country.mmdb``) and ``metacubexd`` UI files from ``LANMUX_ASSETS_DIR``
   into the mihomo home directory (``/data/mihomo``) on first boot
   without overwriting user-customized files.
2. Seeds SQLite settings and generates ``config.yaml`` via
   :func:`app.init_lanmux.init_lanmux` with ``auto_secrets=True`` so the
   container can cold-start with zero mandatory secrets (admin password
   is set via the Web UI setup wizard if ``ADMIN_PASSWORD`` is unset).
3. Spawns ``mihomo -d <mihomo_dir> -f <config_path>`` and
   ``uvicorn app.main:app``.
4. Supervises both children:
   * Forwards ``SIGTERM`` / ``SIGINT`` for clean shutdown.
   * Restarts ``mihomo`` with exponential backoff if it exits
     unexpectedly, keeping the Web UI reachable for recovery.
   * Exits if ``uvicorn`` exits so Docker's restart policy takes over.

Privilege model (H-12): the image runs this entrypoint as root ONLY so
it can fix the ownership of a host-mounted ``/data`` (a fresh bind mount
is created root-owned by the Docker daemon, and the service user could
not write to it). :func:`main` fixes the data directories' ownership
and then drops to the unprivileged ``lanmux`` user (UID/GID 10001,
created in the Dockerfile) before any service code runs, so ``mihomo``
and ``uvicorn`` never run as root. When the entrypoint already runs as
``lanmux`` (plain ``docker run`` with a named volume, which inherits the
image's ``/data`` ownership), the ownership fix is skipped and the data
directories are only checked for writability, failing loudly with a
remediation hint instead of crash-looping on obscure PermissionErrors.
"""

from __future__ import annotations

import os
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Mapping

from .database import DatabaseCorruptError
from .init_lanmux import init_lanmux

GEODATA_FILES = ("GeoIP.dat", "GeoSite.dat", "Country.mmdb")
BACKOFF_STEPS = (1.0, 2.0, 5.0, 10.0, 30.0)

# Unprivileged service user (H-12). Must match the Dockerfile, which
# creates ``lanmux`` with UID/GID 10001. The fallback is only used for
# the remediation hint when the user cannot be resolved (development
# runs outside the image).
SERVICE_USER = "lanmux"
SERVICE_UID_FALLBACK = 10001
SERVICE_GID_FALLBACK = 10001


def _log(msg: str) -> None:
    print(f"[lanmux-docker] {msg}", flush=True)


def _tighten_dir_mode(path: Path, mode: int = 0o700) -> None:
    """Best-effort chmod: remove permission bits outside ``mode`` (M-08).

    Same rule as ``app.database._converge_mode`` (kept in sync): only
    loosens nothing, never raises — a shared or read-only mount must
    not break container startup. The DB file itself is converged by
    ``Database.__init__``; this covers the directories this module
    creates (the mihomo/config dir and the DB parent).
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


def detect_lan_ip() -> str:
    """Best-effort detection of the host's primary outbound IPv4 address.

    Useful under ``network_mode: host`` when ``LANMUX_LAN_IP`` is not set.
    Falls back to ``127.0.0.1`` if offline or unresolvable.
    """
    for target in ("223.5.5.5", "8.8.8.8"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((target, 80))
            ip = sock.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            continue
        finally:
            sock.close()
    return "127.0.0.1"


def sync_assets(
    assets_dir: Path,
    mihomo_dir: Path,
    include_ui: bool = True,
    refresh: bool = False,
) -> list[str]:
    """Provision bundled geodata and metacubexd into ``mihomo_dir``.

    By default existing files are preserved for backwards compatibility.
    ``refresh=True`` intentionally replaces the bundled assets so an image
    upgrade can pick up newer GeoIP/GeoSite data or a newer metacubexd build.
    This is opt-in because ``/data`` is persistent and may contain operator
    customizations.
    """
    mihomo_dir.mkdir(parents=True, exist_ok=True)
    _tighten_dir_mode(mihomo_dir)
    copied: list[str] = []
    if not assets_dir.is_dir():
        return copied

    for filename in GEODATA_FILES:
        src = assets_dir / filename
        dst = mihomo_dir / filename
        if src.is_file() and (refresh or not dst.exists()):
            shutil.copy2(src, dst)
            copied.append(filename)

    if include_ui:
        src_ui = assets_dir / "ui"
        dst_ui = mihomo_dir / "ui"
        if (src_ui / "index.html").is_file() and (
            refresh or not (dst_ui / "index.html").exists()
        ):
            if refresh and dst_ui.exists():
                shutil.rmtree(dst_ui)
            shutil.copytree(src_ui, dst_ui, dirs_exist_ok=True)
            copied.append("ui/")

    return copied


def _resolve_prefixed(env: Mapping[str, str], primary: str, *aliases: str, default: str) -> str:
    """Resolve ``primary`` with legacy ``aliases`` as fallbacks.

    Priority: ``LANMUX_*`` > ``FENLIU_*`` > ``HUB_*`` > ``default``.
    Empty strings count as unset.
    """
    for name in (primary, *aliases):
        value = (env.get(name) or "").strip()
        if value:
            return value
    return default


def _resolve_runtime_paths(env: Mapping[str, str]) -> dict[str, Path]:
    """Resolve the data/config/assets directories from the environment.

    Shared by :func:`prepare_runtime_env` and the privilege setup in
    :func:`main` so both agree on which directories the service user
    must own (defaults: DB ``/data/lanmux.db``, config
    ``/data/mihomo/config.yaml``, assets ``/opt/lanmux-assets``).
    """
    db_path = Path(
        _resolve_prefixed(
            env, "LANMUX_DB_PATH", "FENLIU_DB_PATH", "HUB_DB_PATH",
            default="/data/lanmux.db",
        )
    )
    config_path = Path(
        _resolve_prefixed(
            env, "LANMUX_CONFIG_PATH", "FENLIU_CONFIG_PATH", "HUB_CONFIG_PATH",
            default="/data/mihomo/config.yaml",
        )
    )
    assets_dir = Path(
        _resolve_prefixed(
            env, "LANMUX_ASSETS_DIR", "HUB_ASSETS_DIR",
            default="/opt/lanmux-assets",
        )
    )
    return {
        "db_path": db_path,
        "config_path": config_path,
        "mihomo_dir": config_path.parent,
        "assets_dir": assets_dir,
    }


def _service_user_ids() -> tuple[int, int, str] | None:
    """Resolve the ``lanmux`` service user to ``(uid, gid, home dir)``.

    Returns ``None`` when the user does not exist (development runs
    outside the image): the caller then keeps the current identity and
    warns instead of failing, so local dev/test runs keep working.
    """
    try:
        entry = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        return None
    return entry.pw_uid, entry.pw_gid, entry.pw_dir


def _chown_tree(root: Path, uid: int, gid: int) -> int:
    """Recursively chown ``root`` to ``uid:gid`` where it differs.

    Idempotent: entries already owned by the service user are left
    untouched, so a restart on an already-correct directory changes
    nothing. Symlinks are never followed. Returns the number of entries
    whose ownership was changed. File modes are left alone (DB/config
    file-mode hardening is a separate concern).
    """
    changed = 0

    def _chown_one(path: Path) -> None:
        nonlocal changed
        try:
            st = os.lstat(path)
        except OSError:
            return
        if st.st_uid != uid or st.st_gid != gid:
            os.chown(path, uid, gid, follow_symlinks=False)
            changed += 1

    root.mkdir(parents=True, exist_ok=True)
    _chown_one(root)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            _chown_one(Path(dirpath) / name)
    return changed


def _ensure_privileges(env: Mapping[str, str]) -> None:
    """Fix data-directory ownership and drop root before services start.

    * Running as root (the compose path, where the entrypoint starts as
      ``0:0`` so it can fix a root-owned bind mount): chown the database
      and mihomo directories to the ``lanmux`` service user, then
      ``setgid``/``setuid`` to it. Everything after this point —
      :func:`prepare_runtime_env`, :func:`init_lanmux`, ``mihomo`` and
      ``uvicorn`` — runs as ``lanmux``.
    * Already non-root (plain ``docker run`` with the image default
      ``USER lanmux``): only verify the data directories exist and are
      writable; if not, raise ``OSError`` with the exact remediation so
      the container fails loudly instead of crash-looping on obscure
      ``PermissionError``s later.
    * Root without a ``lanmux`` user (development outside the image):
      warn and continue as-is; the image always carries the user.
    """
    paths = _resolve_runtime_paths(env)
    data_dirs = {paths["db_path"].parent, paths["mihomo_dir"]}
    # Drop a directory when it nests inside another (default layout:
    # /data/mihomo sits inside /data); one recursive chown covers both.
    ordered = sorted(data_dirs, key=lambda p: len(p.parts))
    top_dirs: list[Path] = []
    for candidate in ordered:
        if not any(
            candidate == top or candidate.is_relative_to(top)
            for top in top_dirs
        ):
            top_dirs.append(candidate)

    if os.geteuid() == 0:
        ids = _service_user_ids()
        if ids is None:
            _log(
                f"warning: service user '{SERVICE_USER}' not found; "
                "continuing as root (development run outside the image?)"
            )
            return
        uid, gid, home = ids
        for data_dir in top_dirs:
            try:
                changed = _chown_tree(data_dir, uid, gid)
            except OSError as exc:
                raise OSError(
                    f"cannot fix ownership of {data_dir}: {exc}"
                ) from exc
            if changed:
                _log(
                    f"fixed ownership of {data_dir} "
                    f"({changed} entries -> {SERVICE_USER})"
                )
        try:
            os.initgroups(SERVICE_USER, gid)
            os.setgid(gid)
            os.setuid(uid)
        except OSError as exc:
            raise OSError(
                f"cannot drop privileges to {SERVICE_USER}: {exc}"
            ) from exc
        if os.geteuid() == 0:
            raise OSError(
                f"privilege drop to {SERVICE_USER} did not take effect"
            )
        os.environ["HOME"] = home
        os.environ["USER"] = SERVICE_USER
        os.environ["LOGNAME"] = SERVICE_USER
        _log(f"dropped privileges to {SERVICE_USER} (uid={uid}, gid={gid})")
        # Verify the drop actually left the data directories usable:
        # ownership of the directory itself is fixed above, but a host
        # bind mount can still be unreachable when one of its *parent*
        # directories is not traversable by the service user. Fail here
        # with a clear message instead of a bare PermissionError later.
        for data_dir in top_dirs:
            if not os.access(data_dir, os.R_OK | os.W_OK | os.X_OK):
                raise OSError(
                    f"data directory {data_dir} is not accessible after "
                    f"dropping privileges to {SERVICE_USER}; check the "
                    "directory and its parent directories are traversable "
                    f"by uid {uid} (host bind-mount parent permissions)"
                )
        return

    # Already unprivileged: verify writability, fail loudly with a fix.
    ids = _service_user_ids()
    uid_hint = ids[0] if ids else SERVICE_UID_FALLBACK
    gid_hint = ids[1] if ids else SERVICE_GID_FALLBACK
    hint = (
        "if it is a host bind mount, fix it once on the host with "
        f"'chown -R {uid_hint}:{gid_hint} <host-dir>', or start the "
        "container as root ('--user 0:0') so the entrypoint can fix "
        "ownership and drop privileges itself"
    )
    for data_dir in top_dirs:
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise OSError(
                f"cannot create data directory {data_dir}: {exc}; {hint}"
            ) from exc
        if not os.access(data_dir, os.W_OK):
            raise OSError(f"data directory {data_dir} is not writable; {hint}")


def prepare_runtime_env(base_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the effective runtime environment for init_lanmux and uvicorn.

    All prefixed variables are normalized to their ``LANMUX_*`` spelling
    here (``LANMUX_*`` wins, then ``FENLIU_*``, then ``HUB_*``), so the
    downstream seed helper and uvicorn only ever see the new names.
    The default database moved from ``/data/hub.db`` to
    ``/data/lanmux.db`` in v1.0.0: when the new file is missing but the
    old one exists, it is renamed in place (same volume, atomic).
    """
    env = dict(os.environ if base_env is None else base_env)

    paths = _resolve_runtime_paths(env)
    db_path = paths["db_path"]
    config_path = paths["config_path"]
    mihomo_dir = paths["mihomo_dir"]
    assets_dir = paths["assets_dir"]
    env["LANMUX_DB_PATH"] = str(db_path)
    env["LANMUX_CONFIG_PATH"] = str(config_path)
    env["LANMUX_ASSETS_DIR"] = str(assets_dir)

    # v1.0.0 database migration: /data/hub.db -> /data/lanmux.db.
    # Only for the default path, and only when the new file is absent
    # (an explicit LANMUX_DB_PATH is used as-is, never migrated).
    if db_path == Path("/data/lanmux.db") and not db_path.exists():
        legacy_db = Path("/data/hub.db")
        if legacy_db.is_file():
            db_path.parent.mkdir(parents=True, exist_ok=True)
            legacy_db.rename(db_path)
            _log("migrated database /data/hub.db -> /data/lanmux.db")

    # Inside the All-in-One container, mihomo and lanmux-web share loopback.
    env.setdefault("MIHOMO_BASE_URL", "http://127.0.0.1:{port}")
    web_port = _resolve_prefixed(
        env, "LANMUX_WEB_PORT", "HUB_WEB_PORT", default="8086"
    )
    env["LANMUX_WEB_PORT"] = web_port

    raw_ui = _resolve_prefixed(
        env, "LANMUX_EXTERNAL_UI", "HUB_EXTERNAL_UI", default=""
    ).strip()
    disable_ui = raw_ui.lower() == "none"
    refresh_assets = _resolve_prefixed(
        env, "LANMUX_REFRESH_ASSETS", "HUB_REFRESH_ASSETS", default=""
    ).strip().lower() in ("1", "true", "yes", "on")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    _tighten_dir_mode(db_path.parent)
    copied = sync_assets(
        assets_dir,
        mihomo_dir,
        include_ui=not disable_ui,
        refresh=refresh_assets,
    )
    if copied:
        _log("provisioned bundled assets into "
             f"{mihomo_dir}: {', '.join(copied)}")

    if disable_ui:
        env["LANMUX_EXTERNAL_UI"] = ""
    elif raw_ui:
        env["LANMUX_EXTERNAL_UI"] = raw_ui
    elif (mihomo_dir / "ui" / "index.html").is_file():
        # Must stay a subpath of mihomo home dir (-d) so mihomo accepts it.
        env["LANMUX_EXTERNAL_UI"] = str(mihomo_dir / "ui")

    raw_ip = _resolve_prefixed(
        env, "LANMUX_LAN_IP", "HUB_LAN_IP", default=""
    ).strip()
    if not raw_ip or raw_ip.lower() == "auto":
        detected = detect_lan_ip()
        env["LANMUX_LAN_IP"] = detected
        _log(
            f"LANMUX_LAN_IP not explicitly set; detected {detected} "
            "(under bridge networking, set LANMUX_LAN_IP to your host LAN IP "
            "or update it in Web UI Settings)"
        )
    else:
        env["LANMUX_LAN_IP"] = raw_ip

    return env


def _terminate_proc(
    proc: subprocess.Popen | None, name: str, timeout: float = 8.0
) -> None:
    if proc is None or proc.poll() is not None:
        return
    _log(f"stopping {name} (pid={proc.pid})...")
    try:
        proc.terminate()
    except OSError:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.1)
    _log(f"{name} did not exit in {timeout:.0f}s; killing")
    try:
        proc.kill()
        proc.wait(timeout=2.0)
    except OSError:
        pass


def web_tls_args(env: Mapping[str, str]) -> list[str]:
    """Optional direct TLS for lanmux-web (M-07, minimal closed loop).

    When both ``LANMUX_SSL_CERTFILE`` and ``LANMUX_SSL_KEYFILE`` are
    set and point at existing files, returns the uvicorn
    ``--ssl-certfile/--ssl-keyfile`` args. Any misconfiguration
    (only one set, file missing) logs a warning and returns [] so the
    panel stays up on plain HTTP instead of failing to start. The
    recommended path is still a reverse proxy (see README); this is
    for operators who already have a certificate and want uvicorn to
    terminate TLS directly. No certificate is ever generated here.
    """
    cert = (env.get("LANMUX_SSL_CERTFILE") or "").strip()
    key = (env.get("LANMUX_SSL_KEYFILE") or "").strip()
    if not cert and not key:
        return []
    if not cert or not key:
        _log(
            "warning: only one of LANMUX_SSL_CERTFILE /"
            " LANMUX_SSL_KEYFILE is set; TLS disabled, staying on HTTP"
        )
        return []
    if not Path(cert).is_file() or not Path(key).is_file():
        _log(
            "warning: TLS cert/key file not found"
            f" ({cert} / {key}); TLS disabled, staying on HTTP"
        )
        return []
    return ["--ssl-certfile", cert, "--ssl-keyfile", key]


def main() -> int:
    # Privilege setup first, while still root if applicable: fix /data
    # ownership, then drop to `lanmux`. Everything below this point —
    # init, mihomo, uvicorn — runs unprivileged. See _ensure_privileges.
    try:
        _ensure_privileges(os.environ)
    except OSError as exc:
        _log(f"privilege setup failed: {exc}")
        return 2

    env = prepare_runtime_env()
    apply_env = _resolve_prefixed(
        env, "LANMUX_APPLY_ENV", "HUB_APPLY_ENV", default=""
    ).strip().lower() in ("1", "true", "yes")
    auto_secrets = _resolve_prefixed(
        env, "LANMUX_AUTO_SECRETS", "HUB_AUTO_SECRETS", default="1"
    ).strip().lower() not in ("0", "false", "no")

    try:
        config_path = init_lanmux(
            env=env, apply_env=apply_env, auto_secrets=auto_secrets
        )
    except DatabaseCorruptError as exc:
        # M-28: unrecoverable corruption must fail fast with an
        # explicit message and a non-zero exit — never spawn children
        # and never crash-loop silently. (The common case never gets
        # here: Database.__init__ restores the newest backup first.)
        # Docker's restart policy may still restart this container;
        # each attempt logs this FATAL line instead of a bare
        # traceback, and the container stays down until an operator
        # restores a backup or replaces the database file.
        _log(f"FATAL: {exc}")
        _log(
            "database is unusable and no backup could restore it; "
            "copy a backup from <db-dir>/backups/ over the database "
            "file (or delete the corrupt file to start fresh) and "
            "restart the container"
        )
        return 2
    except (ValueError, OSError) as exc:
        _log(f"initialization failed: {exc}")
        return 2

    mihomo_dir = config_path.parent
    mihomo_bin = env.get("MIHOMO_BIN") or "/usr/local/bin/mihomo"
    web_port = env.get("LANMUX_WEB_PORT") or "8086"

    mihomo_cmd = [mihomo_bin, "-d", str(mihomo_dir), "-f", str(config_path)]
    web_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "0.0.0.0",
        "--port",
        str(web_port),
    ]
    tls_args = web_tls_args(env)
    if tls_args:
        web_cmd.extend(tls_args)
        _log("TLS enabled for lanmux-web"
             f" (cert {env.get('LANMUX_SSL_CERTFILE')})")

    shutting_down = False

    def _handle_signal(signum: int, _frame: object) -> None:
        nonlocal shutting_down
        if not shutting_down:
            _log(f"received signal {signum}; shutting down")
            shutting_down = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    def _spawn_mihomo() -> tuple[subprocess.Popen, float]:
        _log(f"starting mihomo: {' '.join(mihomo_cmd)}")
        return subprocess.Popen(mihomo_cmd, env=env), time.monotonic()

    mihomo_proc: subprocess.Popen | None = None
    mihomo_started_at = 0.0
    mihomo_restart_at = 0.0
    backoff_idx = 0

    if Path(mihomo_bin).is_file():
        mihomo_proc, mihomo_started_at = _spawn_mihomo()
    else:
        _log(
            f"warning: mihomo binary not found at {mihomo_bin}; "
            "starting web console only"
        )

    _log(f"starting lanmux-web on 0.0.0.0:{web_port}")
    web_proc = subprocess.Popen(web_cmd, env=env)

    exit_code = 0
    try:
        while not shutting_down:
            web_rc = web_proc.poll()
            if web_rc is not None:
                _log(f"lanmux-web exited unexpectedly with code {web_rc}")
                exit_code = web_rc if web_rc != 0 else 1
                break

            if mihomo_proc is not None:
                mh_rc = mihomo_proc.poll()
                if mh_rc is not None:
                    uptime = time.monotonic() - mihomo_started_at
                    if uptime > 30.0:
                        backoff_idx = 0
                    delay = BACKOFF_STEPS[
                        min(backoff_idx, len(BACKOFF_STEPS) - 1)
                    ]
                    backoff_idx += 1
                    _log(
                        f"mihomo exited (code={mh_rc}, uptime={uptime:.1f}s); "
                        f"restarting in {delay:.0f}s (Web UI stays online)"
                    )
                    mihomo_proc = None
                    mihomo_restart_at = time.monotonic() + delay
            elif mihomo_restart_at > 0 and time.monotonic() >= mihomo_restart_at:
                mihomo_restart_at = 0.0
                mihomo_proc, mihomo_started_at = _spawn_mihomo()

            time.sleep(0.5)
    finally:
        _terminate_proc(web_proc, "lanmux-web")
        _terminate_proc(mihomo_proc, "mihomo")

    _log("shutdown complete")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
