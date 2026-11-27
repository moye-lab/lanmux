"""File-permission convergence: M-08 (DB / data dir), L-24 (install-time
lanmux.env — covered by the /tmp shell test, see the fix report),
PR-11 (no backup/export flow sweeps sensitive files into an archive).

Scope note: config.yaml / config.yaml.bak write-time 0600 is owned by
the "config apply" cluster (atomic write in config_service.py) and is
deliberately NOT asserted here; this module covers the DB side, the
data directories, and the PR-11 no-backup-flow invariant.
"""

import os
import stat
from pathlib import Path

from app.database import DATA_DIR_MODE, Database, _converge_mode, _ensure_private_db_file
from app.docker_runner import prepare_runtime_env, sync_assets

REPO_ROOT = Path(__file__).resolve().parents[2]


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# -- M-08: DB file -----------------------------------------------------

def test_new_db_created_0600_under_umask_022(tmp_path):
    old_umask = os.umask(0o022)
    try:
        db = Database(tmp_path / "data" / "lanmux.db")
    finally:
        os.umask(old_umask)
    try:
        assert _mode(tmp_path / "data" / "lanmux.db") == 0o600
        assert _mode(tmp_path / "data") == 0o700
    finally:
        db.close()


def test_existing_0644_db_converged_to_0600_on_startup(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    os.chmod(data_dir, 0o755)
    db_file = data_dir / "lanmux.db"
    db_file.touch()
    os.chmod(db_file, 0o644)
    db = Database(db_file)
    try:
        assert _mode(db_file) == 0o600
        assert _mode(data_dir) == 0o700
        # The converged DB must still work (content untouched).
        node_id = db.add_node("N", "ss://x@example.com:8388", {"type": "ss"})
        assert db.get_node(node_id)["name"] == "N"
    finally:
        db.close()


def test_existing_0755_data_dir_converged_to_0700(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    os.chmod(data_dir, 0o755)
    db = Database(data_dir / "lanmux.db")
    try:
        assert _mode(data_dir) == 0o700
    finally:
        db.close()


def test_converge_mode_never_loosens(tmp_path):
    # A 0400 file is stricter than 0600: convergence must not loosen
    # it back (only bits outside the target are removed).
    from app.database import _converge_mode

    f = tmp_path / "f"
    f.write_bytes(b"x")
    os.chmod(f, 0o400)
    _converge_mode(f, 0o600)
    assert _mode(f) == 0o400
    os.chmod(f, 0o644)
    _converge_mode(f, 0o600)
    assert _mode(f) == 0o600


def test_stricter_data_dir_is_not_loosened(tmp_path):
    # NOTE: this test deliberately does NOT open a Database on the
    # read-only dir. A WAL-mode database cannot work in a directory
    # without write permission (SQLite needs to create/access -wal /
    # -shm files), so opening one there fails with "attempt to write a
    # readonly database" on a non-root user (root bypasses the check,
    # which is why this passed locally but failed in CI). The
    # behaviour under test is the permission convergence itself, so
    # exercise _ensure_private_db_file / _converge_mode directly.
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    os.chmod(data_dir, 0o700)
    db_path = data_dir / "lanmux.db"
    _ensure_private_db_file(db_path)
    assert _mode(db_path) == 0o600
    os.chmod(data_dir, 0o500)
    try:
        # A restart's ensure step must not loosen the stricter dir.
        _ensure_private_db_file(db_path)
        assert _mode(data_dir) == 0o500
        # Direct convergence must not loosen it either.
        _converge_mode(data_dir, DATA_DIR_MODE)
        assert _mode(data_dir) == 0o500
        _converge_mode(db_path, 0o600)
        assert _mode(db_path) == 0o600
    finally:
        os.chmod(data_dir, 0o700)


# -- M-08: Docker runtime dirs ------------------------------------------

def test_sync_assets_makes_mihomo_dir_0700(tmp_path):
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "GeoIP.dat").write_bytes(b"x")
    mihomo_dir = tmp_path / "data" / "mihomo"
    sync_assets(assets, mihomo_dir, include_ui=False)
    assert _mode(mihomo_dir) == 0o700


def test_prepare_runtime_env_makes_db_parent_0700(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    os.chmod(data_dir, 0o755)
    prepare_runtime_env(
        {
            "LANMUX_DB_PATH": str(data_dir / "lanmux.db"),
            "LANMUX_CONFIG_PATH": str(data_dir / "mihomo" / "config.yaml"),
            "LANMUX_ASSETS_DIR": str(tmp_path / "assets"),
        }
    )
    assert _mode(data_dir) == 0o700
    assert _mode(data_dir / "mihomo") == 0o700


# -- PR-11: no backup/export flow may sweep sensitive files -----------

def test_no_code_path_archives_the_data_dir():
    """No in-repo code creates an archive from the data directory.

    The repo has no backup endpoint and no tar/zip of DATA_DIR: the
    only copy flows are docker_runner.sync_assets (public geodata/UI
    *into* the data dir) and install.sh `cp -r` of program code. If
    a backup feature is ever added, this test must be updated to
    assert .bak / lanmux.env / plaintext-DB exclusion — it must not
    be silently bypassed by a new archiving call.
    """
    hits = []
    for path in list(REPO_ROOT.rglob("*.py")) + list(REPO_ROOT.rglob("*.sh")):
        if "tests" in path.parts or ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in ("make_archive", "tar -c", "tar -cz", "zip -r"):
            if needle in text:
                hits.append(f"{path.relative_to(REPO_ROOT)}: {needle}")
    assert hits == []


def test_backup_guidance_excludes_sensitive_files():
    """README backup rules (PR-11): .bak and lanmux.env stay out of
    any backup/packaging product, and a DB backup must itself be 0600.
    """
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "config.yaml.bak" in readme
    assert "lanmux.env" in readme
    assert "不应进入任何备份/打包产物" in readme
    assert "0600" in readme
