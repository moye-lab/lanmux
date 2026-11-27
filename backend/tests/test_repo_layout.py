"""Repository layout regression tests (v0.9.9, extended in v1.0.0).

The v0.9.7 merge accidentally dropped ``systemd/`` (the Docker repo
had deleted its own obsolete units), and v0.9.8's installer failed at
the unit step with a bare ``sed: can't read`` error. These tests pin
the templates' existence and their key contents so a future merge
cannot silently lose them again.

The v1.0.0 rename added a second job: no pre-v1.0.0 unit template or
seed-helper module may survive under its old name.
"""

import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SYSTEMD_DIR = REPO_ROOT / "systemd"
VENDOR_DIR = REPO_ROOT / "frontend" / "vendor"

# Full 64-hex sha256 of the vendored frontend assets (audit L-42).
# Recorded in full in frontend/vendor/README.md; a replaced/tampered vendor
# file fails here. Recompute with `sha256sum frontend/vendor/*` when a
# vendor file is legitimately upgraded, and update README.md in the same
# change. tailwind.css is the Tailwind CLI build output (audit L-41),
# compiled from frontend/index.html with tailwind.config.js.
VENDOR_SHA256 = {
    "alpine.min.js": "b600e363d99d95444db54acbfb2deffec9ae792aa99a09229bcda078e5b55643",
    "tailwind.css": "99d295c297cb5229fe01d1b43f7b59a470121d52b8c66bdc1fab67ca854060de",
}


def test_systemd_unit_templates_exist():
    assert (SYSTEMD_DIR / "lanmux-mihomo.service").is_file()
    assert (SYSTEMD_DIR / "lanmux-web.service").is_file()


def test_systemd_unit_templates_content():
    mihomo = (SYSTEMD_DIR / "lanmux-mihomo.service").read_text(encoding="utf-8")
    assert "ExecStart=/opt/lanmux/bin/mihomo -d /etc/lanmux" in mihomo
    for line in mihomo.splitlines():
        if line.startswith("ExecStart="):
            assert "/etc/mihomo" not in line  # never point at the old gateway
    web = (SYSTEMD_DIR / "lanmux-web.service").read_text(encoding="utf-8")
    assert "EnvironmentFile=/etc/lanmux/lanmux.env" in web
    assert "${LANMUX_WEB_PORT}" in web
    assert "uvicorn app.main:app" in web


def test_no_pre_v1_unit_templates_remain():
    # The v1.0.0 rename must leave no fenliu-* unit template behind:
    # install.sh installs exactly the two lanmux-* templates.
    leftovers = sorted(p.name for p in SYSTEMD_DIR.glob("fenliu-*.service"))
    assert leftovers == []


def test_seed_helper_module_renamed():
    app_dir = REPO_ROOT / "backend" / "app"
    assert (app_dir / "init_lanmux.py").is_file()
    assert not (app_dir / "init_fenliu.py").exists()


def test_vendor_file_hashes_match_record():
    # Audit L-42: the README used to record only the first 16 hex chars of
    # each sha256. The full digests below are the tamper-evidence record;
    # update them (and README.md) only when a vendor file is upgraded.
    for name, expected in VENDOR_SHA256.items():
        path = VENDOR_DIR / name
        assert path.is_file(), f"missing vendored file: {name}"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


def test_tailwind_play_cdn_is_gone():
    # Audit L-41: the Play CDN script (browser-side JIT, dev-only per
    # upstream) must not come back; the panel loads compiled static CSS.
    assert not (VENDOR_DIR / "tailwind.js").exists()
    index = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert "/vendor/tailwind.css" in index
    assert "/vendor/tailwind.js" not in index
    assert "cdn.tailwindcss.com" not in index


def test_dependency_lockfiles_exist_and_pin():
    # Audit M-45: the hashed lockfiles are the install inputs; the .txt
    # files are floor manifests only. A lockfile without hashes is not a
    # lockfile. Floors (not exact versions) are asserted so Dependabot
    # bumps do not break this test.
    import re

    def pinned(text, name):
        m = re.search(rf"^{re.escape(name)}==([0-9][0-9a-zA-Z.]*)\s*\\\\?$", text, re.M)
        assert m, f"{name} not pinned in lockfile"
        return tuple(int(p) for p in m.group(1).split(".") if p.isdigit())

    for lock in ("requirements-prod.lock", "requirements.lock"):
        text = (REPO_ROOT / "backend" / lock).read_text(encoding="utf-8")
        assert "--hash=sha256:" in text
    prod = (REPO_ROOT / "backend" / "requirements-prod.lock").read_text(
        encoding="utf-8"
    )
    dev = (REPO_ROOT / "backend" / "requirements.lock").read_text(encoding="utf-8")
    assert pinned(prod, "fastapi") >= (0, 115, 13)
    assert pinned(prod, "pydantic") >= (2, 4, 0)
    assert pinned(prod, "starlette") >= (0, 40, 0)
    assert pinned(dev, "pytest") >= (9, 0, 3)
    # Prod and dev lockfiles must agree on the shared runtime pins.
    assert pinned(dev, "fastapi") == pinned(prod, "fastapi")
    assert pinned(dev, "starlette") == pinned(prod, "starlette")
    assert (REPO_ROOT / "backend" / "constraints.txt").is_file()
    assert "starlette>=0.40.0" in (
        REPO_ROOT / "backend" / "constraints.txt"
    ).read_text(encoding="utf-8")
