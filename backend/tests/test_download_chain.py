"""Download-chain integrity tests (H-13 + M-47 + PR-34 + PR-40).

Pins the SHA256 manifest (``scripts/asset-checksums.sha256``), the
mandatory ``sha256sum -c`` calls in ``install.sh`` / ``Dockerfile``,
the digest-pinned base images, and the fail-closed behaviour of the
verification helpers: a tampered file must abort, never install.

The functional tests extract the real helper functions out of
``install.sh`` (``lookup_sha256`` / ``verify_sha256`` /
``verify_existing_sha256`` plus the tiny ``log_*`` / ``die`` helpers)
and run them in bash against files in a temp dir — no network, no
real install. Extracting instead of copying keeps the test honest:
if the function is edited in install.sh, the test exercises the
edited code.
"""

import hashlib
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "install.sh"
MANIFEST = REPO_ROOT / "scripts" / "asset-checksums.sha256"
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
README = REPO_ROOT / "README.md"

# Hashes verified 2026-11-26: each asset downloaded from the official
# GitHub release, hashed, and cross-checked against a second independent
# mirror (gh-proxy.com vs ghproxy.net); the three geodata hashes also
# match the upstream-published ``*.sha256sum`` files byte for byte.
# These values are the same strings recorded in the manifest — the test
# pins them so a silent manifest edit fails loudly.
EXPECTED_HASHES = {
    "mihomo-linux-amd64-v1.19.34.gz": (
        "223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc"
    ),
    "mihomo-linux-arm64-v1.19.34.gz": (
        "daaf78a6240a282cdfd75bcbf98fe321f6bd52765cc29e79f344191198f0b50f"
    ),
    "compressed-dist.tgz": (
        "8ed5b1e312136a161eb7bbbfc2c4d7dc95217487d0873739668d897ed366af9c"
    ),
    "geoip.dat": (
        "9dc8e7de8db8300ce27b606f4a30632265713d2f33bcc568c0d2c44c825c8687"
    ),
    "geosite.dat": (
        "ae35a23f40a8e0486f0ed1723780ba6805a9f917a51ff30441eb2c41f688244c"
    ),
    "country.mmdb": (
        "6c3ca78dadf2477261ea6addf632682bcfc1ab5924bb4c30eb28c37c828e3373"
    ),
}

MIHOMO_IMAGE_DIGEST = (
    "sha256:4c2495d705f152897a58eac410350f243835fd01ce2fe44949a571faa824d532"
)
ALPINE_DIGEST = (
    "sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _parse_manifest():
    entries = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        digest, _, name = line.partition("  ")
        entries[name] = digest
    return entries


# ---------------------------------------------------------------- manifest
def test_manifest_exists_and_has_all_six_assets():
    assert MANIFEST.is_file()
    entries = _parse_manifest()
    assert set(entries) == set(EXPECTED_HASHES)


def test_manifest_hashes_are_64_hex_and_match_verified_values():
    for name, digest in _parse_manifest().items():
        assert _HEX64.match(digest), f"{name}: not 64 hex: {digest!r}"
        assert digest == EXPECTED_HASHES[name], f"{name}: hash drifted"


def test_manifest_records_geodata_snapshot_date():
    text = MANIFEST.read_text(encoding="utf-8")
    assert "geodata-release-date: 2026-11-26T04:16:13Z" in text
    assert "latest" in text  # honest note: upstream has no dated tag


# ---------------------------------------------------------------- install.sh
def _function_body(source: str, name: str) -> str:
    """Return the body of ``name()`` in a bash source file."""
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start)
    return source[start:end]


def test_install_sh_verifies_all_three_assets():
    source = INSTALL_SH.read_text(encoding="utf-8")
    assert "sha256sum -c" in source
    assert "/checksums.txt" not in source  # upstream file 404s; never fetch it
    for fn in ("install_mihomo", "install_metacubexd", "install_geodata"):
        body = _function_body(source, fn)
        assert "verify_sha256" in body, f"{fn} does not call verify_sha256"


def test_install_geodata_rejects_damaged_existing_file():
    # PR-34: a pre-existing geodata file must be hash-checked, not
    # skipped on size alone.
    source = INSTALL_SH.read_text(encoding="utf-8")
    body = _function_body(source, "install_geodata")
    assert "verify_existing_sha256" in body
    assert "stat -c %s" not in body  # no size-only skip left
    assert "跳过：" not in body


def test_install_sh_downloads_direct_first():
    source = INSTALL_SH.read_text(encoding="utf-8")
    assert 'for prefix in "" "$@"' in source
    assert "DEFAULT_MIRRORS=" in source


def test_install_sh_documents_mirror_risk():
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "第三方" in text and "传输加速" in text


# ---------------------------------------------------------------- Dockerfile
def test_dockerfile_pins_base_image_digests():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert f"metacubex/mihomo:v1.19.34@{MIHOMO_IMAGE_DIGEST}" in text
    # Alpine 3.24.4 (supply-chain cluster, M-48): 3.20 went EOL
    # 2026-04-01; the digest is the multi-arch index digest, verified
    # with crane by that cluster.
    assert f"alpine:3.24.4@{ALPINE_DIGEST}" in text


def test_dockerfile_verifies_downloads_against_manifest():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY scripts/asset-checksums.sha256" in text
    assert "sha256sum -c" in text
    for name in ("geoip.dat", "geosite.dat", "country.mmdb",
                 "compressed-dist.tgz"):
        assert name in text, f"Dockerfile does not verify {name}"


def test_dockerfile_records_geodata_snapshot_in_labels():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert 'org.lanmux.geodata-release-date="2026-11-26T04:16:13Z"' in text
    assert 'org.lanmux.geodata-release-tag="latest"' in text


def test_dockerignore_re_includes_checksum_manifest():
    # .dockerignore excludes scripts/; the manifest must be explicitly
    # re-included or the Dockerfile COPY silently breaks the build.
    assert "!scripts/asset-checksums.sha256" in DOCKERIGNORE.read_text(
        encoding="utf-8"
    )


def test_readme_documents_hash_checks_and_mirror_risk():
    text = README.read_text(encoding="utf-8")
    assert "asset-checksums.sha256" in text
    assert "SHA256" in text
    assert "gh-proxy.com" in text


# ------------------------------------------------------- functional: tamper
def _extract_helpers() -> str:
    """Extract the verification helpers + log/die from install.sh."""
    source = INSTALL_SH.read_text(encoding="utf-8")
    names = (
        "log_info",
        "log_ok",
        "log_warn",
        "die",
        "lookup_sha256",
        "verify_sha256",
        "verify_existing_sha256",
    )
    chunks = []
    for name in names:
        start = source.index(f"{name}() {{")
        rest = source[start:]
        if rest.startswith(f"{name}() {{ ") and "}\n" in rest.split("\n", 1)[0]:
            chunks.append(rest.split("\n", 1)[0])  # one-liner helper
        else:
            end = rest.index("\n}\n")
            chunks.append(rest[: end + len("\n}")])
    return "\n\n".join(chunks)


def _run_bash(script: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _harness(tmp_path: Path, manifest: Path) -> str:
    """Bash prelude: helpers + manifest location + temp workdir."""
    helpers = _extract_helpers()
    return (
        "set -u\n"
        f"SCRIPT_DIR={REPO_ROOT}\n"
        f"ASSET_CHECKSUMS={manifest}\n"
        f"WORK={tmp_path}\n"
        f"{helpers}\n"
    )


def _write_manifest(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """Build a throwaway manifest for small test files we control."""
    manifest = tmp_path / "test-checksums.sha256"
    lines = []
    for name, content in files.items():
        (tmp_path / name).write_bytes(content)
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def test_verify_sha256_accepts_good_file_and_rejects_tampered(tmp_path):
    good = b"lanmux-download-chain-test-payload"
    manifest = _write_manifest(tmp_path, {"good.bin": good})
    prelude = _harness(tmp_path, manifest)
    good_file = tmp_path / "good.bin"
    tampered = tmp_path / "tampered.bin"
    tampered.write_bytes(b"lanmux-download-chain-test-payload!")
    script = textwrap.dedent(f"""\
        {prelude}
        ( verify_sha256 "{good_file}" "good.bin" "test asset" )
        echo "good_rc=$?"
        ( verify_sha256 "{tampered}" "good.bin" "test asset" )
        echo "tampered_rc=$?"
        test -f "{tampered}" && echo "tampered_still_there" || echo "tampered_removed"
        """)
    result = _run_bash(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "good_rc=0" in result.stdout
    assert "SHA256 校验通过" in result.stdout
    # Tampered file: verification must fail AND the file must be deleted.
    assert "tampered_rc=1" in result.stdout
    assert "tampered_removed" in result.stdout
    assert "SHA256 校验失败" in result.stdout + result.stderr


def test_verify_existing_sha256_drives_redownload_on_damage(tmp_path):
    good = b"geodata-stand-in"
    manifest = _write_manifest(tmp_path, {"geoip.dat": good})
    prelude = _harness(tmp_path, manifest)
    damaged = tmp_path / "GeoIP.dat"
    damaged.write_bytes(b"geodata-stand-in-corrupted")
    intact = tmp_path / "GeoSite.dat"
    intact.write_bytes(good)
    script = textwrap.dedent(f"""\
        {prelude}
        if verify_existing_sha256 "{damaged}" "geoip.dat" "geodata geoip.dat"; then
          echo "damaged_rc=0"
        else
          echo "damaged_rc=1"
        fi
        # Same bytes under the geoip.dat manifest name must pass.
        cp "{tmp_path}/geoip.dat" "{tmp_path}/GeoIP2.dat"
        if verify_existing_sha256 "{tmp_path}/GeoIP2.dat" "geoip.dat" "geodata geoip.dat"; then
          echo "intact_rc=0"
        else
          echo "intact_rc=1"
        fi
        """)
    result = _run_bash(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "damaged_rc=1" in result.stdout  # PR-34: damaged -> re-download
    assert "intact_rc=0" in result.stdout


def test_lookup_sha256_is_fail_closed(tmp_path):
    good = b"fail-closed-probe"
    manifest = _write_manifest(tmp_path, {"good.bin": good})
    prelude = _harness(tmp_path, manifest)
    script = textwrap.dedent(f"""\
        {prelude}
        echo "known=$(lookup_sha256 good.bin)"
        ( lookup_sha256 "no-such-asset.bin" )
        echo "unknown_rc=$?"
        ASSET_CHECKSUMS="{tmp_path}/missing.sha256"
        ( lookup_sha256 "good.bin" )
        echo "missing_manifest_rc=$?"
        """)
    result = _run_bash(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"known={hashlib.sha256(good).hexdigest()}" in result.stdout
    assert "unknown_rc=1" in result.stdout  # unpinned version -> refuse
    assert "missing_manifest_rc=1" in result.stdout  # no manifest -> refuse


def test_real_manifest_lookup_returns_verified_hashes():
    """The real manifest answers the real asset names correctly."""
    prelude = _harness(Path("/tmp"), MANIFEST)
    script = (
        prelude
        + 'echo "amd64=$(lookup_sha256 mihomo-linux-amd64-v1.19.34.gz)"\n'
        + 'echo "ui=$(lookup_sha256 compressed-dist.tgz)"\n'
        + 'echo "geo=$(lookup_sha256 geoip.dat)"\n'
    )
    result = _run_bash(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (
        f"amd64={EXPECTED_HASHES['mihomo-linux-amd64-v1.19.34.gz']}"
        in result.stdout
    )
    assert f"ui={EXPECTED_HASHES['compressed-dist.tgz']}" in result.stdout
    assert f"geo={EXPECTED_HASHES['geoip.dat']}" in result.stdout
