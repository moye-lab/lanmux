"""Container readiness/health check for the LanMux All-in-One image.

Docker's HEALTHCHECK must not merely prove that FastAPI is alive: the
container also owns the Mihomo data plane.  This script checks both
process-facing HTTP endpoints without importing the FastAPI application,
so a broken Web process or a dead Mihomo controller makes the container
unhealthy.

Exit codes:
  0 = Web + Mihomo are reachable
  1 = one or both checks failed
"""
from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

for _candidate in (
    Path(__file__).resolve().parent / "backend",
    Path(__file__).resolve().parent.parent,
):
    if (_candidate / "app" / "__init__.py").is_file():
        sys.path.insert(0, str(_candidate))
        break

from app.database import Database

WEB_TIMEOUT = 3.0
MIHOMO_TIMEOUT = 3.0


def _get(url: str, headers: dict[str, str] | None = None) -> bool:
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=WEB_TIMEOUT) as response:
            return 200 <= response.status < 300
    except (OSError, urllib.error.URLError):
        return False


def _mihomo_secret() -> str:
    # LANMUX_* wins, then the pre-v1.0.0 FENLIU_* name, then the
    # Docker-era HUB_* name; the default is the new /data/lanmux.db,
    # with /data/hub.db as a fallback for unmigrated Docker volumes.
    db_path = Path(
        os.environ.get("LANMUX_DB_PATH")
        or os.environ.get("FENLIU_DB_PATH")
        or os.environ.get("HUB_DB_PATH")
        or "/data/lanmux.db"
    )
    if not db_path.is_file() and db_path.name == "lanmux.db":
        legacy = db_path.with_name("hub.db")
        if legacy.is_file():
            db_path = legacy
    db = Database(db_path)
    try:
        return db.get_setting("mihomo_secret") or ""
    finally:
        db.close()


def main() -> int:
    web_port = os.environ.get("LANMUX_WEB_PORT") or os.environ.get("HUB_WEB_PORT") or "8086"
    controller_port = os.environ.get("LANMUX_CONTROLLER_PORT") or os.environ.get("HUB_CONTROLLER_PORT") or "9090"
    base = os.environ.get("MIHOMO_BASE_URL", "http://127.0.0.1:{port}")

    web_ok = _get(f"http://127.0.0.1:{web_port}/health")

    secret = _mihomo_secret()
    controller = base.format(port=controller_port).rstrip("/")
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    mihomo_ok = _get(f"{controller}/version", headers)

    if web_ok and mihomo_ok:
        print("healthy: web=ok mihomo=ok")
        return 0

    print(
        f"unhealthy: web={'ok' if web_ok else 'down'} "
        f"mihomo={'ok' if mihomo_ok else 'down'}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
