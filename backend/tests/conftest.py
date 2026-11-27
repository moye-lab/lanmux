"""Make ``app.*`` importable from the backend/ directory.

Also redirect the module-level app's default paths: importing
``app.main`` builds a module-level ``app`` (for uvicorn), which would
otherwise create the real ``data/lanmux.db`` during test collection.
Tests that need an app build their own via ``create_app`` with tmp
paths; these env defaults only guard the import-time side effect.
``ADMIN_PASSWORD`` is removed so admin seeding is fully explicit in
tests.
"""

import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "LANMUX_DB_PATH", "/tmp/lanmux-unified-pytest/lanmux.db"
)
os.environ.setdefault(
    "LANMUX_CONFIG_PATH", "/tmp/lanmux-unified-pytest/config.yaml"
)
os.environ.pop("ADMIN_PASSWORD", None)
