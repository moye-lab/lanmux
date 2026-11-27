"""FastAPI entrypoint (Phase 2).

``create_app`` wires the routers, the SQLite database, the config
service and the token store. Paths and the mihomo base URL are
configurable via environment (defaults assume the backend runs from
the repo root, as the later installer will):

* ``LANMUX_DB_PATH`` — SQLite file (default ``./data/lanmux.db``);
  ``FENLIU_DB_PATH`` and ``HUB_DB_PATH`` are accepted as legacy
  aliases, in that priority order
* ``LANMUX_CONFIG_PATH`` — generated config.yaml
  (default ``./data/mihomo/config.yaml``); ``FENLIU_CONFIG_PATH``
  and ``HUB_CONFIG_PATH`` are legacy aliases
* ``MIHOMO_BASE_URL`` — controller base URL; may contain ``{port}``,
  filled from settings at request time
  (default ``http://127.0.0.1:{port}``)
* ``ADMIN_PASSWORD`` — seeded as the admin password on first init
  (see :mod:`app.auth`)
* ``LANMUX_SETUP_LOOPBACK_ONLY`` — set to ``1`` to restrict first-run
  setup to loopback clients (default off; Docker users set up from a
  LAN browser — see ``app.routers.auth`` and the README)
* ``LANMUX_VERSION`` / ``LANMUX_COMMIT`` / ``LANMUX_BUILD_TIME`` —
  build-time version stamp (defaults ``1.0.2`` / ``unknown`` /
  ``unknown``); baked into the image by the Dockerfile build args
  and reported by ``GET /health`` and ``GET /api/version``.

All ``/api/*`` routes require a bearer token except ``/health``,
``/api/auth/login`` and ``/api/auth/status``. No CORS is configured:
the frontend is served same-origin from this app.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse

from .auth import (
    TokenStore,
    ensure_admin_password,
    generate_setup_token,
    require_auth,
)
from .config_service import ConfigService
from .database import Database
from .deps import get_mihomo_client
from .mihomo_client import MihomoClient, MihomoError
from .routers import auth as auth_router
from .routers import diagnostics as diagnostics_router
from .routers import nodes as nodes_router
from .routers import rules as rules_router
from .routers import settings as settings_router

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = REPO_ROOT / "data" / "lanmux.db"
DEFAULT_CONFIG_PATH = REPO_ROOT / "data" / "mihomo" / "config.yaml"
DEFAULT_MIHOMO_BASE_URL = "http://127.0.0.1:{port}"
FRONTEND_DIR = REPO_ROOT / "frontend"


def _version_info() -> dict:
    """Build-time version stamp, read from the environment per call.

    Read per request (not at import time) so the values always reflect
    the container's runtime environment, and so tests can override
    them with ``monkeypatch.setenv`` after the app is built.
    """
    return {
        "version": os.environ.get("LANMUX_VERSION") or "1.0.2",
        "commit": os.environ.get("LANMUX_COMMIT") or "unknown",
        "build_time": os.environ.get("LANMUX_BUILD_TIME") or "unknown",
    }


def create_app(
    db_path: str | Path | None = None,
    config_path: str | Path | None = None,
    mihomo_base_url: str | None = None,
) -> FastAPI:
    """Build the app. Tests pass tmp paths; production uses env/defaults."""
    db_path = Path(
        db_path
        or os.environ.get("LANMUX_DB_PATH")
        or os.environ.get("FENLIU_DB_PATH")
        or os.environ.get("HUB_DB_PATH")
        or DEFAULT_DB_PATH
    )
    config_path = Path(
        config_path
        or os.environ.get("LANMUX_CONFIG_PATH")
        or os.environ.get("FENLIU_CONFIG_PATH")
        or os.environ.get("HUB_CONFIG_PATH")
        or DEFAULT_CONFIG_PATH
    )
    base_url = (
        mihomo_base_url
        or os.environ.get("MIHOMO_BASE_URL")
        or DEFAULT_MIHOMO_BASE_URL
    )

    db = Database(db_path)
    admin_ready = ensure_admin_password(db)

    # H-02: first run with no admin password — generate a one-time
    # setup token and print it prominently in the startup log (the
    # installer cannot know it in advance, so the log is the channel).
    # It lives only in memory (app.state.setup_token) and is discarded
    # the moment setup succeeds. When an admin already exists, no
    # token is generated and setup stays permanently disabled.
    setup_token: str | None = None
    if not admin_ready:
        setup_token = generate_setup_token()
        banner = (
            "\n============================================================\n"
            "LanMux 首次启动：尚未设置管理员密码\n"
            f"Setup token（一次性，仅本次启动有效）: {setup_token}\n"
            "在面板设置向导中输入该 token 才能创建管理员密码。\n"
            "查看方式：Docker: docker logs lanmux（或 docker compose logs）；\n"
            "systemd: journalctl -u lanmux-web | grep -i 'setup token'\n"
            "setup 完成后该 token 立即失效。\n"
            "============================================================"
        )
        print(banner, flush=True)

    def client_factory() -> MihomoClient:
        settings = db.get_settings()
        return MihomoClient(
            base_url=base_url.format(port=settings.controller_port),
            secret=settings.mihomo_secret,
        )

    config_service = ConfigService(db, config_path, client_factory)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        db.close()

    app = FastAPI(title="LanMux", version="1.0.2", lifespan=lifespan)
    app.state.db = db
    app.state.config_service = config_service
    app.state.token_store = TokenStore()
    app.state.setup_token = setup_token
    app.state.mihomo_base_url = base_url

    # M-03: security headers on every response.
    # CSP is deliberately Alpine-compatible: the panel is a single file
    # with inline scripts and Alpine directives, so script-src needs
    # 'unsafe-inline' + 'unsafe-eval' and style-src 'unsafe-inline'
    # (a strict default-src 'self' policy would break the panel — see
    # the jsdom suite, which runs the real page). The token lives in
    # an HttpOnly cookie, so CSP here is defense-in-depth, not the
    # only layer. HSTS is intentionally absent: it is only honored
    # over HTTPS and this panel normally runs over plain HTTP on the
    # LAN (see the README TLS / reverse-proxy section, M-07).
    _CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )

    @app.middleware("http")
    async def _security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            # API responses must never sit in a shared cache (M-03).
            response.headers["Cache-Control"] = "no-store"
        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/html"):
            response.headers["Content-Security-Policy"] = _CSP
        return response

    @app.get("/health")
    def health() -> dict:
        # Unauthenticated and polled every 15s by healthcheck.py: keep
        # it cheap — version fields only, never touch the controller.
        return {"status": "ok", "phase": 4, **_version_info()}

    @app.get("/api/version")
    def version(
        _token: str = Depends(require_auth),
        client: MihomoClient = Depends(get_mihomo_client),
    ) -> dict:
        """Authenticated version report, including live mihomo version.

        A down controller degrades to ``mihomo_version: null`` plus an
        ``error`` field — never a 500.
        """
        info = _version_info()
        try:
            mihomo_version = client.get_version().get("version")
        except MihomoError as exc:
            return {**info, "mihomo_version": None, "error": exc.message}
        except Exception as exc:  # defensive: never 500 on this endpoint
            return {**info, "mihomo_version": None, "error": str(exc)}
        return {**info, "mihomo_version": mihomo_version}

    app.include_router(auth_router.router)
    app.include_router(nodes_router.router)
    app.include_router(rules_router.router)
    app.include_router(settings_router.router)
    app.include_router(diagnostics_router.router)

    # Static frontend last: /api/* and /health must win over files.
    # The catch-all is the SPA fallback: some proxies/relays in the
    # user's network path percent-encode the '#' of a tab URL on
    # refresh (/#routing arrives as /%23routing), and any unknown path
    # would otherwise 404 as JSON. Unknown non-API paths serve the
    # panel; the frontend recovers the tab from the pathname
    # (see applyHash). Unknown /api/* paths still 404 as JSON.
    if FRONTEND_DIR.is_dir():
        index_file = FRONTEND_DIR / "index.html"

        @app.get("/", response_class=FileResponse)
        def serve_index() -> FileResponse:
            return FileResponse(index_file)

        @app.get("/{path:path}", response_class=FileResponse)
        def serve_spa_fallback(path: str) -> FileResponse:
            if path == "api" or path.startswith("api/"):
                raise HTTPException(status_code=404, detail="Not Found")
            candidate = (FRONTEND_DIR / path).resolve()
            if (
                candidate.is_file()
                and candidate.is_relative_to(FRONTEND_DIR.resolve())
            ):
                return FileResponse(candidate)
            return FileResponse(index_file)
    return app


app = create_app()
