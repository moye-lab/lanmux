"""FastAPI dependencies: shared DB / config service / mihomo client.

Routers read everything from ``request.app.state`` (populated by
``create_app`` in :mod:`app.main`). Tests override these dependency
functions via ``app.dependency_overrides`` to inject fakes.

Threading: FastAPI runs sync endpoints in a thread pool while the
SQLite connection is shared, so access is serialized by the
per-method lock inside :class:`app.database.Database` (see its
``_locked`` decorator). :func:`get_db` is deliberately a plain
function, NOT a yield dependency holding a lock: FastAPI may run a
yield dependency's teardown on a different worker thread than its
setup, and releasing a threading RLock from another thread raises
``RuntimeError: cannot release un-acquired lock`` — while the lock
stays acquired forever, hanging every later request (2026-11-24 N1
outage: the login burst poisoned the old request-scoped lock and the
whole panel stopped responding, /health included). Never reintroduce
a lock held across a yield here.
"""

from __future__ import annotations

from fastapi import Depends, Request

from .config_service import ConfigService
from .database import Database
from .mihomo_client import MihomoClient


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_config_service(
    request: Request, db: Database = Depends(get_db)
) -> ConfigService:
    return request.app.state.config_service


def get_mihomo_client(
    request: Request, db: Database = Depends(get_db)
) -> MihomoClient:
    """Build a client from live settings (secret + controller port)."""
    settings = db.get_settings()
    base_url: str = request.app.state.mihomo_base_url
    return MihomoClient(
        base_url=base_url.format(port=settings.controller_port),
        secret=settings.mihomo_secret,
    )


def apply_and_report(
    service: ConfigService,
) -> dict:
    """Run a config apply, returning a ``reload`` report dict.

    The DB change that triggered the apply is already committed, so a
    failed apply is reported (not raised): the panel stays usable when
    mihomo is down, and the live config is never broken because the
    service rolls back before reporting the error.
    """
    from .config_service import ConfigApplyError

    try:
        service.apply()
    except ConfigApplyError as exc:
        report: dict = {
            "ok": False,
            "error": exc.message,
            "stage": exc.stage,
            "rolled_back": exc.rolled_back,
            "restart_required": exc.restart_required,
        }
        if exc.restart_required:
            report["restart_reason"] = exc.restart_reason
        return report
    return {
        "ok": True,
        "error": None,
        "stage": None,
        "rolled_back": False,
        "restart_required": False,
    }
