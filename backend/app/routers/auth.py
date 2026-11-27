"""Auth routes: login / logout / status / setup.

``/api/auth/login``, ``/api/auth/status`` and ``/api/auth/setup`` are
public (everything else under ``/api/*`` requires a token).

Login verifies the password against the stored PBKDF2 hash and issues
a 24h token. Failed logins are counted per IP and per account in the
DB; 5 failures lock logins out for 15 minutes (doubling on each
further lock, capped at 120m) and answer 429 (H-01). Failure responses
never distinguish "unknown account" from "wrong password", and failure
logs record only the account label and IP — never the password.

Setup (Phase 3) sets the admin password on a first run where no
password is configured. It requires the one-time setup token printed
in the startup log (H-02); once a password exists it refuses with 403
forever, and the token is discarded on success. Setup is atomic
(single locked check-and-set), so concurrent setups create exactly
one admin. ``LANMUX_SETUP_LOOPBACK_ONLY=1`` optionally restricts setup
to loopback clients (D-04; default off — Docker users run setup from
a LAN browser, and the default-on setting would block normal setup).

Sessions use an ``HttpOnly`` + ``SameSite=Strict`` cookie
(``lanmux_token``); the token is still returned in the JSON body and
``Authorization: Bearer`` still works, for API clients (M-03).
``POST /api/auth/logout-all`` revokes every token (M-04).
``GET /api/auth/session-info`` reports the last login IP/time for the
panel's session section (L-02).
"""

from __future__ import annotations

import hmac
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ..auth import (
    COOKIE_NAME,
    TOKEN_TTL_SECONDS,
    TokenStore,
    clear_login_lockouts,
    client_ip,
    get_login_info,
    hash_password,
    is_loopback_host,
    login_locked_until,
    record_login_failure,
    record_successful_login,
    require_auth,
    verify_password,
)
from ..database import Database
from ..deps import get_db
from ..models import LoginRequest, LoginResponse, SetupRequest

logger = logging.getLogger("lanmux.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])

MIN_SETUP_PASSWORD_LENGTH = 8


def _setup_loopback_only() -> bool:
    """D-04 switch: ``LANMUX_SETUP_LOOPBACK_ONLY=1`` restricts setup
    to loopback clients. Default off (see module docstring). Read per
    request so the switch can change without a restart."""
    return os.environ.get(
        "LANMUX_SETUP_LOOPBACK_ONLY", ""
    ).strip().lower() in ("1", "true", "yes", "on")


def _set_auth_cookie(response: Response, request: Request, token: str) -> None:
    """Set the HttpOnly session cookie (M-03).

    ``Secure`` only on HTTPS — the panel normally runs over plain HTTP
    on the LAN, and a Secure cookie would never be sent there. The
    cookie is scoped to ``/api`` (the only path that needs it).
    """
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=TOKEN_TTL_SECONDS,
        httponly=True,
        samesite="strict",
        path="/api",
        secure=request.url.scheme == "https",
    )


def _clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/api")


@router.get("/status")
def auth_status(db: Database = Depends(get_db)) -> dict:
    """Public: is an admin password configured?"""
    configured = bool(db.get_setting("admin_password_hash"))
    return {
        "admin_configured": configured,
        "setup_token_required": not configured,
        "hint": (
            None
            if configured
            else "no admin password set — set one on the setup screen"
            " with the one-time setup token from the startup log"
            " (docker logs / journalctl -u lanmux-web),"
            " or start the backend with ADMIN_PASSWORD set"
        ),
    }


@router.get("/session-info")
def session_info(
    request: Request,
    db: Database = Depends(get_db),
    _token: str = Depends(require_auth),
) -> dict:
    """Authenticated: last login IP/time + known login IPs (L-02)."""
    return {**get_login_info(db), "current_ip": client_ip(request)}


@router.post("/setup", response_model=LoginResponse)
def setup(
    body: SetupRequest,
    request: Request,
    response: Response,
    db: Database = Depends(get_db),
):
    """First-run only: set the admin password and log in.

    Requires the one-time setup token from the startup log. Refuses
    with 403 once a password is configured (changing it goes through
    ``POST /api/settings/admin-password`` with the current password
    instead) or when the token is missing/wrong/expired. The token is
    discarded on success, so the endpoint is permanently dead after
    setup. The password write is atomic (see
    ``Database.set_admin_password_if_unset``).
    """
    if _setup_loopback_only() and not is_loopback_host(client_ip(request)):
        raise HTTPException(
            status_code=403,
            detail="setup is restricted to loopback connections"
            " (LANMUX_SETUP_LOOPBACK_ONLY=1)",
        )
    if db.get_setting("admin_password_hash"):
        raise HTTPException(
            status_code=403,
            detail="admin password is already configured",
        )
    expected = getattr(request.app.state, "setup_token", None)
    if (
        not expected
        or not body.setup_token
        or not hmac.compare_digest(body.setup_token, expected)
    ):
        raise HTTPException(
            status_code=403,
            detail="invalid or missing setup token;"
            " see the startup log (docker logs /"
            " journalctl -u lanmux-web) for the current token",
        )
    if len(body.password) < MIN_SETUP_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail="password must be at least "
            f"{MIN_SETUP_PASSWORD_LENGTH} characters",
        )
    if not db.set_admin_password_if_unset(hash_password(body.password)):
        # Lost a concurrent setup race: an admin now exists.
        raise HTTPException(
            status_code=403,
            detail="admin password is already configured",
        )
    # One-time token: invalidate it the moment setup succeeds.
    request.app.state.setup_token = None
    store: TokenStore = request.app.state.token_store
    token = store.issue()
    _set_auth_cookie(response, request, token)
    logger.info("setup completed from ip=%s", client_ip(request))
    return LoginResponse(token=token)


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Database = Depends(get_db),
):
    ip = client_ip(request)
    locked_until = login_locked_until(db, ip)
    if locked_until is not None:
        retry_after = max(
            1,
            int((locked_until - datetime.now(timezone.utc)).total_seconds()),
        )
        raise HTTPException(
            status_code=429,
            detail="too many failed login attempts;"
            f" try again after {locked_until.isoformat()}",
            headers={"Retry-After": str(retry_after)},
        )
    stored = db.get_setting("admin_password_hash") or ""
    if not stored:
        raise HTTPException(
            status_code=503,
            detail="admin password is not configured; start the backend"
            " with ADMIN_PASSWORD set",
        )
    if not verify_password(body.password, stored):
        record_login_failure(db, ip)
        # Log account label + IP only — never the password (H-01).
        logger.warning("failed login attempt account=admin ip=%s", ip)
        raise HTTPException(status_code=401, detail="invalid credentials")
    clear_login_lockouts(db, ip)
    is_new_ip = record_successful_login(db, ip)
    if is_new_ip:
        logger.warning("login from new ip account=admin ip=%s", ip)
    else:
        logger.info("login succeeded account=admin ip=%s", ip)
    store: TokenStore = request.app.state.token_store
    token = store.issue()
    _set_auth_cookie(response, request, token)
    return LoginResponse(token=token)


@router.post("/logout")
def logout(
    request: Request, response: Response, token: str = Depends(require_auth)
) -> dict:
    store: TokenStore = request.app.state.token_store
    store.revoke(token)
    _clear_auth_cookie(response)
    return {"ok": True}


@router.post("/logout-all")
def logout_all(
    request: Request, response: Response, _token: str = Depends(require_auth)
) -> dict:
    """Revoke every session token, including the caller's (M-04)."""
    store: TokenStore = request.app.state.token_store
    store.revoke_all()
    _clear_auth_cookie(response)
    logger.info(
        "all sessions revoked by logout-all ip=%s", client_ip(request)
    )
    return {"ok": True, "detail": "all sessions revoked; please log in again"}
