"""LanMux settings routes.

``GET`` is desensitized: secrets are never returned, only ``*_set``
flags. ``PUT`` is a partial update (only provided fields change) and
triggers a config recompile + safe reload, reported in the ``reload``
object. The admin password is changed via
``POST /api/settings/admin-password`` (current password required);
changing it revokes all tokens, including the caller's.

``GET /ss-link`` (Phase 3) builds the ``ss://`` URL for the LAN total
node from settings so the frontend can show it and render its QR code
without ever seeing the SS password itself.
"""

from __future__ import annotations

import base64
import logging
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request

from ..auth import TokenStore, hash_password, require_auth, verify_password
from ..config_service import ConfigService
from ..database import Database
from ..deps import apply_and_report, get_config_service, get_db
from ..models import AdminPasswordChange, SettingsOut, SettingsUpdate

logger = logging.getLogger("lanmux.settings")

router = APIRouter(
    prefix="/api/settings",
    tags=["settings"],
    dependencies=[Depends(require_auth)],
)

# Shadowsocks ciphers mihomo supports on a listener.
SS_CIPHERS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}

MIN_ADMIN_PASSWORD_LENGTH = 8

# Tag shown in clients for the LAN total node (URL-encoded in the link).
SS_LINK_TAG = "LanMux-Core"

# Mixed auth is a pair (M-06 + L-22): saving only one half leaves
# mihomo silently unauthenticated (password without username) or
# emits ``password: ''`` (username without password).
MIXED_AUTH_PAIR_ERROR = (
    "用户名与密码须同时设置"
    "（只填用户名或只填密码无法保存；清空用户名可关闭鉴权）"
)


def _effective_mixed_pair(
    body: SettingsUpdate, db: Database
) -> tuple[str, str]:
    """Username / password as they would be after this update."""
    stored_user = (db.get_setting("mixed_auth_user") or "").strip()
    stored_pass = db.get_setting("mixed_auth_pass") or ""
    user = (
        body.mixed_auth_user.strip()
        if body.mixed_auth_user is not None
        else stored_user
    )
    password = (
        body.mixed_auth_pass
        if body.mixed_auth_pass is not None
        else stored_pass
    )
    return user, password


def _desensitized(db: Database) -> SettingsOut:
    settings = db.get_settings()
    return SettingsOut(
        lan_ip=settings.lan_ip,
        ss_port=settings.ss_port,
        ss_cipher=settings.ss_cipher,
        ss_password_set=bool(settings.ss_password),
        mixed_port=settings.mixed_port,
        mixed_auth_user=settings.mixed_auth_user,
        mixed_auth_pass_set=bool(settings.mixed_auth_pass),
        mihomo_secret_set=bool(settings.mihomo_secret),
        controller_port=settings.controller_port,
    )


def _validate_port(name: str, value: int) -> None:
    if not 1 <= value <= 65535:
        raise HTTPException(
            status_code=400,
            detail=f"{name} must be between 1 and 65535 (got {value})",
        )


@router.get("", response_model=SettingsOut)
def get_settings(db: Database = Depends(get_db)):
    return _desensitized(db)


@router.get("/ss-link")
def get_ss_link(db: Database = Depends(get_db)):
    """Build the ``ss://`` URL for the LAN total node from settings.

    Full-base64url form (``ss://<b64url(method:password@host:port)>#tag``,
    no padding) — the form Shadowrocket / Stash / v2rayNG / Clash all
    accept. The password is embedded in the URL itself (inherent to
    ``ss://`` links); it is not returned as a separate field.
    """
    settings = db.get_settings()
    if not settings.ss_password:
        raise HTTPException(
            status_code=400,
            detail="ss_password is not set — set it in settings first",
        )
    raw = (
        f"{settings.ss_cipher}:{settings.ss_password}"
        f"@{settings.lan_ip}:{settings.ss_port}"
    )
    b64 = (
        base64.urlsafe_b64encode(raw.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    # Explicit plaintext export (M-05): record the reveal.
    db.log_audit("ss_link", None, "SS 链接已导出")
    logger.info("ss_link exported")
    return {
        "url": f"ss://{b64}#{quote(SS_LINK_TAG)}",
        "host": settings.lan_ip,
        "port": settings.ss_port,
        "cipher": settings.ss_cipher,
        "password_set": True,
        "tag": SS_LINK_TAG,
    }


@router.put("", response_model=dict)
def update_settings(
    body: SettingsUpdate,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    # Snapshot the values being changed so a failed apply can restore
    # them: DB and disk must never split (H-05/H-06). The snapshot is
    # only restored on a genuine apply failure — a restart-required
    # outcome keeps the new values on purpose (the new config is
    # already on disk, waiting for the mihomo restart).
    previous: dict[str, str] = {}
    current = db.get_settings()
    for key in (
        "ss_port", "mixed_port", "controller_port", "lan_ip",
        "ss_cipher", "ss_password", "mixed_auth_user",
        "mixed_auth_pass", "mihomo_secret",
    ):
        if getattr(body, key, None) is not None:
            previous[key] = str(getattr(current, key))
    # Mixed pair check FIRST, before any field is persisted: a
    # rejected half pair must not leave the other half stored.
    # Clearing the username with no password in the request means
    # "turn auth off" (the form sends no password when it is left
    # unchanged), so the stored password is cleared with it instead
    # of stranding a half pair.
    disable_mixed_auth = (
        body.mixed_auth_user is not None
        and not body.mixed_auth_user.strip()
        and body.mixed_auth_pass is None
    )
    eff_user, eff_pass = _effective_mixed_pair(body, db)
    if disable_mixed_auth:
        eff_user, eff_pass = "", ""
    if bool(eff_user.strip()) != bool((eff_pass or "").strip()):
        raise HTTPException(status_code=400, detail=MIXED_AUTH_PAIR_ERROR)
    # M-25: validate EVERYTHING first, then commit once. The old code
    # wrote each field as it validated it, so a 400 halfway through
    # left the earlier fields persisted (half-updated settings).
    updates: dict[str, object] = {}
    if body.ss_port is not None:
        _validate_port("ss_port", body.ss_port)
        updates["ss_port"] = body.ss_port
    if body.mixed_port is not None:
        _validate_port("mixed_port", body.mixed_port)
        updates["mixed_port"] = body.mixed_port
    if body.controller_port is not None:
        _validate_port("controller_port", body.controller_port)
        updates["controller_port"] = body.controller_port
    if body.lan_ip is not None:
        if not body.lan_ip.strip():
            raise HTTPException(
                status_code=400, detail="lan_ip must not be empty"
            )
        updates["lan_ip"] = body.lan_ip.strip()
    if body.ss_cipher is not None:
        if body.ss_cipher not in SS_CIPHERS:
            raise HTTPException(
                status_code=400,
                detail=f"unsupported ss_cipher: {body.ss_cipher!r} "
                f"(valid: {sorted(SS_CIPHERS)})",
            )
        updates["ss_cipher"] = body.ss_cipher
    if body.ss_password is not None:
        updates["ss_password"] = body.ss_password
    if disable_mixed_auth:
        updates["mixed_auth_user"] = ""
        updates["mixed_auth_pass"] = ""
    else:
        if body.mixed_auth_user is not None:
            updates["mixed_auth_user"] = body.mixed_auth_user.strip()
        if body.mixed_auth_pass is not None:
            updates["mixed_auth_pass"] = body.mixed_auth_pass
    if body.mihomo_secret is not None:
        updates["mihomo_secret"] = body.mihomo_secret
    # Single transaction: a validation failure above has written
    # nothing, and the bulk write below is all-or-nothing.
    if updates:
        db.set_settings_bulk(updates)
    reload = apply_and_report(service)
    if not reload["ok"] and not reload.get("restart_required"):
        # Genuine failure: roll the DB back to the pre-request values
        # so DB, disk and the running mihomo agree again. (The
        # on-disk file was already rolled back by the apply itself.)
        for key, value in previous.items():
            try:
                db.set_setting(key, value)
            except Exception:
                logger.error(
                    "could not roll back setting %s after failed apply",
                    key, exc_info=True,
                )
    return {
        "settings": _desensitized(db),
        "reload": reload,
    }


@router.post("/admin-password")
def change_admin_password(
    body: AdminPasswordChange,
    request: Request,
    db: Database = Depends(get_db),
):
    stored = db.get_setting("admin_password_hash") or ""
    if not stored or not verify_password(body.current_password, stored):
        raise HTTPException(
            status_code=403, detail="current password is incorrect"
        )
    if len(body.new_password) < MIN_ADMIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail="new password must be at least "
            f"{MIN_ADMIN_PASSWORD_LENGTH} characters",
        )
    db.set_setting("admin_password_hash", hash_password(body.new_password))
    # Changing the password logs out every session, including this one.
    store: TokenStore = request.app.state.token_store
    store.revoke_all()
    return {"ok": True, "detail": "password changed; please log in again"}
