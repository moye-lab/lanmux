"""Admin authentication: password hashing + bearer tokens.

Standard library only — no extra dependencies.

Password storage
----------------
``hashlib.pbkdf2_hmac`` (SHA-256, 260k iterations, 16-byte random salt),
stored as ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>`` in the
``admin_password_hash`` setting. Plaintext is never stored. When a stored
hash is parsed, the iteration count must lie in
``1..MAX_HASH_ITERATIONS`` (1,000,000) — a tampered hash with a huge
iteration count is rejected instead of burning CPU (L-01).

Tokens
------
``secrets.token_hex(32)`` bearer tokens kept in a server-side in-memory
store with 24h expiry. Restarting the backend invalidates all tokens
(single-process LanMux instance; acceptable by design). Expiry slides:
every successful validation extends the token's expiry by the full TTL
(M-04). Expired tokens are purged lazily on every issue/validate call
(L-20). The token is delivered to browsers as an ``HttpOnly`` +
``SameSite=Strict`` cookie (``lanmux_token``, see
:mod:`app.routers.auth`); API clients may still use
``Authorization: Bearer <token>`` (M-03).

Login lockout (H-01)
--------------------
Failed logins are counted per client IP *and* per admin account, in the
``login_lockouts`` DB table (survives restarts). 5 failures impose a
15-minute lock; each further lock doubles the duration (30m, 60m, capped
at 120m). While locked, login answers 429 with a ``Retry-After`` header.
A successful login clears both counters. Failure responses never
distinguish "unknown account" from "wrong password" (single admin
account; both are 401 ``invalid credentials``), and failure logs record
only the account label and IP — never the password.

First-run setup token (H-02)
----------------------------
When no admin password exists at startup, :mod:`app.main` generates a
random one-time setup token (``app.state.setup_token``) and prints it in
the startup log. ``POST /api/auth/setup`` requires that token; after a
successful setup the token is discarded and the endpoint refuses
forever (an admin password now exists). Setup itself is atomic via
``Database.set_admin_password_if_unset`` (single locked check-and-set),
so concurrent setup attempts create exactly one admin.
``LANMUX_SETUP_LOOPBACK_ONLY=1`` optionally restricts setup to
loopback clients (D-04; default off, because Docker users run setup
from a LAN browser — see README).

Admin password seeding
----------------------
On first init, if no hash is stored and the ``ADMIN_PASSWORD``
environment variable is set, it is hashed and stored (see
:func:`ensure_admin_password`). The installer puts the default password
in the install command; the user changes it later via the web settings.
If neither is set, login is impossible until an admin password exists —
``GET /api/auth/status`` reports that state publicly so the UI can
explain it instead of showing a bare 401.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from fastapi import Request

if TYPE_CHECKING:
    from .database import Database

logger = logging.getLogger("lanmux.auth")

TOKEN_TTL = timedelta(hours=24)
TOKEN_TTL_SECONDS = 86400
_HASH_PREFIX = "pbkdf2_sha256"
_DEFAULT_ITERATIONS = 260_000
# L-01: reject stored hashes whose iteration count is outside this range
# instead of letting a tampered value burn CPU (default 260k is inside).
MIN_HASH_ITERATIONS = 1
MAX_HASH_ITERATIONS = 1_000_000
# L-01: exact hex lengths of the stored salt (16 bytes) and digest
# (SHA-256, 32 bytes) — anything else is a malformed/tampered hash.
_SALT_HEX_LEN = 32
_HASH_HEX_LEN = 64

# H-01: login lockout policy (per IP and per account, DB-backed).
LOCKOUT_MAX_FAILURES = 5
LOCKOUT_BASE_SECONDS = 15 * 60
LOCKOUT_MAX_SECONDS = 120 * 60
ACCOUNT_LOCKOUT_KEY = "account"

# M-03: HttpOnly session cookie name (path /api, SameSite=Strict).
COOKIE_NAME = "lanmux_token"

# L-02: how many distinct login IPs to remember for the panel display.
KNOWN_LOGIN_IPS_MAX = 20


def hash_password(password: str) -> str:
    """Hash ``password`` for storage (PBKDF2-HMAC-SHA256 + random salt)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _DEFAULT_ITERATIONS
    )
    return (
        f"{_HASH_PREFIX}${_DEFAULT_ITERATIONS}"
        f"${salt.hex()}${digest.hex()}"
    )


def verify_password(password: str, stored: str) -> bool:
    """Check ``password`` against a stored hash (constant-time compare).

    Returns False for malformed hashes and for iteration counts outside
    ``MIN_HASH_ITERATIONS..MAX_HASH_ITERATIONS`` (L-01).
    """
    if not stored or not stored.startswith(_HASH_PREFIX + "$"):
        return False
    try:
        _, iterations_s, salt_hex, hash_hex = stored.split("$")
        iterations = int(iterations_s)
        if not MIN_HASH_ITERATIONS <= iterations <= MAX_HASH_ITERATIONS:
            return False
        if len(salt_hex) != _SALT_HEX_LEN or len(hash_hex) != _HASH_HEX_LEN:
            return False
        expected = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            iterations,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected.hex(), hash_hex)


def generate_setup_token() -> str:
    """Random one-time setup token (H-02). URL-safe, ~144 bits."""
    return secrets.token_urlsafe(24)


def client_ip(request: Request) -> str:
    """Best-effort client IP for lockout/audit purposes.

    Only the direct peer address is used — ``X-Forwarded-For`` is
    deliberately ignored (clients could spoof it to evade lockout or
    to lock out someone else's IP).
    """
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def is_loopback_host(host: str) -> bool:
    """True for loopback clients (D-04 loopback-only setup switch)."""
    return host in ("127.0.0.1", "::1", "localhost")


class TokenStore:
    """In-memory bearer token store with sliding expiry (M-04).

    Every successful :meth:`valid` extends the token's expiry by the
    full TTL. Expired tokens are purged lazily on every issue/validate
    call so long-running processes do not accumulate them (L-20).
    """

    def __init__(self, ttl: timedelta = TOKEN_TTL):
        self._ttl = ttl
        self._tokens: dict[str, datetime] = {}

    def _purge_expired(self, now: datetime) -> None:
        expired = [t for t, exp in self._tokens.items() if now >= exp]
        for token in expired:
            del self._tokens[token]

    def __len__(self) -> int:
        return len(self._tokens)

    def issue(self) -> str:
        now = datetime.now(timezone.utc)
        self._purge_expired(now)
        token = secrets.token_hex(32)
        self._tokens[token] = now + self._ttl
        return token

    def valid(self, token: str | None) -> bool:
        if not token:
            return False
        now = datetime.now(timezone.utc)
        self._purge_expired(now)
        expiry = self._tokens.get(token)
        if expiry is None:
            return False
        # Sliding expiry: a live token's lifetime extends on each use.
        self._tokens[token] = now + self._ttl
        return True

    def revoke(self, token: str) -> None:
        self._tokens.pop(token, None)

    def revoke_all(self) -> None:
        self._tokens.clear()


# ---------------------------------------------------------------------
# Login lockout (H-01) — DB-backed, per IP + per account.
# ---------------------------------------------------------------------

def _lockout_key_ip(ip: str) -> str:
    return f"ip:{ip}"


def login_locked_until(db: "Database", ip: str) -> datetime | None:
    """Return the lock expiry if the IP or the account is locked."""
    now = datetime.now(timezone.utc)
    for key in (_lockout_key_ip(ip), ACCOUNT_LOCKOUT_KEY):
        row = db.get_login_lockout(key)
        if row is not None and row.get("locked_until"):
            locked_until = datetime.fromisoformat(row["locked_until"])
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if locked_until > now:
                return locked_until
    return None


def record_login_failure(db: "Database", ip: str) -> datetime | None:
    """Count one failed login for the IP and the account.

    Returns the lock expiry if this failure imposed a lock, else None.
    """
    now = datetime.now(timezone.utc)
    imposed: datetime | None = None
    for key in (_lockout_key_ip(ip), ACCOUNT_LOCKOUT_KEY):
        until = db.note_login_failure(
            key,
            max_failures=LOCKOUT_MAX_FAILURES,
            base_lock_seconds=LOCKOUT_BASE_SECONDS,
            max_lock_seconds=LOCKOUT_MAX_SECONDS,
            now=now,
        )
        if until is not None:
            imposed = until
    return imposed


def clear_login_lockouts(db: "Database", ip: str) -> None:
    """Clear the IP and account failure counters (on success)."""
    db.clear_login_lockout(_lockout_key_ip(ip))
    db.clear_login_lockout(ACCOUNT_LOCKOUT_KEY)


# ---------------------------------------------------------------------
# Login audit (L-02) — new-IP log + last-login display data.
# ---------------------------------------------------------------------

def record_successful_login(db: "Database", ip: str) -> bool:
    """Record a successful login. Returns True if the IP is new.

    The caller logs the result (account label + IP only, never the
    password). The last login IP/time and the known-IP list are kept
    in settings for the panel's session section.
    """
    now = datetime.now(timezone.utc)
    known: list[str] = []
    raw = db.get_setting("known_login_ips") or ""
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                known = [str(x) for x in parsed]
        except (ValueError, TypeError):
            known = []
    is_new = ip not in known
    if is_new:
        known.append(ip)
        known = known[-KNOWN_LOGIN_IPS_MAX:]
        db.set_setting("known_login_ips", json.dumps(known))
    db.set_setting("last_login_ip", ip)
    db.set_setting("last_login_at", now.isoformat())
    db.set_setting("last_login_new_ip", "1" if is_new else "0")
    return is_new


def get_login_info(db: "Database") -> dict:
    """Last-login display data for the settings page (L-02)."""
    known: list[str] = []
    raw = db.get_setting("known_login_ips") or ""
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                known = [str(x) for x in parsed]
        except (ValueError, TypeError):
            known = []
    return {
        "last_login_ip": db.get_setting("last_login_ip") or None,
        "last_login_at": db.get_setting("last_login_at") or None,
        "last_login_new_ip": (db.get_setting("last_login_new_ip") or "0") == "1",
        "known_login_ips": known,
    }


def ensure_admin_password(
    db: "Database", password: str | None = None
) -> bool:
    """Seed the admin password from ``ADMIN_PASSWORD`` on first init.

    ``password`` overrides the env var when given (used by the
    installer helper, which reads a caller-provided env mapping).
    Returns True if an admin password hash is now stored, False if
    neither a stored hash nor a password exists.
    """
    if db.get_setting("admin_password_hash"):
        return True
    env_password = (
        password
        if password is not None
        else os.environ.get("ADMIN_PASSWORD", "")
    )
    if not env_password:
        return False
    # Atomic check-and-set: a concurrent setup cannot create a second
    # admin (the same primitive the setup endpoint uses).
    return db.set_admin_password_if_unset(hash_password(env_password))


def require_auth(request: Request) -> str:
    """FastAPI dependency: require a valid session token.

    Reads the ``HttpOnly`` session cookie first, then falls back to
    ``Authorization: Bearer <token>`` for API clients (M-03). Raises
    401 (missing/invalid/expired token). Returns the token. A valid
    token's expiry slides (M-04).
    """
    from fastapi import HTTPException

    token = request.cookies.get(COOKIE_NAME) or ""
    if not token:
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
    store: TokenStore = request.app.state.token_store
    if not store.valid(token):
        raise HTTPException(
            status_code=401,
            detail="missing or invalid auth token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token
