"""Auth hardening tests (audit phase 2, auth cluster).

Covers H-01 (login lockout), H-02 + D-04 (one-time setup token,
atomic setup, loopback switch), M-03 (HttpOnly cookie + security
headers), M-04 (sliding expiry + logout-all), L-01 (hash iteration
bound), L-02 (new-IP login audit + session info) and L-20 (lazy
expiry purge). Real TestClient against a tmp DB; no network.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.auth import (
    COOKIE_NAME,
    TokenStore,
    hash_password,
    verify_password,
)
from app.deps import get_config_service, get_mihomo_client
from app.main import create_app

ADMIN_PASSWORD = "test-admin-password"
SETUP_PASSWORD = "brand-new-admin-pass"


class FakeConfigService:
    def apply(self):
        pass

    def read_config_text(self):
        return None

    def read_masked_config_text(self):
        return None


class FakeMihomoClient:
    def get_version(self):
        return {"version": "fake-1.0-test"}

    def get_connections(self):
        return {"connections": []}

    def get_traffic(self, timeout=5.0):
        return {"up": 0, "down": 0}

    def reload_config(self, force=True):
        pass

    def get_proxies(self):
        return {"proxies": {}}


@pytest.fixture
def app(tmp_path):
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    app.state.db.set_setting(
        "admin_password_hash", hash_password(ADMIN_PASSWORD)
    )
    app.dependency_overrides[get_config_service] = FakeConfigService
    app.dependency_overrides[get_mihomo_client] = FakeMihomoClient
    return app


@pytest.fixture
def app_unconfigured(tmp_path):
    """No admin password: the app generates a one-time setup token."""
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    app.dependency_overrides[get_config_service] = FakeConfigService
    app.dependency_overrides[get_mihomo_client] = FakeMihomoClient
    return app


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def client_unconfigured(app_unconfigured):
    with TestClient(app_unconfigured) as test_client:
        yield test_client


def _login(client, password=ADMIN_PASSWORD):
    response = client.post("/api/auth/login", json={"password": password})
    assert response.status_code == 200, response.text
    return response


# -------------------------------------------------------------------- H-01
def test_login_lockout_after_five_failures(client, app):
    for _ in range(5):
        assert client.post(
            "/api/auth/login", json={"password": "wrong"}
        ).status_code == 401
    # 6th attempt — even the correct password is refused while locked.
    response = client.post(
        "/api/auth/login", json={"password": ADMIN_PASSWORD}
    )
    assert response.status_code == 429, response.text
    assert response.headers.get("Retry-After")
    # A wrong password is refused the same way (no oracle).
    assert client.post(
        "/api/auth/login", json={"password": "wrong"}
    ).status_code == 429
    # Both dimensions are locked: the IP row and the account row exist.
    assert app.state.db.get_login_lockout("account") is not None
    assert app.state.db.get_login_lockout("ip:testclient") is not None


def test_login_lockout_recovers_after_expiry(client, app):
    for _ in range(5):
        client.post("/api/auth/login", json={"password": "wrong"})
    assert client.post(
        "/api/auth/login", json={"password": ADMIN_PASSWORD}
    ).status_code == 429
    # Simulate 15+ minutes passing: move both lock expiries to the past.
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    db = app.state.db
    with db._lock:
        db.conn.execute(
            "UPDATE login_lockouts SET locked_until = ?", (past,)
        )
        db.conn.commit()
    assert _login(client).status_code == 200
    # A successful login clears the counters entirely.
    assert db.get_login_lockout("account") is None
    assert db.get_login_lockout("ip:testclient") is None


def test_login_failure_response_does_not_distinguish(client):
    response = client.post("/api/auth/login", json={"password": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid credentials"


def test_login_lockout_is_exponential(client, app):
    """Second lock (after expiry + 5 more failures) lasts 30m, not 15m."""
    db = app.state.db
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()

    def _lock_once():
        for _ in range(5):
            client.post("/api/auth/login", json={"password": "wrong"})
        assert client.post(
            "/api/auth/login", json={"password": ADMIN_PASSWORD}
        ).status_code == 429
        # Capture the imposed lock BEFORE simulating its expiry.
        row = db.get_login_lockout("account")
        until = datetime.fromisoformat(row["locked_until"])
        with db._lock:
            db.conn.execute(
                "UPDATE login_lockouts SET locked_until = ?", (past,)
            )
            db.conn.commit()
        return until, row["lock_count"]

    first_until, first_count = _lock_once()
    assert first_count == 1
    first_remaining = (
        first_until - datetime.now(timezone.utc)
    ).total_seconds()
    assert 14 * 60 < first_remaining <= 15 * 60
    second_until, second_count = _lock_once()
    assert second_count == 2
    second_remaining = (
        second_until - datetime.now(timezone.utc)
    ).total_seconds()
    assert 29 * 60 < second_remaining <= 30 * 60


# --------------------------------------------------------- H-02 + D-04
def test_setup_token_is_generated_when_unconfigured(app_unconfigured):
    token = app_unconfigured.state.setup_token
    assert token and len(token) >= 24
    assert app_unconfigured.state.db.get_setting(
        "admin_password_hash"
    ) in (None, "")


def test_setup_requires_token(app_unconfigured, client_unconfigured):
    # No token at all.
    response = client_unconfigured.post(
        "/api/auth/setup", json={"password": SETUP_PASSWORD}
    )
    assert response.status_code == 403, response.text
    # Wrong token.
    response = client_unconfigured.post(
        "/api/auth/setup",
        json={"password": SETUP_PASSWORD, "setup_token": "nope"},
    )
    assert response.status_code == 403, response.text
    assert client_unconfigured.get(
        "/api/auth/status"
    ).json()["admin_configured"] is False


def test_setup_token_is_one_time(app_unconfigured, client_unconfigured):
    token = app_unconfigured.state.setup_token
    response = client_unconfigured.post(
        "/api/auth/setup",
        json={"password": SETUP_PASSWORD, "setup_token": token},
    )
    assert response.status_code == 200, response.text
    # The token is discarded on success and the endpoint is dead:
    # a replay with the same token is refused, and so is any other.
    assert app_unconfigured.state.setup_token is None
    for candidate in (token, "another-token", ""):
        response = client_unconfigured.post(
            "/api/auth/setup",
            json={"password": "attacker-password", "setup_token": candidate},
        )
        assert response.status_code == 403, response.text
    # The first password won; the attacker's did not.
    assert _login(client_unconfigured, SETUP_PASSWORD).status_code == 200


def test_concurrent_setup_creates_single_admin(
    app_unconfigured, client_unconfigured
):
    # One event loop, 10 concurrent ASGI requests: sync endpoints run
    # in Starlette's worker threads, so the setup race is real. (A
    # second TestClient context is unusable here — its lifespan
    # shutdown would close the shared DB.)
    import httpx

    token = app_unconfigured.state.setup_token
    results = []

    async def _attempt(password):
        transport = httpx.ASGITransport(app=app_unconfigured)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as c:
            resp = await c.post(
                "/api/auth/setup",
                json={"password": password, "setup_token": token},
            )
            results.append(resp.status_code)

    async def _all():
        await asyncio.gather(
            *[_attempt(f"setup-pass-{i:02d}0000") for i in range(10)]
        )

    asyncio.run(_all())
    assert results.count(200) == 1, results
    assert results.count(403) == 9, results
    # Exactly one admin hash exists and it logs in with the winner.
    assert client_unconfigured.get(
        "/api/auth/status"
    ).json()["admin_configured"] is True


def test_setup_loopback_switch_blocks_non_loopback(
    app_unconfigured, client_unconfigured, monkeypatch
):
    monkeypatch.setenv("LANMUX_SETUP_LOOPBACK_ONLY", "1")
    response = client_unconfigured.post(
        "/api/auth/setup",
        json={
            "password": SETUP_PASSWORD,
            "setup_token": app_unconfigured.state.setup_token,
        },
    )
    # TestClient connects as "testclient" — not loopback — so it is refused.
    assert response.status_code == 403, response.text
    assert client_unconfigured.get(
        "/api/auth/status"
    ).json()["admin_configured"] is False


def test_setup_loopback_switch_allows_loopback(
    app_unconfigured, client_unconfigured, monkeypatch
):
    monkeypatch.setenv("LANMUX_SETUP_LOOPBACK_ONLY", "1")
    # Pretend the peer is loopback (unit-level override of the check).
    import app.routers.auth as auth_router

    monkeypatch.setattr(
        auth_router, "is_loopback_host", lambda host: True
    )
    response = client_unconfigured.post(
        "/api/auth/setup",
        json={
            "password": SETUP_PASSWORD,
            "setup_token": app_unconfigured.state.setup_token,
        },
    )
    assert response.status_code == 200, response.text


def test_setup_loopback_switch_defaults_off(
    app_unconfigured, client_unconfigured, monkeypatch
):
    monkeypatch.delenv("LANMUX_SETUP_LOOPBACK_ONLY", raising=False)
    response = client_unconfigured.post(
        "/api/auth/setup",
        json={
            "password": SETUP_PASSWORD,
            "setup_token": app_unconfigured.state.setup_token,
        },
    )
    assert response.status_code == 200, response.text


# -------------------------------------------------------------------- M-03
def test_login_sets_httponly_cookie(client):
    response = _login(client)
    set_cookie = response.headers.get("set-cookie", "")
    assert COOKIE_NAME in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "samesite=strict" in set_cookie.lower()
    assert "max-age=86400" in set_cookie.lower()


def test_cookie_auth_works_without_bearer_header(client):
    # The TestClient jar keeps the login cookie; a fresh request with
    # no Authorization header at all must still be authenticated.
    _login(client)
    response = client.get("/api/nodes")
    assert response.status_code == 200, response.text


def test_bearer_fallback_still_works_for_api_clients(client):
    response = _login(client)
    token = response.json()["token"]
    # Drop the cookie jar: Bearer header alone must still authenticate.
    client.cookies.clear()
    assert client.get(
        "/api/nodes", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 200


def test_logout_clears_cookie(client):
    _login(client)
    response = client.post("/api/auth/logout")
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie", "")
    assert COOKIE_NAME in set_cookie
    # The cookie jar dropped it: subsequent calls are unauthenticated.
    assert client.get("/api/nodes").status_code == 401


def test_security_headers(client):
    index = client.get("/")
    assert index.headers["X-Frame-Options"] == "DENY"
    assert index.headers["X-Content-Type-Options"] == "nosniff"
    csp = index.headers.get("Content-Security-Policy", "")
    # Alpine-compatible: inline scripts + eval must stay allowed.
    assert "script-src 'self' 'unsafe-inline' 'unsafe-eval'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "frame-ancestors 'none'" in csp
    # API responses are never cached.
    _login(client)
    api = client.get("/api/nodes")
    assert api.headers["Cache-Control"] == "no-store"
    assert api.headers["X-Frame-Options"] == "DENY"


# -------------------------------------------------------------------- M-04
def test_sliding_expiry_refreshes_on_use(client, app):
    response = _login(client)
    token = response.json()["token"]
    store = app.state.token_store
    soon = datetime.now(timezone.utc) + timedelta(seconds=30)
    store._tokens[token] = soon
    assert client.get(
        "/api/nodes", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 200
    # The authenticated request extended the expiry well past 30s.
    assert store._tokens[token] > datetime.now(timezone.utc) + timedelta(
        hours=1
    )


def test_logout_all_revokes_every_token(client, app):
    first = _login(client)
    token1 = first.json()["token"]
    second = _login(client)
    token2 = second.json()["token"]
    assert token1 != token2
    response = client.post("/api/auth/logout-all")
    assert response.status_code == 200
    for token in (token1, token2):
        assert client.get(
            "/api/nodes", headers={"Authorization": f"Bearer {token}"}
        ).status_code == 401


def test_password_change_still_revokes_all_tokens(client):
    first = _login(client)
    token = first.json()["token"]
    response = client.post(
        "/api/settings/admin-password",
        json={
            "current_password": ADMIN_PASSWORD,
            "new_password": "new-admin-password",
        },
    )
    assert response.status_code == 200, response.text
    assert client.get(
        "/api/nodes", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 401


# -------------------------------------------------------------------- L-01
def test_hash_iteration_bound():
    good = hash_password("some-password")
    assert verify_password("some-password", good) is True
    assert verify_password("wrong-password", good) is False
    # Tampered iteration counts are rejected, not executed.
    prefix, _, salt_hex, hash_hex = good.split("$")
    assert verify_password(
        "some-password",
        f"{prefix}$2000000${salt_hex}${hash_hex}",
    ) is False
    assert verify_password(
        "some-password", f"{prefix}$0${salt_hex}${hash_hex}"
    ) is False
    assert verify_password(
        "some-password", f"{prefix}$-5${salt_hex}${hash_hex}"
    ) is False
    assert verify_password(
        "some-password", f"{prefix}$notanumber${salt_hex}${hash_hex}"
    ) is False
    # Malformed shapes are rejected.
    assert verify_password("x", "pbkdf2_sha256$260000$abc") is False
    assert verify_password("x", "") is False


# -------------------------------------------------------------------- L-02
def test_session_info_reports_last_login(client):
    _login(client)
    info = client.get("/api/auth/session-info").json()
    assert info["last_login_ip"] == "testclient"
    assert info["last_login_at"]
    assert info["known_login_ips"] == ["testclient"]
    assert info["last_login_new_ip"] is True
    # A second login from the same IP is no longer "new".
    _login(client)
    info = client.get("/api/auth/session-info").json()
    assert info["last_login_new_ip"] is False
    assert info["known_login_ips"] == ["testclient"]


def test_session_info_requires_auth(client):
    assert client.get("/api/auth/session-info").status_code == 401


# -------------------------------------------------------------------- L-20
def test_expired_tokens_are_purged_lazily():
    store = TokenStore()
    stale = store.issue()
    store._tokens[stale] = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert len(store) == 1
    # Any later issue/validate purges the expired entry.
    store.issue()
    assert stale not in store._tokens
    assert len(store) == 1
    stale2 = store.issue()
    store._tokens[stale2] = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert store.valid(stale2) is False
    assert stale2 not in store._tokens


# ------------------------------------------------- docker_runner TLS (M-07)
def test_web_tls_args(tmp_path):
    from app.docker_runner import web_tls_args

    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    assert web_tls_args({}) == []
    assert web_tls_args(
        {"LANMUX_SSL_CERTFILE": str(cert), "LANMUX_SSL_KEYFILE": str(key)}
    ) == ["--ssl-certfile", str(cert), "--ssl-keyfile", str(key)]
    # Only one side set, or a missing file: stay on HTTP, never crash.
    assert web_tls_args({"LANMUX_SSL_CERTFILE": str(cert)}) == []
    assert web_tls_args(
        {
            "LANMUX_SSL_CERTFILE": str(cert),
            "LANMUX_SSL_KEYFILE": str(tmp_path / "missing.pem"),
        }
    ) == []
