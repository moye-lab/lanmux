"""Tests for the SPA fallback in app.main (v0.8.1).

A refresh of a tab URL (/#routing) can arrive at the server with the
'#' percent-encoded (/%23routing) when a proxy/relay in the user's
network path mangles it; the panel must still load instead of 404ing
as JSON. Unknown non-API paths serve index.html, while unknown /api/*
paths keep the JSON 404.
"""

from fastapi.testclient import TestClient

from app.main import create_app


def _client(tmp_path):
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "config.yaml",
    )
    return TestClient(app)


def test_root_serves_panel(tmp_path):
    client = _client(tmp_path)
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "LanMux" in res.text


def test_mangled_tab_path_serves_panel(tmp_path):
    client = _client(tmp_path)
    # '#routing' percent-encoded by a proxy/relay on refresh.
    res = client.get("/%23routing")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "LanMux" in res.text
    # '#' dropped outright by an intermediary.
    res = client.get("/routing")
    assert res.status_code == 200
    assert "LanMux" in res.text


def test_existing_static_file_served_directly(tmp_path):
    client = _client(tmp_path)
    res = client.get("/index.html")
    assert res.status_code == 200
    assert "LanMux" in res.text


def test_unknown_api_path_still_404s_as_json(tmp_path):
    client = _client(tmp_path)
    res = client.get("/api/nonexistent")
    assert res.status_code == 404
    assert res.json() == {"detail": "Not Found"}


def test_health_still_wins_over_fallback(tmp_path):
    client = _client(tmp_path)
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["phase"] == 4
    assert body["version"] == "1.0.2"
    assert body["commit"] == "unknown"
    assert body["build_time"] == "unknown"


# -- vendored frontend assets (v0.9.5) -----------------------------------
# Alpine.js and the Tailwind Play CDN used to load from jsdelivr /
# cdn.tailwindcss.com; on 2026-11-24 the user's home broadband reset
# connections to jsdelivr (ERR_CONNECTION_RESET), Alpine never loaded,
# and the panel stayed blank (x-cloak hides everything until Alpine
# boots). Both scripts are vendored under frontend/vendor/ and served
# same-origin; the panel must work with no outside network at all.
# Supply-chain hardening (audit L-41): the Tailwind Play CDN script is
# gone — the panel now loads a statically compiled tailwind.css
# (built with the Tailwind CLI from frontend/index.html); no browser-side
# JIT compile happens at runtime anymore.


def test_panel_has_no_cdn_script_tags(tmp_path):
    client = _client(tmp_path)
    res = client.get("/")
    assert res.status_code == 200
    assert "cdn.jsdelivr.net" not in res.text
    assert "cdn.tailwindcss.com" not in res.text
    assert "/vendor/alpine.min.js" in res.text
    assert "/vendor/tailwind.css" in res.text
    # The Play CDN script must not come back (audit L-41).
    assert "/vendor/tailwind.js" not in res.text


def test_vendor_alpine_served(tmp_path):
    client = _client(tmp_path)
    res = client.get("/vendor/alpine.min.js")
    assert res.status_code == 200
    assert "javascript" in res.headers["content-type"]
    assert len(res.content) > 40_000
    assert "3.14.8" in res.text


def test_vendor_tailwind_served(tmp_path):
    client = _client(tmp_path)
    res = client.get("/vendor/tailwind.css")
    assert res.status_code == 200
    assert "text/css" in res.headers["content-type"]
    assert len(res.content) > 10_000
    # Compiled Tailwind v3 output: preflight variables + the custom
    # font-sans stack from tailwind.config.js (mirrors the old inline
    # Play CDN tailwind.config in index.html).
    assert "--tw-" in res.text
    assert "font-family:Inter" in res.text
