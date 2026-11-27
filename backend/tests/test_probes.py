"""Probe total-deadline tests (M-32).

``timeout`` is a *total* deadline enforced with a monotonic clock:
every stage timeout is min(stage timeout, total remaining). The
regression is a slow-drip server — one byte at a time, each recv
inside its own read timeout — against which a plain per-operation
timeout is useless (measured before the fix: ``timeout=2.0`` took
11.1s). All servers below are local; no network is used.
"""

import socket
import threading
import time

from app.probes import probe_direct, probe_via_socks5


def _serve_once(port: int, mode: str, gap: float = 1.0, nbytes: int = 5):
    """Serve one connection: drip the body or the headers."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    conn, _ = server.accept()
    try:
        conn.recv(65536)
        if mode == "body-drip":
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n"
                b"Connection: close\r\n\r\n"
            )
            for _ in range(nbytes):
                conn.sendall(b"x")
                time.sleep(gap)
        else:  # header-drip
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            for _ in range(nbytes):
                conn.sendall(b"X-Drip: a\r\n")
                time.sleep(gap)
            conn.sendall(b"Content-Length: 0\r\n\r\n")
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        time.sleep(0.2)
        conn.close()
        server.close()


def _serve_ok(port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    conn, _ = server.accept()
    try:
        conn.recv(65536)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"Connection: close\r\n\r\nok"
        )
    finally:
        conn.close()
        server.close()


def _start_server(target, *args):
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    time.sleep(0.2)
    return thread


def test_probe_direct_normal_server():
    thread = _start_server(_serve_ok, 18101)
    result = probe_direct("http://127.0.0.1:18101/", timeout=5.0)
    thread.join(timeout=5)
    assert result["ok"] is True
    assert result["status"] == 200
    assert result["ttfb_ms"] is not None
    assert result["elapsed_ms"] < 3000


def test_probe_direct_body_drip_returns_fast():
    # Headers arrive at once; the body then drips. A first-byte
    # probe only needs the headers, so it must return fast — the
    # pre-fix implementation read the whole body and took ~9s.
    thread = _start_server(_serve_once, 18102, "body-drip")
    started = time.monotonic()
    result = probe_direct("http://127.0.0.1:18102/", timeout=2.0)
    elapsed = time.monotonic() - started
    thread.join(timeout=15)
    assert result["ok"] is True
    assert result["status"] == 200
    assert elapsed < 3.0, f"body-drip probe took {elapsed:.2f}s"


def test_probe_direct_header_drip_respects_total_deadline():
    # Headers drip one line per 1.5s; each recv is inside its own
    # 2s read timeout, so only the total deadline can stop this.
    thread = _start_server(_serve_once, 18103, "header-drip")
    started = time.monotonic()
    result = probe_direct("http://127.0.0.1:18103/", timeout=2.0)
    elapsed = time.monotonic() - started
    thread.join(timeout=15)
    assert result["ok"] is False
    assert "deadline" in (result["error"] or "")
    assert result["elapsed_ms"] < 5000, (
        f"header-drip probe took {elapsed:.2f}s "
        "(total deadline not enforced)"
    )


def test_probe_direct_unreachable_fast():
    # Connection refused: no listener — fails fast, no deadline burn.
    started = time.monotonic()
    result = probe_direct("http://127.0.0.1:18109/", timeout=5.0)
    assert result["ok"] is False
    assert time.monotonic() - started < 3.0


def _serve_blackhole(port: int, hold_s: float = 10.0):
    """Accept a SOCKS5 connection and then never answer: the
    handshake recv must be bounded by the total deadline."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    conn, _ = server.accept()
    try:
        time.sleep(hold_s)
    finally:
        conn.close()
        server.close()


def test_probe_via_socks5_blackhole_respects_total_deadline():
    thread = _start_server(_serve_blackhole, 18104)
    started = time.monotonic()
    result = probe_via_socks5(
        "https://example.com/",
        proxy_host="127.0.0.1",
        proxy_port=18104,
        timeout=2.0,
    )
    elapsed = time.monotonic() - started
    thread.join(timeout=15)
    assert result["ok"] is False
    assert result["elapsed_ms"] < 5000, (
        f"blackhole SOCKS5 probe took {elapsed:.2f}s "
        "(total deadline not enforced)"
    )
