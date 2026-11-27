"""First-byte latency probes for the link diagnostics endpoint.

Two probes, both standard library + ``httpx`` (no extra deps):

* :func:`probe_direct` — plain HTTPS GET, measured to first byte
  (time to response headers, timed with a monotonic clock).
* :func:`probe_via_socks5` — HTTPS GET tunnelled through a SOCKS5
  proxy (LanMux's Mixed listener) with remote DNS (``socks5h``
  semantics: the domain name is sent to the proxy, which resolves it
  through mihomo's DNS). Implemented on ``socket`` + ``ssl`` so no
  SOCKS library is needed; username/password auth (RFC 1929) is
  supported when the Mixed listener has auth enabled.

Total deadline (M-32): ``timeout`` is a *total* deadline, enforced
with a monotonic clock. Every stage timeout is
``min(stage_timeout, remaining)``, and :func:`probe_direct` runs its
``httpx`` call in a daemon thread joined at the deadline — httpx
timeouts are per-operation, so a server that drips one byte at a
time (each recv inside its own read timeout) could otherwise run
far past ``timeout`` (measured: ``timeout=2.0`` took 11.1s). The
thread is bounded too: its own stage timeouts are ≤ ``timeout``, so
it exits shortly after the deadline. Only response headers are read
— first-byte timing needs nothing more, and never reading the body
also kills the body-drip case outright.

Both return a result dict and never raise for probe failures — a
failed probe is data, not a crash. ``ok`` is False with ``error`` set
when the target cannot be reached.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
import urllib.parse
from typing import Any, Callable

import httpx

DEFAULT_TIMEOUT = 10.0

# Per-stage nominal timeouts. Each is capped by the remaining total
# budget at the moment the stage starts (see _remaining()).
_CONNECT_TIMEOUT_S = 5.0
_IO_TIMEOUT_S = 5.0


def _deadline(timeout: float) -> float:
    return time.monotonic() + max(0.0, timeout)


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _stage_timeout(nominal: float, deadline: float) -> float:
    """min(stage timeout, total remaining) — never zero or negative
    while the deadline is still ahead (a floor keeps the stage
    callable); 0.05s once the deadline has passed so the caller can
    fail fast instead of blocking."""
    remaining = _remaining(deadline)
    if remaining <= 0:
        return 0.05
    return min(nominal, remaining)


class _ProbeTimeout(TimeoutError):
    """Internal: the total deadline was hit mid-probe."""


def _check_deadline(deadline: float) -> None:
    if _remaining(deadline) <= 0:
        raise _ProbeTimeout("probe total deadline exceeded")


def _run_with_deadline(
    fn: Callable[[], dict[str, Any]], timeout: float
) -> tuple[bool, dict[str, Any] | None]:
    """Run ``fn`` in a daemon thread; join until ``timeout`` seconds.

    Returns ``(True, result)`` when the thread finished in time,
    ``(False, None)`` when the deadline hit first (the thread keeps
    running, bounded by its own stage timeouts, and is abandoned).
    """
    box: dict[str, Any] = {}

    def _target() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - probe failure is data
            box["error"] = exc

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return False, None
    if "error" in box:
        raise box["error"]
    return True, box.get("result")


def probe_direct(url: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """HTTPS GET directly (no proxy); returns first-byte timing."""
    started = time.monotonic()
    deadline = _deadline(timeout)

    def _fetch() -> dict[str, Any]:
        # Stage timeouts are min(nominal, total remaining).
        remaining = _remaining(deadline)
        per_request = httpx.Timeout(
            connect=_stage_timeout(_CONNECT_TIMEOUT_S, deadline),
            read=min(timeout, remaining) if remaining > 0 else 0.05,
            write=_stage_timeout(_IO_TIMEOUT_S, deadline),
            pool=_stage_timeout(_IO_TIMEOUT_S, deadline),
        )
        try:
            # trust_env=False: this probe must measure the DIRECT
            # path, never a proxy picked up from HTTP(S)_PROXY
            # environment variables.
            with httpx.Client(
                timeout=per_request, follow_redirects=True, trust_env=False
            ) as client:
                # Stream + headers only: TTFB is the time to response
                # headers, and never reading the body means a
                # slow-drip body cannot stretch the probe.
                # (response.elapsed is only readable after the
                # response is read/closed, so time the stream entry
                # with the monotonic clock instead.)
                t0 = time.monotonic()
                with client.stream("GET", url) as response:
                    status = response.status_code
                    ttfb_ms = int((time.monotonic() - t0) * 1000)
        except Exception as exc:  # noqa: BLE001 - probe failure is data
            return {
                "url": url,
                "ok": False,
                "ttfb_ms": None,
                "status": None,
                "error": f"direct request failed: {exc}",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        return {
            "url": url,
            "ok": True,
            "ttfb_ms": ttfb_ms,
            "status": status,
            "error": None,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }

    finished, result = _run_with_deadline(
        _fetch, _remaining(deadline)
    )
    if finished and result is not None:
        return result
    return {
        "url": url,
        "ok": False,
        "ttfb_ms": None,
        "status": None,
        "error": (
            f"direct request timed out: total deadline of {timeout:g}s "
            "exceeded"
        ),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


def _socks5_connect(
    sock: socket.socket,
    host: str,
    port: int,
    username: str = "",
    password: str = "",
    deadline: float | None = None,
) -> None:
    """SOCKS5 handshake + CONNECT to ``host:port`` (remote DNS).

    Raises :class:`OSError` / :class:`ValueError` on failure, and
    :class:`_ProbeTimeout` when the total deadline (if given) is hit.
    Every recv is bounded by min(stage timeout, total remaining).
    """

    def recv_exact(n: int) -> bytes:
        chunks = b""
        while len(chunks) < n:
            if deadline is not None:
                _check_deadline(deadline)
                sock.settimeout(
                    _stage_timeout(_IO_TIMEOUT_S, deadline)
                )
            chunk = sock.recv(n - len(chunks))
            if not chunk:
                raise OSError("SOCKS5 proxy closed the connection")
            chunks += chunk
        return chunks

    if deadline is not None:
        _check_deadline(deadline)
        sock.settimeout(_stage_timeout(_IO_TIMEOUT_S, deadline))
    if username:
        # Offer no-auth (0x00) and user/pass (0x02); the server picks.
        sock.sendall(bytes([0x05, 0x02, 0x00, 0x02]))
    else:
        sock.sendall(bytes([0x05, 0x01, 0x00]))
    version, method = recv_exact(2)
    if version != 0x05:
        raise ValueError(f"unexpected SOCKS version: {version}")
    if method == 0xFF:
        raise ValueError("SOCKS5 proxy accepts no offered auth method")
    if method == 0x02:
        user = username.encode("utf-8")
        pw = password.encode("utf-8")
        sock.sendall(
            bytes([0x01, len(user)]) + user + bytes([len(pw)]) + pw
        )
        _, status = recv_exact(2)
        if status != 0x00:
            raise ValueError("SOCKS5 username/password auth failed")
    elif method != 0x00:
        raise ValueError(f"unsupported SOCKS5 auth method: {method:#x}")

    # CONNECT, address type 0x03 (domain name) so the proxy resolves it.
    host_bytes = host.encode("utf-8")
    request = (
        bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)])
        + host_bytes
        + port.to_bytes(2, "big")
    )
    sock.sendall(request)
    _, reply, _, addr_type = recv_exact(4)
    if reply != 0x00:
        raise OSError(f"SOCKS5 CONNECT failed (reply code {reply:#x})")
    if addr_type == 0x01:  # IPv4
        recv_exact(4 + 2)
    elif addr_type == 0x03:  # domain name
        recv_exact(recv_exact(1)[0] + 2)
    elif addr_type == 0x04:  # IPv6
        recv_exact(16 + 2)
    else:
        raise ValueError(f"unexpected SOCKS5 address type: {addr_type:#x}")


def probe_via_socks5(
    url: str,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 7890,
    username: str = "",
    password: str = "",
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """HTTPS GET through a SOCKS5 proxy; returns first-byte timing."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    started = time.monotonic()
    deadline = _deadline(timeout)
    context = ssl.create_default_context()
    try:
        raw = socket.create_connection(
            (proxy_host, proxy_port),
            timeout=_stage_timeout(_CONNECT_TIMEOUT_S, deadline),
        )
        raw.settimeout(_stage_timeout(_IO_TIMEOUT_S, deadline))
        try:
            _socks5_connect(
                raw, host, port, username, password, deadline=deadline
            )
            _check_deadline(deadline)
            tls_sock = context.wrap_socket(raw, server_hostname=host)
            try:
                tls_sock.settimeout(
                    _stage_timeout(_IO_TIMEOUT_S, deadline)
                )
                tls_sock.sendall(
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: lanmux-link-check\r\n"
                    "Connection: close\r\n\r\n".encode("utf-8")
                )
                _check_deadline(deadline)
                tls_sock.settimeout(
                    _stage_timeout(_IO_TIMEOUT_S, deadline)
                )
                first = tls_sock.recv(4096)
            finally:
                tls_sock.close()
        except Exception:
            raw.close()
            raise
    except _ProbeTimeout:
        return {
            "url": url,
            "ok": False,
            "ttfb_ms": None,
            "status": None,
            "error": (
                f"proxied request timed out: total deadline of "
                f"{timeout:g}s exceeded"
            ),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
    except Exception as exc:  # noqa: BLE001 - probe failure is data
        return {
            "url": url,
            "ok": False,
            "ttfb_ms": None,
            "status": None,
            "error": f"proxied request failed: {exc}",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
    ttfb_ms = int((time.monotonic() - started) * 1000)
    status = None
    if first.startswith(b"HTTP/"):
        try:
            status = int(first.split(b" ", 2)[1])
        except (IndexError, ValueError):
            status = None
    return {
        "url": url,
        "ok": bool(first),
        "ttfb_ms": ttfb_ms if first else None,
        "status": status,
        "error": None if first else "empty response from target",
        "elapsed_ms": ttfb_ms,
    }
