"""Status + link diagnostics routes.

All endpoints degrade gracefully when mihomo is unreachable — they
report ``running: false`` / per-probe errors instead of returning 500.

* ``GET /status`` — mihomo version, running state, active connections,
  traffic rates, and config-drift info from the last apply.
* ``POST /link-check`` — first-byte probes: baidu.com DIRECT and
  youtube.com via the Mixed listener (SOCKS5, remote DNS). The DIRECT
  probe still runs when mihomo is down; the proxied probe reports a
  clear error instead. The two probes run in parallel (L-45) under a
  total deadline, behind the probe guard (M-31: max 2 concurrent
  probe tasks, same-target dedup within 5s, per-IP rate limit).
* ``POST /route-check`` — route diagnosis, with a ``connection``
  state (direct / connected / unreachable / unknown). Drift-aware
  (M-13): a drifted config is annotated, never silently trusted.
* ``POST /exit-ip`` — manual-only exit-IP probe through the Mixed
  SOCKS5 listener; reports which group the probe actually travelled.
  Errors are mapped to categories, never raw exception text (L-17).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import time
import urllib.parse

from fastapi import APIRouter, Depends, HTTPException, Request

from .. import probes
from ..auth import require_auth
from ..config_builder import (
    dead_group_keys,
    default_unbound_with_nodes,
)
from ..config_service import ConfigService
from ..database import Database
from ..deps import apply_and_report, get_config_service, get_db, get_mihomo_client
from ..mihomo_client import MihomoClient, MihomoError
from ..models import RouteCheckRequest, Settings
from ..probe_guard import ProbeBusyError, probe_guard
from ..route_check import check_route, normalize_domain

router = APIRouter(
    prefix="/api/diagnostics",
    tags=["diagnostics"],
    dependencies=[Depends(require_auth)],
)

DIRECT_PROBE_URL = "https://www.baidu.com"
PROXIED_PROBE_URL = "https://www.youtube.com"

# IP echo services for /exit-ip (primary, then fallback). Only ever
# fetched on a manual user action — never by any background job.
IPIFY_URL = "https://api.ipify.org?format=json"
IFCONFIG_URL = "https://ifconfig.me/ip"
EXIT_IP_TIMEOUT = 10.0
# M-33: never read more than this from an echo service — a malicious
# or broken echo endpoint must not be able to grow memory unbounded.
MAX_ECHO_BYTES = 64 * 1024
# L-45: total wall-clock budget for the whole link-check (both probes
# run in parallel, each capped at its own 10s probe timeout).
LINK_CHECK_TOTAL_DEADLINE_S = 25.0

# L-17: probe errors are mapped to stable categories. Raw exception
# text (errno strings, hostnames, partial responses) never leaves
# the API — the panel shows the category, the log keeps the detail.
_ERROR_DESCRIPTIONS: dict[str, str] = {
    "connection_refused": "连接被拒绝",
    "timeout": "连接超时（超过总时限）",
    "dns_failure": "域名解析失败",
    "unreachable": "目标网络不可达",
    "response_too_large": "回显响应超过 64KB 上限",
    "invalid_response": "回显服务返回异常",
    "probe_failed": "探测失败",
}


def _sanitize_probe_error(raw: str | None) -> str:
    """Map a raw probe error to a stable error category (L-17)."""
    text = (raw or "").lower()
    if "connection refused" in text or "errno 111" in text:
        return "connection_refused"
    if "timed out" in text or "timeout" in text or "deadline" in text:
        return "timeout"
    if (
        "name or service not known" in text
        or "getaddrinfo" in text
        or "nodename nor servname" in text
        or "temporary failure in name resolution" in text
    ):
        return "dns_failure"
    if "network is unreachable" in text or "unreachable" in text:
        return "unreachable"
    if "exceeded" in text and "64kb" in text:
        return "response_too_large"
    if (
        "invalid json" in text
        or "invalid ip" in text
        or "unreadable response" in text
        or "returned http" in text
    ):
        return "invalid_response"
    return "probe_failed"


def _client_id(request: Request) -> str:
    if request.client is not None:
        return request.client.host or "unknown"
    return "unknown"


def _check_probe_rate(request: Request) -> None:
    if not probe_guard.check_rate(_client_id(request)):
        raise HTTPException(
            status_code=429,
            detail="too many probe requests; try again in a minute",
        )


def _drift_info(db: Database) -> dict[str, object]:
    def _revision(key: str) -> int:
        try:
            return int(db.get_setting(key, "0") or "0")
        except (TypeError, ValueError):
            return 0

    db_revision = _revision("config_revision_db")
    running_revision = _revision("config_revision_running")
    return {
        "config_drift": db_revision > running_revision,
        "db_revision": db_revision,
        "running_revision": running_revision,
    }


def _decode_chunked(body: bytes) -> bytes:
    """Decode a chunked HTTP body; pass through anything malformed."""
    out = bytearray()
    rest = body
    while rest:
        line, sep, rest = rest.partition(b"\r\n")
        if not sep:
            return bytes(out) + rest
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            return bytes(out) + body
        if size == 0:
            return bytes(out)
        out += rest[:size]
        rest = rest[size:]
        if rest.startswith(b"\r\n"):
            rest = rest[2:]
    return bytes(out)


def _fetch_via_socks5(
    url: str, settings: Settings, timeout: float = EXIT_IP_TIMEOUT
) -> tuple[str | None, str | None]:
    """GET ``url`` through the Mixed SOCKS5 listener; return (ip, error).

    Reuses :func:`app.probes._socks5_connect` (same handshake as
    :func:`app.probes.probe_via_socks5`, which only reports timing),
    then reads the response body — the echo service's IP. Never
    raises; failures are returned as ``(None, error)``.

    ``timeout`` is a total deadline (M-32, monotonic clock; each
    stage takes min(stage timeout, remaining)), and at most
    :data:`MAX_ECHO_BYTES` are read (M-33) — over that, the read is
    aborted and an error is returned instead of the IP.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    context = ssl.create_default_context()
    started = time.monotonic()
    deadline = started + max(0.0, timeout)
    try:
        raw = socket.create_connection(
            ("127.0.0.1", settings.mixed_port),
            timeout=min(5.0, max(0.05, deadline - time.monotonic())),
        )
        raw.settimeout(5.0)
        try:
            probes._socks5_connect(
                raw,
                host,
                port,
                settings.mixed_auth_user,
                settings.mixed_auth_pass,
                deadline=deadline,
            )
            tls_sock = context.wrap_socket(raw, server_hostname=host)
            try:
                tls_sock.settimeout(5.0)
                tls_sock.sendall(
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: lanmux-exit-ip\r\n"
                    "Accept: */*\r\n"
                    "Connection: close\r\n\r\n".encode("utf-8")
                )
                chunks: list[bytes] = []
                total = 0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return (
                            None,
                            f"proxied request to {url} failed: "
                            "total deadline exceeded",
                        )
                    tls_sock.settimeout(min(5.0, remaining))
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ECHO_BYTES:
                        return (
                            None,
                            f"echo service {url} response exceeded "
                            "64KB limit",
                        )
                    chunks.append(chunk)
            finally:
                tls_sock.close()
        except Exception:
            raw.close()
            raise
    except Exception as exc:  # noqa: BLE001 - probe failure is data
        return None, f"proxied request to {url} failed: {exc}"
    raw_response = b"".join(chunks)
    head, sep, body = raw_response.partition(b"\r\n\r\n")
    if not sep:
        return None, f"echo service {url} returned an unreadable response"
    status = None
    try:
        status = int(head.split(b" ", 2)[1])
    except (IndexError, ValueError):
        pass
    if status != 200:
        return None, f"echo service {url} returned HTTP {status}"
    if b"transfer-encoding: chunked" in head.lower():
        body = _decode_chunked(body)
    text = body.decode("utf-8", errors="ignore").strip()
    if "api.ipify.org" in host:
        try:
            ip = str(json.loads(text).get("ip") or "").strip()
        except (ValueError, AttributeError):
            return None, (
                f"echo service {url} returned invalid JSON: {text[:80]!r}"
            )
    else:
        ip = text.split()[0] if text.split() else ""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None, f"echo service {url} returned an invalid IP: {ip[:80]!r}"
    return ip, None


def _fetch_exit_ip(
    settings: Settings,
) -> tuple[str | None, str | None, str]:
    """Try ipify, then ifconfig.me; return (ip, error, via_domain).

    ``via_domain`` is the echo service that actually produced the IP
    (``api.ipify.org`` when both fail, i.e. the primary attempt).
    The raw error is kept internally (the endpoint sanitizes it
    before responding, L-17).
    """
    last_error: str | None = None
    for url, domain in (
        (IPIFY_URL, "api.ipify.org"),
        (IFCONFIG_URL, "ifconfig.me"),
    ):
        ip, error = _fetch_via_socks5(url, settings)
        if ip is not None:
            return ip, None, domain
        last_error = error
    return None, last_error or "echo service request failed", "api.ipify.org"


def _revision(db: Database, key: str) -> int:
    try:
        return int(db.get_setting(key, "0") or "0")
    except (TypeError, ValueError):
        return 0


def _flag(db: Database, key: str) -> bool:
    try:
        return (db.get_setting(key, "0") or "0") == "1"
    except Exception:
        return False


def _config_freshness(db: Database) -> dict:
    """Config source / freshness annotation (L-30).

    The preview and status endpoints must never present DB-derived
    data as if it were the running config: the annotation says
    where the data comes from and whether mihomo is actually
    running it.
    """
    db_revision = _revision(db, "config_revision_db")
    running_revision = _revision(db, "config_revision_running")
    last_apply_ok = db.get_setting("last_apply_ok", "1") == "1"
    drift_flag = _flag(db, "config_drift_flag")
    restart_pending = _flag(db, "config_restart_pending")
    unreachable = _flag(db, "controller_unreachable")
    drift = db_revision > running_revision or drift_flag
    if restart_pending:
        state = "restart_pending"
        freshness = "pending_restart"
        note = (
            "新配置已写入磁盘（基于数据库），待重启 mihomo 后生效；"
            "运行中的 mihomo 仍在使用旧配置"
        )
    elif drift:
        state = "drift"
        freshness = "stale"
        note = "基于数据库，未应用到 mihomo；运行中的仍是旧配置"
    elif unreachable:
        state = "controller_unreachable"
        freshness = "unknown"
        note = "控制器不可达，运行态未知；显示的是数据库状态"
    elif db_revision == running_revision and last_apply_ok:
        state = "running"
        freshness = "current"
        note = "与运行配置一致（基于数据库，与 mihomo 运行态一致）"
    else:
        state = "error"
        freshness = "stale"
        note = "上次应用失败，运行配置可能不是最新；见上次报错"
    try:
        restart_reason = db.get_setting("config_restart_reason") or None
    except Exception:
        restart_reason = None
    return {
        "db_revision": db_revision,
        "running_revision": running_revision,
        "drift": drift,
        "drift_flag": drift_flag,
        "controller_unreachable": unreachable,
        "restart_pending": restart_pending,
        "restart_reason": restart_reason,
        "state": state,
        "source": "database",
        "freshness": freshness,
        "note": note,
        "in_sync": db_revision == running_revision
        and last_apply_ok
        and not drift
        and not restart_pending,
    }


@router.get("/status")
def status(
    db: Database = Depends(get_db),
    client: MihomoClient = Depends(get_mihomo_client),
    service: ConfigService = Depends(get_config_service),
):
    freshness = _config_freshness(db)
    last_apply_ok = db.get_setting("last_apply_ok", "1") == "1"
    # H-03/H-04 panel signals: groups bound to nothing but dead nodes
    # (compiled to REJECT), and the fail-open Default state (apply
    # refused until Default is bound). The panel turns these into a
    # strong warning banner + per-group REJECT badges.
    nodes = db.list_nodes()
    bindings = db.list_bindings()
    dead_groups = dead_group_keys(nodes, bindings)
    default_unbound = default_unbound_with_nodes(nodes, bindings)
    result: dict = {
        "mihomo": {"running": False, "version": None, "error": None},
        "connections": {"count": None},
        "traffic": {"up": None, "down": None},
        "config": {
            **freshness,
            "last_apply_stage": db.get_setting("last_apply_stage") or "",
            "exists": service.read_config_text() is not None,
            "last_apply_at": db.get_setting("last_apply_at"),
            "last_apply_error": db.get_setting("last_apply_error") or None,
            "dead_groups": dead_groups,
            "default_unbound": default_unbound,
        },
    }
    try:
        version = client.get_version()
    except MihomoError as exc:
        result["mihomo"]["error"] = exc.message
        return result
    result["mihomo"]["running"] = True
    result["mihomo"]["version"] = version.get("version")
    try:
        connections = client.get_connections()
        result["connections"]["count"] = len(
            connections.get("connections", []) or []
        )
    except MihomoError as exc:
        result["connections"]["error"] = exc.message
    try:
        traffic = client.get_traffic()
        result["traffic"]["up"] = traffic.get("up")
        result["traffic"]["down"] = traffic.get("down")
    except MihomoError as exc:
        result["traffic"]["error"] = exc.message
    return result


@router.post("/link-check")
async def link_check(request: Request, db: Database = Depends(get_db)):
    """First-byte probes, DIRECT vs proxied, run in parallel (L-45).

    Guarded by the probe guard (M-31): per-IP rate limit, at most 2
    concurrent probe tasks, and a 5s same-target dedup. Errors are
    sanitized to categories (L-17); drift is annotated (M-13).
    """
    _check_probe_rate(request)
    settings = db.get_settings()
    cache_key = f"link-check:{settings.mixed_port}"
    cached = probe_guard.get_cached(cache_key)
    if cached is not None:
        return {**cached, "cached": True}
    try:
        with probe_guard.run_probe():
            try:
                direct, proxied = await asyncio.wait_for(
                    asyncio.gather(
                        asyncio.to_thread(
                            probes.probe_direct, DIRECT_PROBE_URL
                        ),
                        asyncio.to_thread(
                            probes.probe_via_socks5,
                            PROXIED_PROBE_URL,
                            proxy_host="127.0.0.1",
                            proxy_port=settings.mixed_port,
                            username=settings.mixed_auth_user,
                            password=settings.mixed_auth_pass,
                        ),
                    ),
                    timeout=LINK_CHECK_TOTAL_DEADLINE_S,
                )
            except TimeoutError:
                error = "timeout"
                direct = {
                    "url": DIRECT_PROBE_URL,
                    "ok": False,
                    "ttfb_ms": None,
                    "status": None,
                    "error": error,
                    "elapsed_ms": int(LINK_CHECK_TOTAL_DEADLINE_S * 1000),
                }
                proxied = {
                    "url": PROXIED_PROBE_URL,
                    "ok": False,
                    "ttfb_ms": None,
                    "status": None,
                    "error": error,
                    "elapsed_ms": int(LINK_CHECK_TOTAL_DEADLINE_S * 1000),
                }
    except ProbeBusyError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    # Sanitize probe errors to categories before responding (L-17).
    for probe in (direct, proxied):
        if probe.get("error"):
            probe["error"] = _sanitize_probe_error(probe["error"])
    if not proxied["ok"] and proxied.get("error"):
        # Make the common case (mihomo not running) obvious.
        proxied["hint"] = (
            "the proxied probe goes through the Mixed listener on port "
            f"{settings.mixed_port}; if mihomo is not running it fails "
            "while the DIRECT probe still succeeds"
        )
    result: dict = {
        "direct": direct,
        "proxied": proxied,
        "cached": False,
        **_drift_info(db),
    }
    probe_guard.put_cached(cache_key, result)
    return result


@router.post("/route-check")
def route_check(
    body: RouteCheckRequest,
    db: Database = Depends(get_db),
    client: MihomoClient = Depends(get_mihomo_client),
):
    """Explain where a domain goes: matched rule, group, exit node.

    Matches the domain against the same ordered rules the config
    compiler emits; the current node comes from mihomo's live group
    state when reachable, otherwise from DB probe-state inference.
    A down mihomo degrades to inference, never a 500. Drift is
    annotated on the result (M-13); see :func:`app.route_check.
    check_route` for the forced-rule / IP-CIDR model (M-09, M-10).
    """
    try:
        domain = normalize_domain(body.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return check_route(db, client, domain)


@router.post("/exit-ip")
def exit_ip(
    request: Request,
    body: RouteCheckRequest,
    db: Database = Depends(get_db),
    client: MihomoClient = Depends(get_mihomo_client),
):
    """Fetch the exit IP for a domain's group via the Mixed listener.

    Manual-only probe (the panel calls it from a button; nothing
    triggers it in the background). Runs :func:`check_route` for the
    domain, fetches an IP echo service through the Mixed SOCKS5
    listener, then runs :func:`check_route` for the echo service's
    domain to report which group the probe actually travelled
    (``via_group`` / ``via_node``). A failed probe returns HTTP 200
    with ``ip`` null and ``error`` set — an IP is never fabricated.
    The error is a sanitized category, never raw exception text
    (L-17). Guarded like link-check (M-31).
    """
    _check_probe_rate(request)
    try:
        domain = normalize_domain(body.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    cache_key = f"exit-ip:{domain}"
    cached = probe_guard.get_cached(cache_key)
    if cached is not None:
        return {**cached, "cached": True}
    result = check_route(db, client, domain)
    # Diagnosed group/current: the matched group, or the Default group
    # for an unmatched domain (its downstream path). DIRECT / REJECT /
    # unknown targets have no group.
    if result["matched"] and result.get("group") is not None:
        group = result["group"]
        current = result["current"]
    elif not result["matched"] and result.get("default_group"):
        group = result["default_group"]["group"]
        current = result["default_group"]["current"]
    else:
        group = None
        current = None

    settings = db.get_settings()
    try:
        with probe_guard.run_probe():
            ip, raw_error, via_domain = _fetch_exit_ip(settings)
    except ProbeBusyError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    via = check_route(db, client, via_domain)
    if via["matched"] and via.get("group") is not None:
        via_group = via["group"]
        via_current = via["current"]
    elif not via["matched"] and via.get("default_group"):
        via_group = via["default_group"]["group"]
        via_current = via["default_group"]["current"]
    else:
        via_group = None
        via_current = None
    via_node = (
        via_current["name"] if isinstance(via_current, dict) else None
    )

    # L-17: only the category leaves the API.
    error = _sanitize_probe_error(raw_error) if raw_error else None
    drift_suffix = ""
    if result.get("config_drift"):
        drift_suffix = (
            " 本次诊断基于过期配置，仅供参考，请先重新应用配置。"
        )
    if ip is None:
        note = (
            "出口 IP 探测失败，未返回任何 IP（未伪造）。"
            f"原因：{_ERROR_DESCRIPTIONS.get(error or '', '探测失败')}。"
            "请确认 mihomo 正在运行且 Mixed 入口"
            f"（127.0.0.1:{settings.mixed_port}）可达，然后重试。"
            + drift_suffix
        )
    elif group is None:
        note = (
            f"注意：诊断域名走 DIRECT（无代理组），本次探测实际走的是 "
            f"{via_group or '未知'} 组"
            f"{'（出口节点：' + via_node + '）' if via_node else ''}；"
            f"{ip} 是 {via_group or '未知'} 组的出口 IP，"
            "不是该域名的出口 IP。"
            + drift_suffix
        )
    elif via_group == group:
        note = (
            f"本次探测实际走的是 {via_group} 组，与诊断的 {group} 组一致，"
            f"因此 {ip} 就是 {group} 组的出口 IP"
            f"{'（出口节点：' + via_node + '）' if via_node else ''}。"
            + drift_suffix
        )
    else:
        note = (
            f"注意：本次探测实际走的是 {via_group or '未知'} 组"
            f"{'（出口节点：' + via_node + '）' if via_node else ''}，"
            f"不是诊断组 {group} 的出口 IP；"
            f"{ip} 是 {via_group or '未知'} 组的出口 IP，"
            f"不能当作 {group} 组的出口 IP。"
            + drift_suffix
        )
    response = {
        "domain": domain,
        "group": group,
        "current": current,
        "ip": ip,
        "via_group": via_group,
        "via_node": via_node,
        "error": error,
        "note": note,
        "cached": False,
        "config_drift": bool(result.get("config_drift")),
        "db_revision": result.get("db_revision"),
        "running_revision": result.get("running_revision"),
    }
    probe_guard.put_cached(cache_key, response)
    return response


@router.get("/config-preview")
def config_preview(
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    freshness = _config_freshness(db)
    masked = service.read_masked_config_text()
    if masked is None:
        return {
            "exists": False,
            "config": None,
            "message": "no config has been generated yet — add a node or"
            " change a setting to trigger the first apply",
            "source": "none",
            "freshness": "none",
            "note": "尚未生成任何配置",
        }
    # The preview shows the on-disk file, not the running config:
    # say so, and say whether the disk file matches what mihomo runs.
    if freshness["restart_pending"]:
        note = (
            "磁盘上的 config.yaml（脱敏后）；这是待重启的新配置，"
            "运行中的 mihomo 仍在使用旧配置"
        )
    elif freshness["drift"]:
        note = "磁盘上的 config.yaml（脱敏后）；数据库已有更新未应用"
    elif freshness["controller_unreachable"]:
        note = (
            "磁盘上的 config.yaml（脱敏后）；控制器不可达，"
            "无法确认运行中的配置是否与此一致"
        )
    else:
        note = "磁盘上的 config.yaml（脱敏后）；与运行配置一致"
    return {
        "exists": True,
        "config": masked,
        "message": None,
        "source": "disk: config.yaml",
        "freshness": freshness["freshness"],
        "note": note,
    }

@router.post("/confirm-restart")
def confirm_restart(
    service: ConfigService = Depends(get_config_service),
):
    """Confirm a pending mihomo restart took effect (H-05/H-06).

    Call after restarting mihomo following a Secret / controller
    port change. Probes the controller with the new secret/port;
    success clears the restart-pending state and marks the config
    running, failure keeps the pending state.
    """
    return service.confirm_restart()

@router.post("/reapply")
def reapply(
    service: ConfigService = Depends(get_config_service),
):
    """Manually recompile and hot-reload mihomo config (recover from drift)."""
    return {"reload": apply_and_report(service)}
