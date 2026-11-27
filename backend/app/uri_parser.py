"""Multi-protocol node URI parser -> mihomo ``proxies`` dicts.

Supported schemes
-----------------
``vless://``
    Reality / XTLS-Vision / WS / gRPC parameters.
``vmess://``
    Standard Base64 JSON, tolerates missing ``=`` padding.
``ss://``
    SIP002 (``ss://base64(method:password)@host:port``) and legacy
    Base64 (``ss://base64(method:password@host:port)``), with ``plugin``
    query support (obfs-local / v2ray-plugin).
``trojan://``
    With optional SNI / ALPN / WS / gRPC parameters.
``hysteria2://`` / ``hy2://``
    With salamander obfs, ``insecure`` and SNI parameters.
``tuic://``
    ``uuid:password`` userinfo, congestion control / UDP relay mode.

:func:`parse_uri` returns a complete mihomo proxy dict including the
``name`` key (taken from the URI fragment, or a ``<type>-<host>``
fallback). Malformed input raises :class:`ValueError` with a clear
message; nothing is silently guessed.

Shared validation (H-11 / M-15 / M-34)
--------------------------------------
:func:`validate_proxy_dict` is the single shared validator for a
mihomo proxy dict, used by the node PUT endpoint and by the import
path alike (and by the config compiler's ``validate_config_dict`` —
see M-34). It enforces the type whitelist, port range 1-65535, UUID
format, required per-type fields and cipher whitelists, and returns
a normalized copy (``hy2`` -> ``hysteria2``, port coerced to ``int``,
missing VMess defaults filled). It raises :class:`ValueError` on the
first problem; callers turn that into HTTP 400.

Cross-protocol rules (documented here so every parser agrees)
-------------------------------------------------------------
* Empty fields (L-05): an empty-string value is treated as **absent**
  and the protocol default applies (e.g. empty ``type`` -> ``tcp``,
  empty ``tls`` -> no TLS). A *required* field that is empty or
  missing is **rejected** (missing UUID / host / port / password /
  cipher). The two cases are never mixed within one field.
* Duplicate query parameters (M-22 / L-10): **last value wins**,
  and the duplicate is reported as a warning (see
  :func:`parse_uri_with_warnings`).
* Unknown query parameters (M-22): ignored, and reported as a
  warning in the import result — never silently swallowed without a
  trace, never fatal.
* Parameter names (L-07): matched case-insensitively — query keys
  are lowercased before matching, so ``SNI`` and ``sni`` are the
  same parameter. Values keep their original case.
* Base64 (L-09): one decoder for every protocol — missing ``=``
  padding is auto-completed and both the standard (``+/``) and the
  URL-safe (``-_``) alphabets are accepted.
* Names (L-13 / L-14): a node name is at most
  :data:`MAX_NODE_NAME_LEN` characters; longer names are truncated
  (with a warning) and an empty name gets the fallback
  ``node-<shortid>`` (with a warning). Import-time duplicates are
  resolved by the config compiler's final-name-set loop (H-10),
  which never emits a name that already exists.
* Per-protocol default fill (L-11) — applied identically by the
  parsers and by :func:`validate_proxy_dict`:

  ==================  ============================================
  protocol            defaults filled when the field is absent
  ==================  ============================================
  vless               ``network`` -> ``"tcp"``
  vmess               ``cipher`` -> ``"auto"``, ``alterId`` -> ``0``,
                      ``tls`` -> ``False``, ``network`` -> ``"tcp"``
  ss                  (none — cipher/password are required)
  trojan              ``network`` -> ``"tcp"`` (only emitted when
                      non-tcp)
  hysteria2 / tuic    (none — password/uuid are required)
  ==================  ============================================

  Fields that are absent are equivalent to their default at
  compile time; the compiler additionally fills a missing proxy
  ``type`` with ``"ss"`` for legacy rows (see
  ``config_builder.build_config``).

Limitations (documented, not bugs)
---------------------------------
* Trojan passwords containing a literal ``@`` must be percent-encoded
  (``%40``); an unencoded ``@`` ends the userinfo by URI definition.
* Hysteria2 userinfo is the password; in the rare ``user:password``
  form the part after the first ``:`` is used as the password.
* A ``flow`` value (e.g. XTLS-Vision) is passed through as-is; mihomo
  itself validates flow/network combinations at config load.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import secrets
import urllib.parse
import uuid
from typing import Any

SUPPORTED_SCHEMES = ("vless", "vmess", "ss", "trojan", "hysteria2", "hy2", "tuic")

#: Proxy ``type`` values mihomo accepts from this codebase. ``hy2``
#: is accepted as an alias and normalized to ``hysteria2``.
SUPPORTED_PROXY_TYPES = ("vless", "vmess", "ss", "trojan", "hysteria2", "tuic")

#: Maximum node-name length (L-13). Longer names are truncated.
MAX_NODE_NAME_LEN = 64

#: Ciphers mihomo accepts for Shadowsocks (``2022-blake3-*`` included).
SS_CIPHERS = frozenset({
    "aes-128-gcm", "aes-256-gcm",
    "aes-128-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-256-cfb",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "chacha20-ietf", "xchacha20",
    "rc4-md5",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
})

#: Ciphers mihomo accepts for VMess.
VMESS_CIPHERS = frozenset({
    "auto", "aes-128-gcm", "chacha20-poly1305", "none",
})

#: Networks accepted for vless/vmess/trojan proxy dicts.
PROXY_NETWORKS = frozenset({"tcp", "ws", "grpc", "h2", "http"})

#: Query keys whose values are credentials and must never be echoed.
_SENSITIVE_QUERY_KEYS = frozenset({
    "password", "uuid", "psw", "token", "secret",
    "pbk", "sid", "obfs-password", "key",
})

#: Known query parameters per scheme (lowercased keys). Anything else
#: is reported as an "unknown parameter" warning (M-22).
_KNOWN_QUERY_PARAMS: dict[str, frozenset[str]] = {
    "vless": frozenset({
        "type", "security", "encryption", "sni", "alpn", "fp", "flow",
        "path", "host", "servicename", "pbk", "sid", "headertype", "mode",
    }),
    "trojan": frozenset({
        "sni", "alpn", "allowinsecure", "type", "path", "host",
        "servicename", "security", "fp",
    }),
    "hysteria2": frozenset({
        "sni", "insecure", "obfs", "obfs-password", "alpn",
    }),
    "tuic": frozenset({
        "congestion_control", "congestion-control",
        "udp_relay_mode", "udp-relay-mode",
        "sni", "alpn", "allow_insecure", "allow-insecure",
    }),
    "ss": frozenset({"plugin", "uot", "group"}),
}

#: Known top-level keys of a VMess JSON payload.
_VMESS_KNOWN_KEYS = frozenset({
    "v", "ps", "add", "port", "id", "aid", "scy", "net", "type",
    "host", "path", "tls", "sni", "alpn", "fp", "security",
    "allowinsecure",
})

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


# ---------------------------------------------------------------- helpers
def _b64decode_to_bytes(data: str) -> bytes:
    """Base64 decode, tolerating missing ``=`` padding (L-09).

    Accepts both the standard (``+/``) and the URL-safe (``-_``)
    alphabets; stray whitespace is ignored. Anything else is rejected
    instead of silently skipped.
    """
    text = re.sub(r"\s+", "", data.strip())
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid Base64 payload: {data[:32]!r}") from exc


def _validate_port(value: object, kind: str) -> int:
    """Shared port check (H-11 / M-15 / L-08): int 1-65535.

    Accepts an ``int`` or a digit string (``"443"``); anything else —
    including booleans, floats and out-of-range values — is rejected.
    """
    if isinstance(value, bool):
        raise ValueError(f"{kind} has an invalid port: {value!r}")
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        raise ValueError(f"{kind} has an invalid port: {value!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"{kind} has an out-of-range port: {port}")
    return port


def _validate_uuid(value: object, kind: str) -> str:
    """Shared UUID check (M-15): must parse with :func:`uuid.UUID`.

    Returns the canonical (lowercase) form.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{kind} is missing the UUID")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError) as exc:
        raise ValueError(
            f"{kind} has an invalid UUID: {value!r}"
        ) from exc


def _validate_host(value: object, kind: str) -> str:
    """Shared host check (M-15): an IP literal or a DNS hostname.

    A single trailing dot (FQDN root) is stripped. Non-ASCII names
    are rejected — they must be supplied as punycode.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{kind} is missing a server address")
    host = value.strip()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise ValueError(f"{kind} is missing a server address")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _DOMAIN_RE.match(host):
        raise ValueError(f"{kind} has an invalid server address: {host!r}")
    return host


def _validate_cipher(
    cipher: object, kind: str, allowed: frozenset[str]
) -> str:
    """Shared cipher check (M-15): must be in the protocol whitelist."""
    if not isinstance(cipher, str) or not cipher.strip():
        raise ValueError(f"{kind} is missing the cipher")
    name = cipher.strip()
    if name not in allowed:
        raise ValueError(
            f"{kind} has an unsupported cipher: {name!r} "
            f"(supported: {', '.join(sorted(allowed))})"
        )
    return name


def _query_params(
    parsed: urllib.parse.ParseResult,
    known: frozenset[str] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, str]:
    """Query parameters, percent-decoded, keys lowercased (L-07).

    Duplicate keys: **last value wins** (M-22 / L-10), reported as a
    warning. Keys outside ``known`` (when given) are dropped and
    reported as "unknown parameter" warnings (M-22).
    """
    parsed_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params: dict[str, str] = {}
    for raw_key, values in parsed_qs.items():
        key = raw_key.strip().lower()
        if len(values) > 1 and warnings is not None:
            warnings.append(
                f"duplicate query parameter {raw_key!r} "
                "(kept last value)"
            )
        if known is not None and key not in known:
            if warnings is not None:
                warnings.append(
                    f"unknown query parameter {raw_key!r} ignored"
                )
            continue
        params[key] = values[-1]
    return params


def _query_params_from_string(
    query: str,
    known: frozenset[str] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, str]:
    """Same as :func:`_query_params` for a raw query string."""
    parsed = urllib.parse.ParseResult(
        scheme="", netloc="", path="", params="", query=query, fragment=""
    )
    return _query_params(parsed, known=known, warnings=warnings)


def _fragment_name(parsed: urllib.parse.ParseResult, fallback: str) -> str:
    if parsed.fragment:
        name = urllib.parse.unquote(parsed.fragment).strip()
        if name:
            return name
    return fallback


def normalize_node_name(
    name: object, *, warnings: list[str] | None = None
) -> str:
    """Apply the node-name rules (L-13 / L-14) to one name.

    Empty/blank -> ``node-<shortid>`` fallback; longer than
    :data:`MAX_NODE_NAME_LEN` -> truncated. Both cases append a
    human-readable notice to ``warnings`` when a list is given.
    """
    text = name.strip() if isinstance(name, str) else ""
    if not text:
        generated = f"node-{secrets.token_hex(4)}"
        if warnings is not None:
            warnings.append(
                f"empty node name, generated fallback {generated!r}"
            )
        return generated
    if len(text) > MAX_NODE_NAME_LEN:
        truncated = text[:MAX_NODE_NAME_LEN].rstrip()
        if warnings is not None:
            warnings.append(
                f"node name truncated to {MAX_NODE_NAME_LEN} characters"
            )
        return truncated
    return text


def mask_uri_for_log(uri: str) -> str:
    """Redact credentials from a node URI for error reporting (M-19).

    The userinfo (password / UUID) is replaced with ``***``; for
    schemes whose body itself carries credentials (VMess JSON and
    legacy SS Base64 payloads) the whole body is replaced with
    ``***``. Sensitive query values (``password``, ``uuid``, ``pbk``,
    ``sid``, …) are redacted too. The fragment (display name) is
    kept — it contains no credentials. URIs without a scheme are
    returned unchanged, and the result is capped at 200 characters.
    """
    if not isinstance(uri, str) or "://" not in uri:
        return uri
    scheme, _, rest = uri.partition("://")
    fragment = ""
    if "#" in rest:
        rest, _, fragment = rest.partition("#")
    query = ""
    if "?" in rest:
        rest, _, query = rest.partition("?")
    if "@" in rest:
        _, _, hostport = rest.rpartition("@")
        rest = "***@" + hostport
    elif rest:
        rest = "***"
    if query:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        masked = [
            (k, "***" if k.strip().lower() in _SENSITIVE_QUERY_KEYS else v)
            for k, v in pairs
        ]
        query = urllib.parse.urlencode(masked)
    out = f"{scheme}://{rest}"
    if query:
        out += f"?{query}"
    if fragment:
        out += f"#{fragment}"
    return out[:200] + ("…" if len(out) > 200 else "")


def _port(parsed: urllib.parse.ParseResult, kind: str) -> int:
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{kind} URI has an invalid port") from exc
    if port is None:
        raise ValueError(f"{kind} URI is missing a port")
    return _validate_port(port, kind)


def _split_hostport(hostport: str, kind: str) -> tuple[str, int]:
    """Split ``host:port`` / ``[ipv6]:port`` (used by the ss parser)."""
    tmp = urllib.parse.urlparse("//" + hostport)
    host = tmp.hostname
    if not host:
        raise ValueError(f"{kind} URI is missing a server address")
    host = _validate_host(host, kind)
    try:
        port = tmp.port
    except ValueError as exc:
        raise ValueError(f"{kind} URI has an invalid port: {hostport!r}") from exc
    if port is None:
        raise ValueError(f"{kind} URI is missing a port")
    return host, _validate_port(port, kind)


def _alpn_list(params: dict[str, str]) -> list[str] | None:
    raw = params.get("alpn", "")
    if not raw:
        return None
    values = [item.strip() for item in raw.split(",") if item.strip()]
    return values or None


def _ws_opts(params: dict[str, str]) -> dict:
    opts: dict = {}
    path = params.get("path", "")
    if path:
        opts["path"] = path
    host = params.get("host", "")
    if host:
        opts["headers"] = {"Host": host}
    return opts


def _grpc_opts(params: dict[str, str]) -> dict:
    # Query keys are lowercased by _query_params, so the camelCase
    # "serviceName" arrives as "servicename" (L-07).
    service = params.get("servicename", "")
    return {"grpc-service-name": service} if service else {}


# ------------------------------------------------------------------- vless
def _parse_vless(uri: str, warnings: list[str]) -> dict:
    parsed = urllib.parse.urlparse(uri)
    uuid_value = _validate_uuid(
        urllib.parse.unquote(parsed.username or ""), "vless URI"
    )
    host = _validate_host(parsed.hostname, "vless URI")
    port = _port(parsed, "vless")
    params = _query_params(parsed, _KNOWN_QUERY_PARAMS["vless"], warnings)

    proxy: dict = {
        "name": _fragment_name(parsed, f"vless-{host}"),
        "type": "vless",
        "server": host,
        "port": port,
        "uuid": uuid_value,
    }

    network = params.get("type", "tcp").lower() or "tcp"
    proxy["network"] = network
    if network == "ws":
        opts = _ws_opts(params)
        if opts:
            proxy["ws-opts"] = opts
    elif network == "grpc":
        opts = _grpc_opts(params)
        if opts:
            proxy["grpc-opts"] = opts

    flow = params.get("flow", "")
    if flow:
        proxy["flow"] = flow

    security = params.get("security", "").lower()
    if security == "tls":
        proxy["tls"] = True
        sni = params.get("sni", "")
        if sni:
            proxy["servername"] = sni
        alpn = _alpn_list(params)
        if alpn:
            proxy["alpn"] = alpn
        fingerprint = params.get("fp", "")
        if fingerprint:
            proxy["client-fingerprint"] = fingerprint
    elif security == "reality":
        proxy["tls"] = True
        sni = params.get("sni", "")
        if sni:
            proxy["servername"] = sni
        fingerprint = params.get("fp", "")
        if fingerprint:
            proxy["client-fingerprint"] = fingerprint
        reality_opts: dict = {}
        public_key = params.get("pbk", "")
        if public_key:
            reality_opts["public-key"] = public_key
        short_id = params.get("sid", "")
        if short_id:
            reality_opts["short-id"] = short_id
        if reality_opts:
            proxy["reality-opts"] = reality_opts
    return proxy


# ------------------------------------------------------------------- vmess
def _parse_vmess_tls(value: object) -> bool:
    """Interpret a VMess JSON ``tls`` field by its type (M-16).

    Boolean ``true`` enables TLS (it used to be stringified and
    compared to ``"tls"``, silently dropping TLS). Strings ``"tls"``
    and ``"reality"`` enable TLS with their original meaning;
    ``""`` / ``"false"`` / ``"none"`` / ``"0"`` disable it.
    Anything else — including numbers other than 0/1 — is rejected
    rather than guessed.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value == 1:
            return True
        if value == 0:
            return False
        raise ValueError(f"vmess URI has an unknown tls value: {value!r}")
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("", "false", "none", "no", "0"):
            return False
        if text in ("tls", "true", "yes", "1", "reality"):
            return True
        raise ValueError(f"vmess URI has an unknown tls value: {value!r}")
    raise ValueError(f"vmess URI has an unknown tls value: {value!r}")


def _parse_vmess(uri: str, warnings: list[str]) -> dict:
    body = uri.split("://", 1)[1]
    body = body.split("#", 1)[0].split("?", 1)[0]
    try:
        raw = _b64decode_to_bytes(body).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("vmess URI payload is not valid UTF-8 JSON") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("vmess URI payload is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("vmess URI payload must be a JSON object")
    for key in data:
        if key not in _VMESS_KNOWN_KEYS and warnings is not None:
            warnings.append(f"unknown vmess JSON field {key!r} ignored")

    host = _validate_host(data.get("add"), "vmess URI")
    uuid_value = _validate_uuid(data.get("id"), "vmess URI")
    try:
        port = _validate_port(data.get("port"), "vmess URI")
    except ValueError as exc:
        raise ValueError("vmess URI has an invalid port") from exc

    proxy: dict = {
        "name": data.get("ps") or f"vmess-{host}",
        "type": "vmess",
        "server": host,
        "port": port,
        "uuid": uuid_value,
    }
    aid_raw = data.get("aid", 0)
    if isinstance(aid_raw, bool):
        raise ValueError("vmess URI has an invalid alterId (aid)")
    if isinstance(aid_raw, int):
        alter_id = aid_raw
    elif isinstance(aid_raw, str) and aid_raw.strip().isdigit():
        alter_id = int(aid_raw.strip())
    else:
        raise ValueError("vmess URI has an invalid alterId (aid)")
    if alter_id < 0:
        raise ValueError("vmess URI has an invalid alterId (aid)")
    proxy["alterId"] = alter_id
    proxy["cipher"] = _validate_cipher(
        data.get("scy") or "auto", "vmess URI", VMESS_CIPHERS
    )

    tls = _parse_vmess_tls(data.get("tls", ""))
    proxy["tls"] = tls
    if tls:
        sni = data.get("sni", "")
        if sni:
            proxy["servername"] = sni
        alpn = data.get("alpn", "")
        if alpn:
            proxy["alpn"] = [a.strip() for a in str(alpn).split(",") if a.strip()]

    network = str(data.get("net", "tcp") or "tcp").lower()
    proxy["network"] = network
    path = data.get("path", "")
    ws_host = data.get("host", "")
    obfs_type = str(data.get("type", "") or "").lower()
    if network == "ws":
        opts: dict = {}
        if path:
            opts["path"] = path
        if ws_host:
            opts["headers"] = {"Host": ws_host}
        if opts:
            proxy["ws-opts"] = opts
    elif network == "h2":
        opts = {}
        if path:
            opts["path"] = path
        if ws_host:
            opts["headers"] = {"Host": ws_host}
        if opts:
            proxy["h2-opts"] = opts
    elif network == "grpc":
        if path:
            proxy["grpc-opts"] = {"grpc-service-name": path}
    elif network == "tcp" and obfs_type == "http":
        opts = {}
        if path:
            opts["path"] = [path]
        if ws_host:
            opts["headers"] = {"Host": [ws_host]}
        if opts:
            opts.setdefault("method", "GET")
            proxy["http-opts"] = opts
    return proxy


# ---------------------------------------------------------------------- ss
def _ss_userinfo(userinfo: str) -> tuple[str, str]:
    """Decode ``method:password`` from SIP002 userinfo.

    Tries Base64 first, then falls back to a literal
    ``method:password`` string (some clients skip the encoding).
    The password is UTF-8 text (M-17): non-ASCII passwords such as
    Chinese characters are accepted, there is no ASCII restriction.
    """
    raw = urllib.parse.unquote(userinfo)
    try:
        decoded = _b64decode_to_bytes(raw).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        decoded = ""
    if decoded and ":" in decoded:
        method, _, password = decoded.partition(":")
        if method and password:
            return method, password
    if ":" in raw:
        method, _, password = raw.partition(":")
        if method and password:
            return method, password
    raise ValueError("ss URI has malformed userinfo (expected method:password)")


def _parse_ss_plugin(params: dict[str, str]) -> tuple[str, dict]:
    """Parse the ``plugin`` query parameter into mihomo plugin/plugin-opts.

    Translates the common obfs option names (``obfs``/``obfs-host``) to
    mihomo's ``mode``/``host`` keys; anything else passes through.
    A leading ``;`` (and surrounding whitespace) is stripped first
    (M-18); if the first part is an option (``key=value``) rather than
    a plugin name, there is no plugin name — the parts are all options.
    """
    raw = params.get("plugin", "")
    if not raw:
        return "", {}
    raw = raw.strip().lstrip(";").strip()
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    if not parts:
        return "", {}
    opts: dict = {}
    first = parts[0]
    if "=" in first:
        plugin = ""
        option_parts = parts
    else:
        plugin = first
        option_parts = parts[1:]
    for part in option_parts:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        if key == "obfs":
            opts["mode"] = value.strip()
        elif key == "obfs-host":
            opts["host"] = value.strip()
        elif key == "obfs-path":
            opts["path"] = value.strip()
        else:
            opts[key] = value.strip()
    return plugin, opts


def _parse_ss(uri: str, warnings: list[str]) -> dict:
    parsed = urllib.parse.urlparse(uri)
    params = _query_params(parsed, _KNOWN_QUERY_PARAMS["ss"], warnings)
    # NOTE: do NOT use parsed.netloc here — a legacy Base64 payload may
    # contain '/', which urlparse treats as the start of the path and
    # would silently truncate the payload. Work on the raw body instead.
    body = uri.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0]
    if "@" in body:
        # SIP002: ss://base64(method:password)@host:port
        userinfo, _, hostport = body.rpartition("@")
        method, password = _ss_userinfo(userinfo)
        host, port = _split_hostport(hostport, "ss")
    else:
        # Legacy: ss://base64(method:password@host:port[/?plugin=...])
        try:
            decoded = _b64decode_to_bytes(body).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("ss URI payload is not valid UTF-8") from exc
        if "/?" in decoded:
            # Only "/?" starts the plugin query in a decoded legacy
            # payload ("method:password@host:port/?plugin=..."). A bare
            # "?" must NOT split here — it can legitimately occur inside
            # a password.
            decoded, _, query_string = decoded.partition("/?")
            extra = _query_params_from_string(
                query_string, _KNOWN_QUERY_PARAMS["ss"], warnings
            )
            params = {**extra, **params}
        if "@" not in decoded:
            raise ValueError(
                "ss URI is missing '@' (expected method:password@host:port)"
            )
        userinfo, _, hostport = decoded.rpartition("@")
        if ":" not in userinfo:
            raise ValueError(
                "ss URI is missing ':' (expected method:password@host:port)"
            )
        method, _, password = userinfo.partition(":")
        host, port = _split_hostport(hostport, "ss")
    if not method or not password:
        raise ValueError("ss URI is missing the method or password")
    method = _validate_cipher(method, "ss URI", SS_CIPHERS)

    proxy: dict = {
        "name": _fragment_name(parsed, f"ss-{host}"),
        "type": "ss",
        "server": host,
        "port": port,
        "cipher": method,
        "password": password,
    }
    plugin, plugin_opts = _parse_ss_plugin(params)
    if plugin:
        proxy["plugin"] = plugin
    if plugin_opts:
        proxy["plugin-opts"] = plugin_opts
    if uot := params.get("uot", ""):
        proxy["udp-over-tcp"] = uot == "1"
    return proxy


# ------------------------------------------------------------------ trojan
def _parse_trojan(uri: str, warnings: list[str]) -> dict:
    parsed = urllib.parse.urlparse(uri)
    userinfo = parsed.netloc.rpartition("@")[0]
    password = urllib.parse.unquote(userinfo)
    if not password:
        raise ValueError("trojan URI is missing the password")
    host = _validate_host(parsed.hostname, "trojan URI")
    port = _port(parsed, "trojan")
    params = _query_params(parsed, _KNOWN_QUERY_PARAMS["trojan"], warnings)

    proxy: dict = {
        "name": _fragment_name(parsed, f"trojan-{host}"),
        "type": "trojan",
        "server": host,
        "port": port,
        "password": password,
    }
    sni = params.get("sni", "")
    if sni:
        proxy["sni"] = sni
    alpn = _alpn_list(params)
    if alpn:
        proxy["alpn"] = alpn
    if params.get("allowinsecure", "") == "1":
        proxy["skip-cert-verify"] = True
    network = params.get("type", "tcp").lower() or "tcp"
    if network != "tcp":
        proxy["network"] = network
        if network == "ws":
            opts = _ws_opts(params)
            if opts:
                proxy["ws-opts"] = opts
        elif network == "grpc":
            opts = _grpc_opts(params)
            if opts:
                proxy["grpc-opts"] = opts
    return proxy


# -------------------------------------------------------------- hysteria2
def _parse_hysteria2(uri: str, warnings: list[str]) -> dict:
    parsed = urllib.parse.urlparse(uri)
    userinfo = urllib.parse.unquote(parsed.netloc.rpartition("@")[0])
    if not userinfo:
        raise ValueError("hysteria2 URI is missing the password")
    # Rare user:password form -> the part after the first ':' is the password.
    password = userinfo.partition(":")[2] if ":" in userinfo else userinfo
    if not password:
        raise ValueError("hysteria2 URI is missing the password")
    host = _validate_host(parsed.hostname, "hysteria2 URI")
    port = _port(parsed, "hysteria2")
    params = _query_params(parsed, _KNOWN_QUERY_PARAMS["hysteria2"], warnings)

    proxy: dict = {
        "name": _fragment_name(parsed, f"hysteria2-{host}"),
        "type": "hysteria2",
        "server": host,
        "port": port,
        "password": password,
    }
    sni = params.get("sni", "")
    if sni:
        proxy["sni"] = sni
    if params.get("insecure", "") == "1":
        proxy["skip-cert-verify"] = True
    obfs = params.get("obfs", "")
    if obfs:
        proxy["obfs"] = obfs
        obfs_password = params.get("obfs-password", "")
        if obfs_password:
            proxy["obfs-password"] = obfs_password
    alpn = _alpn_list(params)
    if alpn:
        proxy["alpn"] = alpn
    return proxy


# --------------------------------------------------------------------- tuic
def _parse_tuic(uri: str, warnings: list[str]) -> dict:
    parsed = urllib.parse.urlparse(uri)
    userinfo = urllib.parse.unquote(parsed.netloc.rpartition("@")[0])
    if ":" not in userinfo:
        raise ValueError(
            "tuic URI must use uuid:password userinfo"
            " (tuic://uuid:password@host:port)"
        )
    uuid_raw, _, password = userinfo.partition(":")
    if not uuid_raw or not password:
        raise ValueError("tuic URI is missing the UUID or password")
    uuid_value = _validate_uuid(uuid_raw, "tuic URI")
    host = _validate_host(parsed.hostname, "tuic URI")
    port = _port(parsed, "tuic")
    params = _query_params(parsed, _KNOWN_QUERY_PARAMS["tuic"], warnings)

    proxy: dict = {
        "name": _fragment_name(parsed, f"tuic-{host}"),
        "type": "tuic",
        "server": host,
        "port": port,
        "uuid": uuid_value,
        "password": password,
    }
    congestion = params.get("congestion_control", "") or params.get(
        "congestion-control", ""
    )
    if congestion:
        proxy["congestion-controller"] = congestion
    relay_mode = params.get("udp_relay_mode", "") or params.get(
        "udp-relay-mode", ""
    )
    if relay_mode:
        proxy["udp-relay-mode"] = relay_mode
    sni = params.get("sni", "")
    if sni:
        proxy["sni"] = sni
    alpn = _alpn_list(params)
    if alpn:
        proxy["alpn"] = alpn
    if params.get("allow_insecure", "") == "1" or params.get(
        "allow-insecure", ""
    ) == "1":
        proxy["skip-cert-verify"] = True
    return proxy


_HANDLERS = {
    "vless": _parse_vless,
    "vmess": _parse_vmess,
    "ss": _parse_ss,
    "trojan": _parse_trojan,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "tuic": _parse_tuic,
}


def parse_uri_with_warnings(uri: str) -> tuple[dict, list[str]]:
    """Parse one node URI, also returning non-fatal warnings.

    Warnings cover duplicate query parameters (last value kept),
    unknown query parameters / VMess JSON fields (ignored), and
    node-name truncation / fallback generation. Anything that makes
    the node unusable raises :class:`ValueError` instead — warnings
    never carry a bad node.
    """
    if not isinstance(uri, str) or "://" not in uri:
        raise ValueError(f"malformed node URI (missing scheme): {uri[:40]!r}")
    scheme = uri.split("://", 1)[0].strip().lower()
    handler = _HANDLERS.get(scheme)
    if handler is None:
        raise ValueError(
            f"unsupported node URI scheme: {scheme!r} "
            f"(supported: {', '.join(SUPPORTED_SCHEMES)})"
        )
    warnings: list[str] = []
    proxy = handler(uri, warnings)
    proxy["name"] = normalize_node_name(proxy.get("name"), warnings=warnings)
    return proxy, warnings


def parse_uri(uri: str) -> dict:
    """Parse one node URI into a mihomo proxy dict (with ``name``).

    Raises :class:`ValueError` on unknown schemes or malformed input.
    See :func:`parse_uri_with_warnings` for the non-fatal warnings
    this discards.
    """
    proxy, _ = parse_uri_with_warnings(uri)
    return proxy


# ------------------------------------------------------- shared validation
def validate_proxy_dict(
    proxy: dict[str, Any],
    *,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Validate + normalize one mihomo proxy dict (H-11 / M-34).

    This is the shared validator for every path that writes a proxy
    into the database: the node PUT endpoint (``proxy`` JSON) and the
    URI import path (parsed output is re-checked here). The config
    compiler's ``validate_config_dict`` (M-34) is meant to call this
    same function per proxy — see the coordinator note in the audit
    report; this definition is the one to wire it to.

    Checks (all failures raise :class:`ValueError`, callers map it
    to HTTP 400 and refuse the write):

    * ``proxy`` is a dict; ``type`` is present and in
      :data:`SUPPORTED_PROXY_TYPES` (``hy2`` is normalized to
      ``hysteria2``).
    * ``server`` is a valid IP or hostname; ``port`` is an int
      (or digit string) in 1-65535.
    * ``uuid`` is present and well-formed for vless / vmess / tuic
      (and validated whenever present for other types).
    * ``password`` is a non-empty string for ss / trojan /
      hysteria2 / tuic.
    * ``cipher`` is in the protocol whitelist for ss (required)
      and vmess (default ``"auto"`` when absent, per L-11).
    * ``tls``, when present, is a boolean; ``alterId``, when
      present, is a non-negative int; ``network``, when present,
      is a known network; ``servername`` / ``sni`` / ``alpn``
      have the right shapes when present.

    Returns a normalized copy: type lowercased / alias-resolved,
    port coerced to ``int``, UUID canonicalized, VMess defaults
    (``cipher="auto"``, ``alterId=0``) filled, and the name run
    through :func:`normalize_node_name` (empty -> ``node-<shortid>``,
    over-long -> truncated; both reported via ``warnings`` when a
    list is supplied). Unknown extra keys are passed through
    untouched — mihomo accepts proxy fields this validator does
    not know about (e.g. ``udp``), and rejecting them would break
    forward compatibility.
    """
    if not isinstance(proxy, dict):
        raise ValueError("proxy JSON must be an object")
    data: dict[str, Any] = dict(proxy)

    ptype = data.get("type")
    if not isinstance(ptype, str) or not ptype.strip():
        raise ValueError("proxy JSON must include a non-empty 'type'")
    ptype = ptype.strip().lower()
    if ptype == "hy2":
        ptype = "hysteria2"
        if warnings is not None:
            warnings.append("proxy type 'hy2' normalized to 'hysteria2'")
    if ptype not in SUPPORTED_PROXY_TYPES:
        raise ValueError(
            f"unsupported proxy type: {ptype!r} "
            f"(supported: {', '.join(SUPPORTED_PROXY_TYPES)})"
        )
    data["type"] = ptype

    data["server"] = _validate_host(data.get("server"), "proxy JSON")
    data["port"] = _validate_port(data.get("port"), "proxy JSON")

    uuid_value = data.get("uuid")
    if ptype in ("vless", "vmess", "tuic"):
        data["uuid"] = _validate_uuid(uuid_value, "proxy JSON")
    elif uuid_value is not None:
        data["uuid"] = _validate_uuid(uuid_value, "proxy JSON")

    if ptype in ("ss", "trojan", "hysteria2", "tuic"):
        password = data.get("password")
        if not isinstance(password, str) or not password:
            raise ValueError(
                f"proxy JSON for type {ptype!r} must include a "
                "non-empty 'password'"
            )

    if ptype == "ss":
        data["cipher"] = _validate_cipher(
            data.get("cipher"), "proxy JSON", SS_CIPHERS
        )
    elif ptype == "vmess":
        data["cipher"] = _validate_cipher(
            data.get("cipher") or "auto", "proxy JSON", VMESS_CIPHERS
        )
        alter_id = data.get("alterId", 0)
        if isinstance(alter_id, bool):
            raise ValueError("proxy JSON has an invalid alterId (aid)")
        if isinstance(alter_id, int):
            pass
        elif isinstance(alter_id, str) and alter_id.strip().isdigit():
            alter_id = int(alter_id.strip())
        else:
            raise ValueError("proxy JSON has an invalid alterId (aid)")
        if alter_id < 0:
            raise ValueError("proxy JSON has an invalid alterId (aid)")
        data["alterId"] = alter_id

    tls = data.get("tls")
    if tls is not None and not isinstance(tls, bool):
        raise ValueError("proxy JSON 'tls' must be a boolean")
    network = data.get("network")
    if network is not None:
        if not isinstance(network, str) or network.lower() not in PROXY_NETWORKS:
            raise ValueError(
                f"proxy JSON has an unsupported network: {network!r}"
            )
        data["network"] = network.lower()
    for key in ("servername", "sni"):
        if data.get(key) is not None and not isinstance(data[key], str):
            raise ValueError(f"proxy JSON {key!r} must be a string")
    if data.get("alpn") is not None and (
        not isinstance(data["alpn"], list)
        or not all(isinstance(item, str) for item in data["alpn"])
    ):
        raise ValueError("proxy JSON 'alpn' must be a list of strings")

    data["name"] = normalize_node_name(data.get("name"), warnings=warnings)
    return data
