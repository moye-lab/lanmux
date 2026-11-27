"""Secret masking for previews, node reads and exports (M-01 / L-23).

Whitelist approach: only keys that are known to be safe stay in
plaintext. A mapping key is sensitive when its lower-cased name
contains a sensitive substring (``password`` / ``key`` / ``secret`` /
``uuid`` / ``token`` ...) or is in the explicit sensitive set (e.g.
``short-id``, which carries no sensitive substring but is a Reality
credential). Masking recurses into nested dicts and lists, so
Reality / Trojan / WebSocket option blocks are covered too.

``mask_secret`` (L-23): a short secret (8 chars or fewer) is fully
masked — showing its first/last characters would be most of the
secret. A longer secret keeps its first and last two characters so
the operator can still tell secrets apart, with the middle hidden.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# A key is sensitive when it contains one of these substrings
# (case-insensitive) or is listed in _SENSITIVE_KEYS.
_SENSITIVE_SUBSTRINGS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "uuid",
    "key",
    "credential",
    "private",
    "psk",
)

# Sensitive keys that carry no sensitive substring (M-01: ``short-id``
# is a Reality credential but contains none of the substrings above).
_SENSITIVE_KEYS = frozenset({"short-id", "short_id"})

MASKED = "********"

# URI schemes whose userinfo / opaque part may carry credentials.
_PROXY_SCHEMES = frozenset(
    {
        "ss",
        "ssr",
        "vless",
        "vmess",
        "trojan",
        "trojan-go",
        "socks",
        "socks5",
        "http",
        "https",
        "hysteria",
        "hysteria2",
        "hy2",
        "tuic",
        "tuic5",
        "snell",
        "wireguard",
        "wg",
        "mieru",
        "anytls",
        "ssh",
    }
)


def is_sensitive_key(key: Any) -> bool:
    """True when ``key`` names a credential-bearing field."""
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    if lowered in _SENSITIVE_KEYS:
        return True
    return any(sub in lowered for sub in _SENSITIVE_SUBSTRINGS)


def mask_secret(value: Any) -> str:
    """Mask one secret value (L-23).

    Short secrets (<= 8 chars) are fully masked; longer ones keep
    their first and last two characters. Non-string values mask
    fully — there is nothing safe to preserve.
    """
    if not isinstance(value, str):
        return MASKED
    if len(value) <= 8:
        return MASKED
    return f"{value[:2]}****{value[-2:]}"


def mask_value(obj: Any) -> Any:
    """Recursively mask sensitive keys in a nested structure.

    Sensitive keys are replaced wholesale (their whole subtree is
    hidden, not recursed into); every other key passes through and
    its value is recursed into, so safe fields (server, port, type,
    cipher, fingerprint, ...) survive untouched.
    """
    if isinstance(obj, dict):
        return {
            key: (mask_secret(value) if is_sensitive_key(key) else mask_value(value))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [mask_value(item) for item in obj]
    return obj


def mask_node_uri(uri: Any) -> Any:
    """Mask the credential part of a node URI.

    ``vless://<uuid>@host`` / ``trojan://<pass>@host`` /
    ``ss://<base64(method:pass)>@host`` lose their userinfo;
    ``ss://<base64(method:pass@host)>`` / ``vmess://<base64-json>``
    lose the whole opaque blob (it carries no host part to keep);
    a bare ``host:port`` URI has no credentials and is untouched.
    Sensitive query parameters (``?password=...``) are masked too.
    The fragment (node name) is kept.
    """
    if not isinstance(uri, str) or "://" not in uri:
        return uri
    try:
        parts = urlsplit(uri)
    except ValueError:
        return uri
    if parts.scheme.lower() not in _PROXY_SCHEMES:
        return uri
    netloc = parts.netloc
    if "@" in netloc:
        netloc = MASKED + "@" + netloc.rsplit("@", 1)[1]
    elif netloc and "." not in netloc and ":" not in netloc:
        # Opaque base64 blob (full-form ss:// / vmess://): no host
        # part to preserve, so the whole blob is hidden.
        netloc = MASKED
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        if any(is_sensitive_key(k) for k, _ in pairs):
            query = urlencode(
                [
                    (k, MASKED if is_sensitive_key(k) else v)
                    for k, v in pairs
                ]
            )
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def mask_node(node: dict[str, Any]) -> dict[str, Any]:
    """Copy of a node row with credentials masked (list/single reads).

    The ``proxy`` dict is masked recursively and the ``uri`` loses
    its credential part; everything else (name, server, port, type,
    speedtest results, ...) is returned unchanged.
    """
    masked = dict(node)
    if isinstance(masked.get("proxy"), dict):
        masked["proxy"] = mask_value(masked["proxy"])
    if isinstance(masked.get("uri"), str):
        masked["uri"] = mask_node_uri(masked["uri"])
    return masked
