"""Compile LanMux DB state into a mihomo ``config.yaml``.

The compiler enforces the task-book low-latency baseline:

* ``ipv6: false``, ``tcp-concurrent: true``, ``unified-delay: true``,
  ``find-process-mode: off``
* Dual LAN listeners (Shadowsocks + Mixed, both UDP, ``0.0.0.0``)
* Sniffer with ``parse-pure-ip`` (HTTP/TLS/QUIC)
* ``redir-host`` DNS, no fake-ip, no overseas DoH as the main resolver;
  domestic nameservers are AliDNS / Tencent DNSPod
* Forced top rules: private + CN traffic always ``DIRECT``

Two corrections vs. the task book as written
--------------------------------------------
1. DNS ``nameserver`` / ``fallback`` entries are **plain URL strings**.
   The task book wrote them in Markdown link syntax
   (``[https://...](https://...)``), which is invalid YAML and is
   NOT reproduced here.
2. The generated YAML contains **no ``${VAR}`` placeholders**. Secrets
   (mihomo ``secret``, SS password) are rendered from settings at
   compile time; :func:`build_config` raises :class:`ValueError` if
   either is unset instead of emitting a literal placeholder.

Fallback DNS ``#group`` fragments
---------------------------------
``fallback`` nameservers use the documented mihomo form
``https://1.1.1.1/dns-query#<group>``, where ``<group>`` must be an
existing proxy-group name (here: ``Default``). The fragment survives
the YAML round-trip as part of the plain scalar (verified by test).

AI service domains (``AI`` group)
--------------------------------------
``DOMAIN-SUFFIX`` matches cover the domain and all its subdomains, so
e.g. ``openai.com`` already covers ``api.openai.com`` and
``chat.openai.com``; ``anthropic.com`` covers ``console.anthropic.com``.

* OpenAI / ChatGPT: ``openai.com``, ``chatgpt.com``,
  ``oaiusercontent.com`` (ChatGPT file/image CDN)
* Anthropic / Claude: ``anthropic.com``, ``claude.ai``
* Google Gemini / AI Studio: ``gemini.google.com``,
  ``aistudio.google.com``, ``ai.google.dev``,
  ``generativelanguage.googleapis.com`` (Gemini API)
"""

from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Sequence

import yaml

from .database import Database
from .models import GROUP_DISPLAY_NAMES, Settings
from .rule_validation import (
    filter_valid_custom_rules,
    validate_custom_rule,
)
from .uri_parser import (
    SUPPORTED_PROXY_TYPES,
    validate_proxy_dict as _shared_validate_proxy_dict,
)

logger = logging.getLogger(__name__)

HEALTH_CHECK_URL = "http://www.gstatic.com/generate_204"

# Top-level sections a compiled config must contain.
REQUIRED_SECTIONS = (
    "proxies",
    "proxy-groups",
    "rules",
    "listeners",
    "dns",
    "secret",
)
# NOTE the unit trap (2026-11-24, cost us a whole afternoon): mihomo's
# group `interval` is in SECONDS but its group `timeout` is in
# MILLISECONDS (default 5000). Writing timeout=5 meant a 5ms deadline,
# so every scheduled health check timed out, every proxy stayed
# "dead", and fallback groups never switched nodes at runtime.
# Keep the _S / _MS suffixes so the units stay visible at every use.
HEALTH_CHECK_INTERVAL_S = 60
HEALTH_CHECK_TIMEOUT_MS = 5000

# Business groups in rule order. "default" is the final MATCH group.
# Order matters: first match wins. AI domains stay before the Google
# group (gemini.google.com etc. are google.com subdomains), and YouTube
# stays first (googlevideo.com belongs to the YouTube group, not Google).
GROUP_KEYS = [
    "youtube",
    "telegram",
    "netflix",
    "tiktok",
    "spotify",
    "twitter",
    "facebook",
    "streaming",
    "ai",
    "google",
    "apple",
    "microsoft",
    "bilibili",
    "default",
]

AI_DOMAINS = [
    # OpenAI / ChatGPT
    "openai.com",
    "chatgpt.com",
    "oaiusercontent.com",
    # Anthropic / Claude
    "anthropic.com",
    "claude.ai",
    # Google Gemini / AI Studio
    "gemini.google.com",
    "aistudio.google.com",
    "ai.google.dev",
    "generativelanguage.googleapis.com",
]

FORCED_RULES = [
    "GEOIP,PRIVATE,DIRECT",
    "GEOSITE,PRIVATE,DIRECT",
    "GEOSITE,CN,DIRECT",
    "GEOIP,CN,DIRECT",
]

_BUSINESS_RULES: list[str] = [
    "GEOSITE,youtube,YouTube",
    "GEOSITE,telegram,Telegram",
    "GEOIP,telegram,Telegram",
    "GEOSITE,netflix,Netflix",
    "GEOSITE,tiktok,TikTok",
    "GEOSITE,spotify,Spotify",
    "GEOSITE,twitter,Twitter",
    "GEOSITE,facebook,Facebook",
    "GEOSITE,disney,Streaming",
    "GEOSITE,hbo,Streaming",
    "GEOSITE,hulu,Streaming",
    "GEOSITE,primevideo,Streaming",
    # AI domains MUST stay before GEOSITE,google (see GROUP_KEYS note).
    *[f"DOMAIN-SUFFIX,{domain},AI" for domain in AI_DOMAINS],
    "GEOSITE,google,Google",
    "GEOSITE,apple,Apple",
    "GEOSITE,microsoft,Microsoft",
    "GEOSITE,bilibili,Bilibili",
    "MATCH,Default",
]

_DOMESTIC_NAMESERVERS = ["223.5.5.5", "119.29.29.29"]


# ------------------------------------------------------------------ helpers
def _fsync_dir(path: Path) -> None:
    """fsync a directory so a rename inside it survives a crash."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _unique_tmp_path(target: Path) -> Path:
    """A tmp sibling of ``target`` unique to this process + call.

    Concurrent writers must never share one ``.tmp`` name (H-07):
    pid + cryptographic randomness make collisions negligible, and
    the file lives in the same directory so ``os.replace`` stays
    atomic.
    """
    return target.with_name(
        f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    )


def atomic_write_bytes(path: str | Path, data: bytes) -> Path:
    """Atomically write ``data`` to ``path`` with mode 0600.

    Write to a uniquely-named tmp file → flush → fsync → chmod 0600
    → ``os.replace`` → fsync the directory. On any failure the tmp
    file is removed and the exception propagates; the previous live
    file is never left half-written.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = _unique_tmp_path(target)
    try:
        with open(tmp_path, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, target)
        _fsync_dir(target.parent)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return target


def atomic_write_text(path: str | Path, text: str) -> Path:
    """Text form of :func:`atomic_write_bytes` (UTF-8, mode 0600)."""
    return atomic_write_bytes(path, text.encode("utf-8"))


def _as_dict(item: Any) -> dict[str, Any]:
    """Accept a Pydantic model or a plain dict."""
    if hasattr(item, "model_dump"):
        return item.model_dump()
    return dict(item)


def _settings_dict(settings: Settings | dict[str, Any]) -> dict[str, Any]:
    data = _as_dict(settings)
    data.setdefault("ss_port", 10001)
    data.setdefault("ss_cipher", "aes-128-gcm")
    data.setdefault("mixed_port", 7890)
    data.setdefault("controller_port", 9090)
    data.setdefault("mixed_auth_user", "")
    data.setdefault("mixed_auth_pass", "")
    data.setdefault("external_ui", "")
    return data


def _unique_proxy_names(nodes: list[dict[str, Any]]) -> dict[int, str]:
    """Map node id -> unique proxy name (``Name (2)`` on collision).

    Mihomo proxy names must be unique; a duplicate name would break
    group membership, so collisions are disambiguated deterministically.

    The candidate name is checked against the **final** set of names
    already assigned (H-10): a generated ``Name (2)`` that collides
    with a user's pre-existing ``Name (2)`` node keeps incrementing
    (``Name (3)``, ``Name (4)``, …) until it is unique. Checking only
    the raw names would emit the duplicate and break the reload.
    """
    used: set[str] = set()
    result: dict[int, str] = {}
    for node in nodes:
        base = node["name"]
        candidate = base
        suffix = 2
        while candidate in used:
            candidate = f"{base} ({suffix})"
            suffix += 1
        used.add(candidate)
        result[node["id"]] = candidate
    return result


def _live_members(
    group_key: str,
    bindings: list[dict[str, Any]],
    enabled_ids: dict[int, str],
) -> list[str]:
    """Proxy names of the group's bindings that resolve to a live node.

    Bindings pointing at disabled or deleted nodes contribute nothing.
    An empty result means the group has no usable exit node — whether
    it was never bound at all, or its nodes all died, is decided by
    the caller from the binding rows (see :func:`_group_members`).
    """
    return [
        enabled_ids[b["node_id"]]
        for b in bindings
        if b["group_key"] == group_key and b["node_id"] in enabled_ids
    ]


def _group_members(
    group_key: str,
    bindings: list[dict[str, Any]],
    enabled_ids: dict[int, str],
) -> tuple[list[str], str]:
    """Resolve one group's proxies and mode from its bindings.

    Returns ``(proxy_names, mode)``. Bindings pointing at disabled or
    deleted nodes are skipped. The empty-group outcome depends on
    whether the group was ever bound — the H-03 fail-closed rule:

    * never bound (no binding rows): ``["DIRECT"]`` — the design
      default for an unconfigured group, unchanged;
    * bound, but every bound node is disabled or deleted: ``["REJECT"]``
      — the group must NOT silently fall back to DIRECT, or traffic
      the user expects to be proxied would leak out direct with no
      warning. Rebind a live node, or clear the binding to go back to
      DIRECT deliberately.
    """
    members = _live_members(group_key, bindings, enabled_ids)
    mode = "fallback"
    group_bindings = [b for b in bindings if b["group_key"] == group_key]
    if group_bindings:
        main = next(
            (b for b in group_bindings if b.get("role") == "main"),
            group_bindings[0],
        )
        mode = main.get("mode", "fallback")
    if members:
        return members, mode
    if group_bindings:
        return ["REJECT"], mode
    return ["DIRECT"], mode


def dead_group_keys(
    nodes: Sequence[Any],
    bindings: Sequence[Any],
) -> list[str]:
    """Group keys (in rule order) whose bindings exist but resolve to
    no live node — i.e. the groups :func:`_group_members` compiles to
    ``REJECT``. Never-bound groups are NOT dead; they compile to
    DIRECT by design.
    """
    node_dicts = [_as_dict(n) for n in nodes]
    binding_dicts = [_as_dict(b) for b in bindings]
    enabled_ids = _unique_proxy_names(
        [n for n in node_dicts if n.get("enabled", True)]
    )
    dead: list[str] = []
    for key in GROUP_KEYS:
        group_bindings = [
            b for b in binding_dicts if b["group_key"] == key
        ]
        if group_bindings and not _live_members(
            key, binding_dicts, enabled_ids
        ):
            dead.append(key)
    return dead


def default_unbound_with_nodes(
    nodes: Sequence[Any],
    bindings: Sequence[Any],
) -> bool:
    """True when the library holds at least one node but the Default
    group has no binding rows at all — the H-04 fail-open state.
    A Default group whose bindings exist but all point at dead nodes
    is NOT unbound (it is dead and compiles to REJECT); a library
    with zero nodes is NOT unbound either (a fresh install, where
    DIRECT is the only option for the first config).
    """
    node_dicts = [_as_dict(n) for n in nodes]
    binding_dicts = [_as_dict(b) for b in bindings]
    if not node_dicts:
        return False
    return not any(b["group_key"] == "default" for b in binding_dicts)


def default_apply_gate(
    nodes: Sequence[Any],
    bindings: Sequence[Any],
) -> str | None:
    """H-04 refusal message when an apply must not proceed, else None.

    Refuses only the fail-open state: nodes exist but Default was
    never bound. Applying then would leave ALL unmatched traffic
    DIRECT while the user believes a proxy is in place. The message
    tells the user exactly what to do (bind Default first). Zero-node
    libraries pass — a fresh install cannot complete its first config
    any other way.
    """
    if not default_unbound_with_nodes(nodes, bindings):
        return None
    return (
        "Default 组未绑定任何节点：为防止全部流量静默直连，本次应用已被拒绝。"
        "请先在「业务分流」页为 Default 组绑定至少一个节点，然后重新应用配置。"
    )


def _dns_section(default_usable: bool = True) -> dict[str, Any]:
    """DNS section. ``default_usable`` says whether the Default group
    currently has at least one live node.

    The ``fallback`` DoH servers are queried *through* the Default
    group (``#Default`` fragment). When Default has no live node,
    fallback must be omitted, not left pointing at a DIRECT/REJECT
    group: via a DIRECT Default the fallback query would go out
    direct (a fail-open DNS leak in exactly the state H-04 guards),
    and via a REJECT Default every fallback query would fail. There
    is no other proxy-DNS path — the only fail-closed option is no
    fallback at all, leaving the domestic main nameservers to answer.

    Field-by-field check against the mihomo v1.19.34 DNS table
    (config/config.go): enable / ipv6 / prefer-h3 / cache-algorithm
    (lru|arc) / enhanced-mode (normal|redir-host|fake-ip) /
    respect-rules / default-nameserver (plain IPs only — bootstrap
    resolvers) / nameserver / fallback (with #<group> fragment) /
    fallback-filter (geoip / geoip-code / geosite / ipcidr /
    domain) / nameserver-policy (geosite: keys) are all valid keys
    with values in their documented domains. `fallback-lazy-query`
    is intentionally left at its default (false): fallback servers
    are queried in parallel with `nameserver` — see the README DNS
    section (M-38) for the privacy note on that default.
    """
    section: dict[str, Any] = {
        "enable": True,
        "ipv6": False,
        "prefer-h3": False,
        "cache-algorithm": "arc",
        "enhanced-mode": "redir-host",
        "respect-rules": True,
        "default-nameserver": list(_DOMESTIC_NAMESERVERS),
        # M-40: proxy hostnames must not be resolved through domestic
        # UDP only — a poisoned answer makes a healthy node look
        # offline. Use a trusted overseas DoH (Google), bootstrapped
        # via default-nameserver like the fallback list.
        "proxy-server-nameserver": ["https://dns.google/dns-query"],
        "direct-nameserver": list(_DOMESTIC_NAMESERVERS),
        "nameserver-policy": {
            "geosite:private,cn": list(_DOMESTIC_NAMESERVERS),
        },
        "nameserver": [
            "https://dns.alidns.com/dns-query",
            "https://doh.pub/dns-query",
        ],
        # M-39: fallback-filter previously had only geoip/geosite, so
        # a bogon answer (e.g. 240.0.0.0/4) or a poisoned answer for
        # a known-overseas domain did not trigger fallback. ipcidr
        # entries are CIDRs (240.0.0.0/4 is mihomo's own documented
        # example; 0.0.0.0/32 is the other classic bogon) and domain
        # entries are "+." suffix patterns — both in mihomo's actual
        # format. geoip-code CN still covers CN-IP answers.
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "CN",
            "geosite": ["gfw"],
            "ipcidr": ["240.0.0.0/4", "0.0.0.0/32"],
            "domain": ["+.google.com", "+.youtube.com"],
        },
    }
    if default_usable:
        section["fallback"] = [
            "https://1.1.1.1/dns-query#Default",
            "https://8.8.8.8/dns-query#Default",
        ]
    return section


def _sniffer_section() -> dict[str, Any]:
    return {
        "enable": True,
        "parse-pure-ip": True,
        "sniff": {
            "HTTP": {
                "ports": [80, "8080-8880"],
                "override-destination": True,
            },
            "TLS": {"ports": [443, 8443]},
            "QUIC": {"ports": [443, 8443]},
        },
    }


# --------------------------------------------------------------------- build
def build_config(
    nodes: Sequence[Any],
    bindings: Sequence[Any],
    custom_rules: Sequence[Any],
    settings: Settings | dict[str, Any],
) -> dict[str, Any]:
    """Compile LanMux state into a mihomo config dict.

    ``nodes`` / ``bindings`` / ``custom_rules`` may be Pydantic models
    or plain dicts (as returned by :class:`~app.database.Database`).
    Raises :class:`ValueError` if a required secret is unset or a
    custom rule is malformed.
    """
    cfg_settings = _settings_dict(settings)
    secret = str(cfg_settings.get("mihomo_secret") or "")
    ss_password = str(cfg_settings.get("ss_password") or "")
    if not secret:
        raise ValueError(
            "cannot compile config: 'mihomo_secret' is not set in settings"
        )
    if not ss_password:
        raise ValueError(
            "cannot compile config: 'ss_password' is not set in settings"
        )

    node_dicts = [_as_dict(n) for n in nodes]
    binding_dicts = [_as_dict(b) for b in bindings]
    rule_dicts = [_as_dict(r) for r in custom_rules]

    enabled_nodes = [n for n in node_dicts if n.get("enabled", True)]
    unique_names = _unique_proxy_names(enabled_nodes)

    # H-03: a bound group with no live node compiles to REJECT (see
    # _group_members). Say so loudly — a silent REJECT is almost as
    # bad as a silent DIRECT if nobody notices the group is dead.
    dead = dead_group_keys(node_dicts, binding_dicts)
    if dead:
        logger.warning(
            "proxy group(s) %s have bindings but no live nodes; "
            "generating REJECT (fail-closed) — rebind a live node or "
            "clear the binding to return to DIRECT",
            [GROUP_DISPLAY_NAMES[k] for k in dead],
        )
    # DNS fallback rides through the Default group: only emit it while
    # Default has a live node, otherwise it would go direct (H-04).
    default_usable = bool(
        _live_members("default", binding_dicts, unique_names)
    )

    proxies: list[dict[str, Any]] = []
    for node in enabled_nodes:
        proxy = dict(node.get("proxy") or {})
        proxy["name"] = unique_names[node["id"]]
        proxy.setdefault("type", "ss")
        proxies.append(proxy)

    proxy_groups: list[dict[str, Any]] = []
    for key in GROUP_KEYS:
        members, mode = _group_members(key, binding_dicts, unique_names)
        proxy_groups.append(
            {
                "name": GROUP_DISPLAY_NAMES[key],
                "type": mode,
                "proxies": members,
                "url": HEALTH_CHECK_URL,
                "interval": HEALTH_CHECK_INTERVAL_S,
                "timeout": HEALTH_CHECK_TIMEOUT_MS,
                # mihomo defaults lazy=true: an idle group skips its
                # scheduled checks, so its health data goes stale and
                # failover can't happen when traffic arrives. This box
                # is always on; the check traffic is negligible.
                "lazy": False,
            }
        )

    rules: list[str] = list(FORCED_RULES)
    for rule in rule_dicts:
        if not rule.get("enabled", True):
            continue
        # M-12: compile with the same validator the save path uses —
        # unknown target, comma/space in the value, invalid CIDR or
        # bad domain all fail the compile instead of being emitted
        # into a mihomo config that would reload-fail or mis-route.
        rule_type = rule.get("type")
        value = str(rule.get("value") or "").strip()
        target = str(rule.get("target") or "").strip()
        validate_custom_rule(
            str(rule_type or ""), value, target
        )
        rules.append(f"{rule_type},{value},{target}")
    rules.extend(_BUSINESS_RULES)

    listeners: list[dict[str, Any]] = [
        {
            "name": "lan-ss",
            "type": "shadowsocks",
            "listen": "0.0.0.0",
            "port": int(cfg_settings["ss_port"]),
            "cipher": str(cfg_settings["ss_cipher"]),
            "password": ss_password,
            "udp": True,
        },
        {
            "name": "lan-mixed",
            "type": "mixed",
            "listen": "0.0.0.0",
            "port": int(cfg_settings["mixed_port"]),
            "udp": True,
        },
    ]
    # Mixed auth is a pair (M-06 + L-22): username without a password
    # silently disables auth in mihomo, and a username with an empty
    # password would emit ``password: ''``. A half pair is a config
    # error, never a silently unauthenticated listener — fail loudly
    # here as a backstop (the settings API rejects half pairs on
    # save; this also covers half pairs seeded by other paths).
    mixed_user = str(cfg_settings.get("mixed_auth_user") or "").strip()
    mixed_pass = str(cfg_settings.get("mixed_auth_pass") or "").strip()
    if bool(mixed_user) != bool(mixed_pass):
        raise ValueError(
            "cannot compile config: Mixed 用户名与密码须同时设置"
            " (mixed_auth_user / mixed_auth_pass must both be set or"
            " both be empty)"
        )
    if mixed_user:
        listeners[1]["username"] = mixed_user
        listeners[1]["password"] = mixed_pass

    config: dict[str, Any] = {
        "ipv6": False,
        "tcp-concurrent": True,
        "unified-delay": True,
        "find-process-mode": "off",
        "external-controller": (
            f"0.0.0.0:{int(cfg_settings['controller_port'])}"
        ),
        "secret": secret,
        "listeners": listeners,
        "sniffer": _sniffer_section(),
        "dns": _dns_section(default_usable),
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules,
    }

    # metacubexd dashboard (Phase 4): only emitted when the installer
    # (or the operator) configured a UI directory. Mihomo serves it at
    # <external-controller>/ui/; the LanMux frontend links there.
    external_ui = str(cfg_settings.get("external_ui") or "").strip()
    if external_ui:
        config["external-ui"] = external_ui
    return config


def proxy_names_for_nodes(nodes: Sequence[Any]) -> dict[int, str]:
    """Public wrapper: node id -> unique proxy name in the live config.

    Speedtests must address proxies by these names (duplicate node
    names are disambiguated as ``Name (2)``, see :func:`_unique_proxy_names`).
    """
    node_dicts = [_as_dict(n) for n in nodes]
    enabled = [n for n in node_dicts if n.get("enabled", True)]
    return _unique_proxy_names(enabled)


def snapshot_db(
    db: Database,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], Settings]:
    """Read the whole compiler input in one consistent snapshot.

    The four reads (nodes / bindings / custom rules / settings) are
    done while holding the database's per-instance lock, so no
    concurrent writer can slip in between them and produce a torn
    config (part new, part old — M-35). :class:`Database` methods
    take the same lock, and it is an RLock, so re-entering it here
    from the same thread is safe. A db-like object without ``_lock``
    falls back to plain sequential reads.
    """
    lock = getattr(db, "_lock", None)
    if lock is None:
        return (
            db.list_nodes(),
            db.list_bindings(),
            db.list_custom_rules(),
            db.get_settings(),
        )
    with lock:
        return (
            db.list_nodes(),
            db.list_bindings(),
            db.list_custom_rules(),
            db.get_settings(),
        )


def build_from_db(db: Database) -> dict[str, Any]:
    """Compile the current database state into a mihomo config dict.

    Reads a single consistent snapshot (see :func:`snapshot_db`).
    """
    nodes, bindings, custom_rules, settings = snapshot_db(db)
    return build_config(
        nodes=nodes,
        bindings=bindings,
        custom_rules=custom_rules,
        settings=settings,
    )


def domain_matchable_rules(
    custom_rules: Sequence[Any],
) -> list[dict[str, str]]:
    """Ordered domain-matchable rules, in the exact order they appear
    in the compiled config (see :func:`build_config`).

    Only rules evaluable from a bare domain or IP are included:
    enabled custom ``DOMAIN-SUFFIX`` / ``DOMAIN-KEYWORD`` /
    ``IP-CIDR`` rules (DB order — the same order they are compiled
    in), then the business rules that carry a domain (``GEOSITE``
    categories and the AI ``DOMAIN-SUFFIX`` list). ``GEOIP`` rules
    need a resolved IP, the forced CN/PRIVATE rules need the
    geosite/geoip databases, and ``MATCH`` is the terminal rule — none
    of those can be evaluated from a domain alone, so they are left
    out here and documented by :mod:`app.route_check` instead (the
    forced rules are listed in the diagnosis response with their
    source label; IP-CIDR rules only match IP inputs).

    Invalid rows are dropped with the same validator the compiler
    uses (:func:`app.rule_validation.filter_valid_custom_rules`),
    so diagnosis can never report a rule the compiler refused.

    Each entry: ``rule`` (verbatim text as emitted), ``kind``
    (``domain-suffix`` / ``domain-keyword`` / ``ip-cidr`` /
    ``geosite``), ``value``, ``target``, ``source`` (``custom`` /
    ``builtin``).
    """
    rules: list[dict[str, str]] = []
    for rule in filter_valid_custom_rules(
        [_as_dict(r) for r in custom_rules], check_target=False
    ):
        if not rule.get("enabled", True):
            continue
        rule_type = rule.get("type")
        if rule_type not in (
            "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR",
        ):
            continue
        value = str(rule.get("value") or "").strip()
        target = str(rule.get("target") or "").strip()
        if not value or not target:
            continue
        rules.append(
            {
                "rule": f"{rule_type},{value},{target}",
                "kind": str(rule_type).lower(),
                "value": value,
                "target": target,
                "source": "custom",
            }
        )
    for text in _BUSINESS_RULES:
        parts = text.split(",", 2)
        if len(parts) != 3:
            continue
        rule_type, value, target = parts
        if rule_type == "GEOSITE":
            kind = "geosite"
        elif rule_type == "DOMAIN-SUFFIX":
            kind = "domain-suffix"
        else:  # GEOIP (IP-based) and MATCH (terminal) are not matchable.
            continue
        rules.append(
            {
                "rule": text,
                "kind": kind,
                "value": value,
                "target": target,
                "source": "builtin",
            }
        )
    return rules


def dump_yaml(config: dict[str, Any]) -> str:
    """Render a config dict as YAML text (key order preserved)."""
    return yaml.safe_dump(
        config, sort_keys=False, allow_unicode=True, default_flow_style=False
    )


def write_config_file(
    config: dict[str, Any], path: str | Path
) -> Path:
    """Atomically write rendered YAML to ``path`` (mode 0600).

    Unique tmp file → fsync → ``os.replace`` → fsync the directory;
    a failed write leaves no ``.tmp`` behind and never truncates
    the previous file (L-27). The parent directory is checked first
    (L-12): it is created when missing and must be writable, so an
    unwritable destination fails here with a clear message instead
    of a bare OS error mid-write.
    """
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(
            f"cannot create config directory {target.parent}: {exc}"
        ) from exc
    if not os.access(target.parent, os.W_OK):
        raise OSError(
            f"config path is not writable: {target} "
            f"(directory {target.parent} is not writable)"
        )
    return atomic_write_text(path, dump_yaml(config))


# ------------------------------------------------------- deep validation
# Proxy types mihomo accepts on a ``proxies`` entry. The six node
# protocols LanMux supports are validated by the shared
# ``validate_proxy_dict`` in :mod:`app.uri_parser` (see below);
# ``PROXY_TYPES`` here is the wider mihomo-side set kept for legacy
# / exotic proxy types already stored in the DB.
PROXY_TYPES: frozenset[str] = frozenset(
    {
        "ss", "ssr", "vmess", "vless", "trojan", "hysteria",
        "hysteria2", "tuic", "snell", "socks5", "http",
        "wireguard", "anytls", "ssh",
    }
)

# Per-type required fields beyond the generic server/port/name/type.
_PROXY_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "ss": ("cipher", "password"),
    "ssr": ("cipher", "password"),
    "vmess": ("uuid",),
    "vless": ("uuid",),
    "trojan": ("password",),
    "hysteria2": ("password",),
    "tuic": ("uuid", "password"),
    "snell": ("psk",),
    "wireguard": ("private-key",),
}

# Rule types mihomo accepts (first field of a rule line).
_RULE_TYPES: frozenset[str] = frozenset(
    {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
        "GEOSITE", "GEOIP", "IP-CIDR", "IP-CIDR6", "IP-ASN",
        "SRC-IP-CIDR", "SRC-IP-CIDR6", "DST-PORT", "SRC-PORT",
        "PROCESS-NAME", "PROCESS-PATH", "RULE-SET", "MATCH",
        "AND", "OR", "NOT", "GEOIP-ASN",
    }
)

_PROXY_GROUP_TYPES: frozenset[str] = frozenset(
    {"select", "fallback", "url-test", "load-balance", "relay"}
)

_LISTENER_TYPES: frozenset[str] = frozenset(
    {"shadowsocks", "mixed", "socks", "http", "tuic", "hysteria2", "dns"}
)


def _validate_port_value(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{where} port must be an integer, got {value!r}")
    if not 1 <= value <= 65535:
        raise ValueError(f"{where} port {value} is out of range (1-65535)")
    return value


def validate_proxy_dict(proxy: dict[str, Any]) -> None:
    """Deep-validate one mihomo proxy dict (M-34).

    The six node protocols LanMux supports are checked by the shared
    validator in :mod:`app.uri_parser` — the same function the node
    PUT / import paths use (H-11): server shape, UUID format, cipher
    whitelist, TLS/network shapes. Any other type mihomo accepts
    (legacy or exotic nodes already in the DB, e.g. wireguard /
    snell) gets the structural checks below instead, so a legacy
    node is never newly rejected at apply time. The compiled dict
    itself must also carry a real ``int`` port (the shared validator
    coerces digit strings only inside its own returned copy).
    Raises :class:`ValueError` naming the defect.
    """
    if not isinstance(proxy, dict):
        raise ValueError(f"proxy entry is not a mapping: {proxy!r}")
    name = proxy.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("proxy entry is missing a non-empty 'name'")
    raw_type = proxy.get("type")
    ptype = raw_type.strip().lower() if isinstance(raw_type, str) else None
    if ptype in SUPPORTED_PROXY_TYPES:
        # Shared validator raises ValueError on any defect; its
        # normalized copy is discarded here (validation only).
        _shared_validate_proxy_dict(proxy)
        _validate_port_value(proxy.get("port"), f"proxy {name!r}")
        return
    if ptype not in PROXY_TYPES:
        raise ValueError(
            f"proxy {name!r} has unsupported type {raw_type!r} "
            f"(valid: {sorted(PROXY_TYPES)})"
        )
    server = proxy.get("server")
    if not isinstance(server, str) or not server.strip():
        raise ValueError(f"proxy {name!r} is missing a non-empty 'server'")
    _validate_port_value(proxy.get("port"), f"proxy {name!r}")
    for field in _PROXY_REQUIRED_FIELDS.get(str(ptype), ()):
        value = proxy.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"proxy {name!r} (type {ptype!r}) is missing "
                f"required field {field!r}"
            )


def _validate_rule_line(
    rule: Any, group_names: set[str], index: int
) -> None:
    """Validate one compiled rule line (``TYPE,VALUE,TARGET[,no-resolve]``)."""
    if not isinstance(rule, str) or not rule.strip():
        raise ValueError(f"rule #{index} is empty")
    parts = rule.split(",")
    if parts[0] == "MATCH":
        if len(parts) != 2 or not parts[1].strip():
            raise ValueError(
                f"rule #{index} is a malformed MATCH rule: {rule!r}"
            )
        target = parts[1].strip()
    else:
        if len(parts) < 3:
            raise ValueError(
                f"rule #{index} needs TYPE,VALUE,TARGET: {rule!r}"
            )
        if len(parts) > 4 or (len(parts) == 4 and parts[3] != "no-resolve"):
            raise ValueError(
                f"rule #{index} has unexpected fields: {rule!r}"
            )
        rule_type, value, target = (
            parts[0].strip(),
            parts[1].strip(),
            parts[2].strip(),
        )
        if rule_type not in _RULE_TYPES:
            raise ValueError(
                f"rule #{index} has unknown type {rule_type!r}"
            )
        if not value:
            raise ValueError(f"rule #{index} has an empty value: {rule!r}")
        if rule_type in ("IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6"):
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                raise ValueError(
                    f"rule #{index} has an invalid CIDR {value!r}"
                ) from None
        if rule_type in ("DST-PORT", "SRC-PORT"):
            if "-" in value:
                lo, _, hi = value.partition("-")
                try:
                    lo_i, hi_i = int(lo), int(hi)
                except ValueError:
                    raise ValueError(
                        f"rule #{index} has an invalid port range "
                        f"{value!r}"
                    ) from None
                if not (1 <= lo_i <= hi_i <= 65535):
                    raise ValueError(
                        f"rule #{index} has an out-of-range port "
                        f"range {value!r}"
                    )
            else:
                try:
                    port = int(value)
                except ValueError:
                    raise ValueError(
                        f"rule #{index} has an invalid port {value!r}"
                    ) from None
                if not 1 <= port <= 65535:
                    raise ValueError(
                        f"rule #{index} has an out-of-range port {value!r}"
                    )
    if target not in group_names and target not in ("DIRECT", "REJECT"):
        raise ValueError(
            f"rule #{index} targets unknown group {target!r} "
            f"(valid: {sorted(group_names)} / DIRECT / REJECT)"
        )


def validate_config_dict(config: dict[str, Any]) -> None:
    """Deep-validate a compiled config dict (M-34).

    Beyond the required top-level sections, checks: proxy entries
    (see :func:`validate_proxy_dict`, duplicate names rejected),
    listener ports (range + unique, including the external
    controller port), proxy-group types and member references, and
    rule lines (type, CIDR/port values, target legitimacy).
    Raises :class:`ValueError` naming the defect.
    """
    if not isinstance(config, dict):
        raise ValueError("compiled config is not a mapping")
    for section in REQUIRED_SECTIONS:
        if section not in config:
            raise ValueError(
                f"compiled config is missing required section: {section!r}"
            )
    if not isinstance(config["proxies"], list):
        raise ValueError("compiled config section 'proxies' is not a list")
    if not isinstance(config["proxy-groups"], list):
        raise ValueError(
            "compiled config section 'proxy-groups' is not a list"
        )
    if not isinstance(config["rules"], list):
        raise ValueError("compiled config section 'rules' is not a list")

    # -- proxies: deep check + unique names ----------------------------
    proxy_names: set[str] = set()
    for proxy in config["proxies"]:
        validate_proxy_dict(proxy)
        name = str(proxy["name"])
        if name in proxy_names:
            raise ValueError(f"duplicate proxy name: {name!r}")
        proxy_names.add(name)

    # -- proxy-groups: known types, members must resolve --------------
    group_names: set[str] = set()
    for group in config["proxy-groups"]:
        if not isinstance(group, dict):
            raise ValueError(f"proxy-group entry is not a mapping: {group!r}")
        gname = group.get("name")
        if not isinstance(gname, str) or not gname.strip():
            raise ValueError("proxy-group entry is missing a non-empty 'name'")
        group_names.add(gname)
    for group in config["proxy-groups"]:
        gtype = group.get("type")
        if gtype not in _PROXY_GROUP_TYPES:
            raise ValueError(
                f"proxy-group {group.get('name')!r} has unsupported "
                f"type {gtype!r} (valid: {sorted(_PROXY_GROUP_TYPES)})"
            )
        members = group.get("proxies")
        if not isinstance(members, list):
            raise ValueError(
                f"proxy-group {group.get('name')!r} 'proxies' is not a list"
            )
        for member in members:
            if member in ("DIRECT", "REJECT"):
                continue
            if member not in proxy_names and member not in group_names:
                raise ValueError(
                    f"proxy-group {group.get('name')!r} references "
                    f"unknown proxy/group {member!r}"
                )

    # -- listeners + external-controller: ports in range and unique ----
    listeners = config.get("listeners")
    if listeners is None:
        listeners = []
    if not isinstance(listeners, list):
        raise ValueError("compiled config section 'listeners' is not a list")
    used_ports: dict[int, str] = {}
    for listener in listeners:
        if not isinstance(listener, dict):
            raise ValueError(
                f"listener entry is not a mapping: {listener!r}"
            )
        lname = listener.get("name")
        if not isinstance(lname, str) or not lname.strip():
            raise ValueError("listener entry is missing a non-empty 'name'")
        ltype = listener.get("type")
        if ltype not in _LISTENER_TYPES:
            raise ValueError(
                f"listener {lname!r} has unsupported type {ltype!r} "
                f"(valid: {sorted(_LISTENER_TYPES)})"
            )
        port = _validate_port_value(
            listener.get("port"), f"listener {lname!r}"
        )
        if port in used_ports:
            raise ValueError(
                f"port {port} is used by both {used_ports[port]!r} "
                f"and listener {lname!r}"
            )
        used_ports[port] = f"listener {lname!r}"
    controller = config.get("external-controller")
    if controller is not None:
        if not isinstance(controller, str) or ":" not in controller:
            raise ValueError(
                f"external-controller must look like 'host:port', "
                f"got {controller!r}"
            )
        try:
            ctrl_port = int(controller.rsplit(":", 1)[1])
        except ValueError:
            raise ValueError(
                f"external-controller has a non-numeric port: "
                f"{controller!r}"
            ) from None
        if not 1 <= ctrl_port <= 65535:
            raise ValueError(
                f"external-controller port {ctrl_port} is out of range "
                "(1-65535)"
            )
        if ctrl_port in used_ports:
            raise ValueError(
                f"port {ctrl_port} is used by both "
                f"{used_ports[ctrl_port]!r} and the external controller"
            )

    # -- secret: must be a non-empty string ----------------------------
    secret = config.get("secret")
    if not isinstance(secret, str) or not secret.strip():
        raise ValueError("compiled config 'secret' must be a non-empty string")

    # -- dns: must be a mapping when present ---------------------------
    dns = config.get("dns")
    if dns is not None and not isinstance(dns, dict):
        raise ValueError("compiled config section 'dns' is not a mapping")

    # -- rules ----------------------------------------------------------
    for index, rule in enumerate(config["rules"]):
        _validate_rule_line(rule, group_names, index)
