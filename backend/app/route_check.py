"""Domain route diagnostics: explain why a domain goes where it goes.

Matches a domain against the same ordered rules the config compiler
emits (:func:`app.config_builder.domain_matchable_rules`), then
resolves the winning group to its live exit node.

The diagnostic model includes the forced rules (M-09) and all custom
rules including IP-CIDR (M-10), each annotated with its source:

* ``forced`` — ``GEOIP,PRIVATE`` / ``GEOSITE,PRIVATE`` /
  ``GEOSITE,CN`` / ``GEOIP,CN`` (CN egress guard). They precede every
  other rule. A private IP input, or a private-namespace domain, is
  matched here directly and reported as
  "强制 DIRECT（CN 出口防护）" — distinct from a business group that
  merely resolves to DIRECT because it has no bound nodes
  ("业务组 DIRECT").
* ``custom`` / ``builtin`` — user rules and business rules.

Honesty limits (surfaced in the response ``note``):

* Whether a domain hits ``GEOSITE,CN`` / ``GEOIP,CN`` cannot be
  decided from the domain string alone (it needs the geosite/geoip
  databases or a resolved IP), so a domain diagnosis always warns
  that a CN site would have hit the forced CN rules first.
* ``GEOSITE`` categories are matched against a curated list of
  canonical domains per category (the full GeoSite database is not
  parsed). A domain outside the curated list reports "no domain rule
  matched" together with the downstream path (``GEOIP,CN`` -> DIRECT,
  otherwise the final ``MATCH`` -> Default group).
* IP-CIDR custom rules only match IP inputs. For a domain input they
  are listed in ``ip_cidr_rules`` but cannot be evaluated — the note
  says so.
* Diagnosis checks drift (M-13): when the DB revision is ahead of
  the running revision the result is annotated "基于过期配置，仅供
  参考".
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .config_builder import (
    FORCED_RULES,
    domain_matchable_rules,
    proxy_names_for_nodes,
)
from .database import Database
from .mihomo_client import MihomoClient, MihomoError
from .models import GROUP_DISPLAY_NAMES
from .rule_validation import is_private_domain

# Canonical domains per GEOSITE category, used to approximate geosite
# membership (the full GeoSite database is not parsed). Keep this list
# conservative: only domains that unambiguously belong to the category.
GEOSITE_DOMAINS: dict[str, tuple[str, ...]] = {
    "youtube": (
        "youtube.com", "youtu.be", "googlevideo.com",
        "youtube-nocookie.com",
    ),
    "telegram": ("telegram.org", "t.me"),
    "netflix": (
        "netflix.com", "nflxext.com", "nflximg.net", "nflxvideo.net",
    ),
    "tiktok": ("tiktok.com", "tiktokcdn.com", "musical.ly"),
    "spotify": ("spotify.com", "scdn.co"),
    "twitter": ("twitter.com", "x.com", "twimg.com"),
    "facebook": ("facebook.com", "fbcdn.net", "fb.com", "messenger.com"),
    "disney": ("disneyplus.com", "disney.com"),
    "hbo": ("hbo.com", "max.com", "hbomax.com"),
    "hulu": ("hulu.com", "huluim.com"),
    "primevideo": ("primevideo.com", "amazonvideo.com"),
    "google": (
        "google.com", "gmail.com", "googleapis.com", "gstatic.com",
        "googleusercontent.com", "googlesyndication.com",
    ),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": (
        "microsoft.com", "windows.com", "windowsupdate.com",
        "office.com", "live.com", "msn.com", "bing.com",
    ),
    "bilibili": ("bilibili.com", "bilivideo.com", "biligame.com", "hdslb.com"),
}

_DISPLAY_TO_KEY = {v: k for k, v in GROUP_DISPLAY_NAMES.items()}

NO_MATCH_NOTE = (
    "未命中域名规则。后续走向：若该域名解析到中国大陆 IP，命中 "
    "GEOIP,CN 走 DIRECT；否则命中最终 MATCH 规则，走 Default 组。"
)

CN_CAVEAT = (
    "注意：强制规则 GEOSITE,CN / GEOIP,CN 排在所有域名规则之前，仅凭"
    "域名无法判断是否命中；若该域名属于中国大陆站点，实际会先命中 "
    "CN 规则走 DIRECT。"
)

# Human labels for the forced rules (M-09): the panel shows which
# layer produced a DIRECT, instead of a bare "DIRECT".
FORCED_RULE_LABELS: dict[str, str] = {
    "GEOIP,PRIVATE,DIRECT": "强制 DIRECT（CN 出口防护）",
    "GEOSITE,PRIVATE,DIRECT": "强制 DIRECT（CN 出口防护）",
    "GEOSITE,CN,DIRECT": "强制 DIRECT（CN 出口防护）",
    "GEOIP,CN,DIRECT": "强制 DIRECT（CN 出口防护）",
}

DRIFT_NOTE = "注意：配置已漂移（库修订 {db} > 运行修订 {running}），本次诊断基于过期配置，仅供参考，请先重新应用配置。"


def _forced_rules_list() -> list[dict[str, str]]:
    """The forced rules, in compiled order, with source labels."""
    return [
        {
            "rule": text,
            "label": FORCED_RULE_LABELS.get(text, "强制规则"),
            "source": "forced",
        }
        for text in FORCED_RULES
    ]


def _drift_info(db: Database) -> dict[str, Any]:
    """Drift state from the revision counters (M-13)."""
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


def _with_drift(note: str, drift: dict[str, Any]) -> str:
    if drift["config_drift"]:
        return (
            note + " " + DRIFT_NOTE.format(
                db=drift["db_revision"],
                running=drift["running_revision"],
            )
        )
    return note


def normalize_domain(raw: str) -> str:
    """Lowercase, strip scheme/path/query/port/trailing dot.

    Accepts a bare domain, a full URL, or an IP address (v4/v6, with
    or without brackets / port). Raises :class:`ValueError` on
    empty input or on an input that is not a valid domain or IP
    (L-16): total length ≤ 253, labels 1–63 chars of ``[a-z0-9-]``
    not starting/ending with ``-``, and at least one dot — a
    single-label name is not a diagnosable domain.
    """
    text = (raw or "").strip().lower()
    if not text:
        raise ValueError("domain must not be empty")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/")[0].split("?")[0].split("#")[0]
    if not text:
        raise ValueError("domain must not be empty")
    # Bare IP (v6 included — checked before any ':' handling, since
    # a ':' inside an IPv6 literal is not a port separator).
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if text.startswith("["):
        # Bracketed IP: "[2001:db8::1]" or "[2001:db8::1]:8080".
        if "]" not in text:
            raise ValueError(f"invalid domain: {raw!r}")
        host, _, rest = text[1:].partition("]")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError(f"invalid domain: {raw!r}") from None
        if rest and not (
            rest.startswith(":") and rest[1:].isdigit()
        ):
            raise ValueError(f"invalid domain: {raw!r}")
        return str(ip)
    if ":" in text:  # strip :port (a domain never contains ':')
        host, _, port = text.partition(":")
        if ":" in port or not port.isdigit():
            raise ValueError(f"invalid domain: {raw!r}")
        text = host
    text = text.strip().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if not text:
        raise ValueError("domain must not be empty")
    # An IP with a port ("1.2.3.4:8080") lands here after stripping.
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    _validate_domain(text, raw)
    return text


def _validate_domain(text: str, raw: str) -> None:
    if len(text) > 253:
        raise ValueError(f"invalid domain (too long): {raw!r}")
    labels = text.split(".")
    if len(labels) < 2:
        raise ValueError(
            f"invalid domain: {raw!r} "
            "(a domain needs at least one dot, or be an IP address)"
        )
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in label)
        ):
            raise ValueError(f"invalid domain: {raw!r}")


def _suffix_match(domain: str, value: str) -> bool:
    """DOMAIN-SUFFIX semantics: the domain itself or any subdomain."""
    return domain == value or domain.endswith("." + value)


def _geosite_match(domain: str, category: str) -> bool:
    return any(
        _suffix_match(domain, known)
        for known in GEOSITE_DOMAINS.get(category, ())
    )


def _ip_cidr_match(domain: str, value: str) -> bool:
    """IP-CIDR semantics: only IP inputs can match (M-10)."""
    try:
        ip = ipaddress.ip_address(domain)
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return ip in network


def match_domain(
    domain: str, rules: list[dict[str, str]]
) -> dict[str, str] | None:
    """First matching rule in config order, or None."""
    for rule in rules:
        kind = rule["kind"]
        value = rule["value"]
        if kind == "domain-suffix":
            if _suffix_match(domain, value):
                return rule
        elif kind == "domain-keyword":
            if value in domain:
                return rule
        elif kind == "geosite":
            if _geosite_match(domain, value):
                return rule
        elif kind == "ip-cidr":
            if _ip_cidr_match(domain, value):
                return rule
    return None


def _connection(
    effective_target: str | None,
    current: dict[str, Any] | None,
    current_source: str | None,
    mihomo_reachable: bool | None,
    has_members: bool = False,
) -> str:
    """Connection state for a resolved group (four values only).

    * ``direct`` — the effective target is DIRECT.
    * ``connected`` — a current node exists, mihomo is reachable, and
      the current node comes from mihomo's live state.
    * ``unreachable`` — the group has bound nodes but no usable
      current node (all offline / none selected).
    * ``unknown`` — everything else (e.g. mihomo is down so the
      current node is only inferred from DB probe state).
    """
    if effective_target == "DIRECT":
        return "direct"
    if (
        current is not None
        and mihomo_reachable is True
        and current_source == "mihomo"
    ):
        return "connected"
    if has_members and current is None:
        return "unreachable"
    return "unknown"


def _node_summary(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node["id"],
        "name": node["name"],
        "online": node.get("last_online"),
        "delay_ms": node.get("last_delay_ms"),
    }


def _infer_current(
    main: dict[str, Any] | None, backups: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """DB-side fallback: main if online, else first online backup."""
    if main is not None and main.get("last_online") is True:
        return _node_summary(main)
    for node in backups:
        if node.get("last_online") is True:
            return _node_summary(node)
    return None


def _current_node(
    db: Database,
    display: str,
    main: dict[str, Any] | None,
    backups: list[dict[str, Any]],
    client: MihomoClient | None,
    bound_ids: set[int] | None = None,
) -> tuple[dict[str, Any] | None, str | None, bool | None, str | None]:
    """Current exit node for a group.

    Returns ``(node, source, mihomo_reachable, now_outside_group)``.
    Prefers the live ``now`` field from ``GET /proxies/{group}`` —
    but only when that node is bound to this group (M-11): a live
    ``now`` naming a node from another group says nothing about this
    group's exit, so it is ignored and the DB inference is used
    instead (the ignored name is reported in ``now_outside_group``).
    On any mihomo error (or when no client is given) infers from DB
    probe state. ``mihomo_reachable`` is None when mihomo was never
    contacted.
    """
    if client is None:
        return _infer_current(main, backups), "inferred", None, None
    try:
        group = client.get_proxy_group(display)
    except MihomoError as exc:
        # A connection error means mihomo is down; an HTTP error means
        # mihomo answered but the group lookup failed (e.g. the group
        # is not in the live config yet) — either way, infer from DB.
        return (
            _infer_current(main, backups),
            "inferred",
            not exc.connection_error,
            None,
        )
    now = group.get("now")
    if now == "DIRECT":
        return None, "mihomo", True, None
    if isinstance(now, str) and now:
        names = proxy_names_for_nodes(db.list_nodes())
        by_name = {name: nid for nid, name in names.items()}
        node_id = by_name.get(now)
        if node_id is not None:
            if bound_ids is not None and node_id not in bound_ids:
                # Live `now` belongs to another group — it must not
                # stand in for this group's exit node (M-11).
                node = db.get_node(node_id)
                outside = node["name"] if node is not None else now
                return (
                    _infer_current(main, backups),
                    "inferred",
                    True,
                    outside,
                )
            node = db.get_node(node_id)
            if node is not None:
                return _node_summary(node), "mihomo", True, None
    # `now` missing or names a proxy the DB does not know: infer.
    return _infer_current(main, backups), "inferred", True, None


def resolve_group(
    db: Database, group_key: str, client: MihomoClient | None
) -> dict[str, Any]:
    """Resolve a group to policy + main/backups + current exit node.

    Mirrors :func:`app.config_builder._group_members`: bindings
    pointing at disabled or deleted nodes are skipped. A group with
    no usable members resolves to ``REJECT`` when it has bindings
    (fail-closed, H-03 — the compiled config says REJECT, so the
    diagnosis must say the same), and to ``DIRECT`` only when it was
    never bound at all.
    """
    display = GROUP_DISPLAY_NAMES[group_key]
    bindings = db.list_bindings(group_key)
    nodes = {n["id"]: n for n in db.list_nodes()}
    main: dict[str, Any] | None = None
    backups: list[dict[str, Any]] = []
    mode = "fallback"
    if bindings:
        main_binding = next(
            (b for b in bindings if b.get("role") == "main"),
            bindings[0],
        )
        mode = main_binding.get("mode", "fallback")
    for binding in bindings:
        node = nodes.get(binding["node_id"])
        if node is None or not node["enabled"]:
            continue
        if binding.get("role") == "main" and main is None:
            main = node
        elif binding.get("role") == "backup":
            backups.append(node)
    bound_ids = {n["id"] for n in ([main] if main else []) + backups}
    result: dict[str, Any] = {
        "group": display,
        "group_key": group_key,
        "policy": mode,
        "main": _node_summary(main) if main is not None else None,
        "backups": [_node_summary(n) for n in backups],
        "current": None,
        "current_source": None,
        "mihomo_reachable": None,
        "now_outside_group": None,
        "effective_target": display,
        "connection": "unknown",
    }
    if main is None and not backups:
        if bindings:
            # Bound, but every bound node is disabled or deleted: the
            # compiled group is REJECT, not DIRECT (H-03). Connection
            # "unreachable" fits: bound nodes exist, none usable.
            result["effective_target"] = "REJECT"
            result["connection"] = "unreachable"
        else:
            result["effective_target"] = "DIRECT"
            result["connection"] = "direct"
        return result
    current, source, reachable, outside = _current_node(
        db, display, main, backups, client, bound_ids
    )
    result.update(
        {
            "current": current,
            "current_source": source,
            "mihomo_reachable": reachable,
            "now_outside_group": outside,
            "connection": _connection(
                result["effective_target"],
                current,
                source,
                reachable,
                has_members=True,
            ),
        }
    )
    return result


def check_route(
    db: Database, client: MihomoClient | None, raw_domain: str
) -> dict[str, Any]:
    """Full route diagnosis for one domain (see module docstring)."""
    domain = normalize_domain(raw_domain)
    drift = _drift_info(db)
    rules = domain_matchable_rules(db.list_custom_rules())
    ip_cidr_rules = [
        {"rule": r["rule"], "target": r["target"]}
        for r in rules
        if r["kind"] == "ip-cidr"
    ]
    forced = _forced_rules_list()
    common: dict[str, Any] = {
        "forced_rules": forced,
        "ip_cidr_rules": ip_cidr_rules,
        **drift,
    }
    # M-09: the forced rules are evaluated first when the input
    # itself decides them — a private IP, or a private-namespace
    # domain. (Whether a domain is CN cannot be decided here; the
    # note says so.)
    forced_match: dict[str, Any] | None = None
    try:
        ip = ipaddress.ip_address(domain)
        if ip.is_private:
            forced_match = {
                "rule": "GEOIP,PRIVATE,DIRECT",
                "rule_kind": "forced",
                "rule_source": "forced",
                "target": "DIRECT",
                "note": (
                    "强制 DIRECT（CN 出口防护）：该 IP 属于私有地址段，"
                    "强制规则 GEOIP,PRIVATE,DIRECT 先于所有自定义规则"
                    "与业务规则命中。"
                ),
            }
    except ValueError:
        if is_private_domain(domain):
            forced_match = {
                "rule": "GEOSITE,PRIVATE,DIRECT",
                "rule_kind": "forced",
                "rule_source": "forced",
                "target": "DIRECT",
                "note": (
                    "强制 DIRECT（CN 出口防护）：该域名属于私有域名范围，"
                    "强制规则 GEOSITE,PRIVATE,DIRECT 先于所有自定义规则"
                    "与业务规则命中。"
                ),
            }
    if forced_match is not None:
        return {
            **common,
            "domain": domain,
            "matched": True,
            "rule": forced_match["rule"],
            "rule_kind": forced_match["rule_kind"],
            "rule_source": forced_match["rule_source"],
            "group": None,
            "group_key": None,
            "target": "DIRECT",
            "effective_target": "DIRECT",
            "direct_reason": "forced",
            "policy": None,
            "main": None,
            "backups": [],
            "current": None,
            "current_source": None,
            "now_outside_group": None,
            "mihomo_reachable": None,
            "connection": "direct",
            "note": _with_drift(forced_match["note"], drift),
            "default_group": None,
        }
    matched = match_domain(domain, rules)
    if matched is None:
        default = resolve_group(db, "default", client)
        note = NO_MATCH_NOTE
        if ip_cidr_rules:
            note += (
                f" 另有 {len(ip_cidr_rules)} 条自定义 IP-CIDR 规则，"
                "仅对 IP 输入生效，本次域名诊断未参与匹配。"
            )
        return {
            **common,
            "domain": domain,
            "matched": False,
            "rule": None,
            "rule_kind": None,
            "rule_source": None,
            "group": None,
            "group_key": None,
            "target": None,
            "effective_target": None,
            "direct_reason": (
                "unbound_group"
                if default["effective_target"] == "DIRECT"
                else None
            ),
            "policy": None,
            "main": None,
            "backups": [],
            "current": None,
            "current_source": None,
            "now_outside_group": default.get("now_outside_group"),
            "mihomo_reachable": default["mihomo_reachable"],
            "connection": default["connection"],
            "note": _with_drift(note, drift),
            "default_group": default,
        }
    target = matched["target"]
    rule_kind = (
        "custom" if matched.get("source") == "custom" else matched["kind"]
    )
    rule_source = (
        "custom" if matched.get("source") == "custom" else "builtin"
    )
    note = CN_CAVEAT
    if matched["kind"] == "ip-cidr":
        note = (
            "自定义 IP-CIDR 规则命中（该输入为 IP 地址）。"
            + CN_CAVEAT
        )
    elif ip_cidr_rules:
        note += (
            f" 另有 {len(ip_cidr_rules)} 条自定义 IP-CIDR 规则，"
            "仅对 IP 输入生效，本次域名诊断未参与匹配。"
        )
    base: dict[str, Any] = {
        **common,
        "domain": domain,
        "matched": True,
        "rule": matched["rule"],
        "rule_kind": rule_kind,
        "rule_source": rule_source,
        "target": target,
        "note": _with_drift(note, drift),
        "default_group": None,
    }
    if target in ("DIRECT", "REJECT"):
        return {
            **base,
            "group": None,
            "group_key": None,
            "effective_target": target,
            "direct_reason": (
                "custom_direct" if target == "DIRECT" else None
            ),
            "policy": None,
            "main": None,
            "backups": [],
            "current": None,
            "current_source": None,
            "now_outside_group": None,
            "mihomo_reachable": None,
            "connection": _connection(target, None, None, None),
        }
    group_key = _DISPLAY_TO_KEY.get(target)
    if group_key is None:
        # Unknown target (e.g. a custom rule pointing at a typo'd
        # group name): report the match honestly, no group resolution.
        return {
            **base,
            "group": target,
            "group_key": None,
            "effective_target": target,
            "direct_reason": None,
            "policy": None,
            "main": None,
            "backups": [],
            "current": None,
            "current_source": None,
            "now_outside_group": None,
            "mihomo_reachable": None,
            "connection": "unknown",
        }
    resolved = resolve_group(db, group_key, client)
    direct_reason = None
    note_text = base["note"]
    if resolved["effective_target"] == "DIRECT":
        # The rule points at a real group, but the group has no
        # usable members: this is "业务组 DIRECT", not the forced
        # DIRECT of the CN egress guard (M-09).
        direct_reason = "unbound_group"
        note_text = (
            note_text
            + f" 业务组 DIRECT：{resolved['group']} 组未绑定可用节点，"
            "按空组 DIRECT 处理。"
        )
    return {
        **base,
        "note": note_text,
        "group": resolved["group"],
        "group_key": group_key,
        "effective_target": resolved["effective_target"],
        "direct_reason": direct_reason,
        "policy": resolved["policy"],
        "main": resolved["main"],
        "backups": resolved["backups"],
        "current": resolved["current"],
        "current_source": resolved["current_source"],
        "now_outside_group": resolved["now_outside_group"],
        "mihomo_reachable": resolved["mihomo_reachable"],
        "connection": resolved["connection"],
    }
