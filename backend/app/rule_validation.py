"""Shared custom-rule validation + forced-rule shadowing (M-12 / M-14).

One module owns everything every layer needs to agree on about a
custom rule, so the save path, the config compiler and the route
diagnostics can never drift apart again:

* :func:`validate_custom_rule` — strict validation. The rules router
  turns its :class:`ValueError` into a 400; the config compiler lets
  it propagate as a compile failure (a bad rule must never be emitted
  into a mihomo config). The diagnostics model uses it in filter mode
  (:func:`filter_valid_custom_rules`) — a rule the compiler would
  refuse is also invisible to diagnosis, so the two can never
  disagree about what is live.
* :func:`forced_shadow_reason` — a custom rule can never win against
  the forced rules (``GEOIP,PRIVATE`` / ``GEOSITE,PRIVATE`` /
  ``GEOSITE,CN`` / ``GEOIP,CN`` always come first in the generated
  config). A rule whose match scope is provably inside a forced
  rule's scope is *shadowed*: it is kept and compiled (harmless —
  mihomo evaluates in order), but the API marks it and the panel
  tells the user it never takes effect. The check is deliberately
  conservative: only cases decidable from the value alone are
  flagged (private IP ranges, private domains). Whether a domain
  belongs to GEOSITE,CN / GEOIP,CN cannot be decided from the domain
  string alone — the route diagnosis says so in its note instead.
  Moving custom rules before the forced rules would break the CN
  egress guard, so that is never done.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .models import GROUP_DISPLAY_NAMES

CUSTOM_RULE_TYPES = ("DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR")

VALID_RULE_TARGETS = frozenset(GROUP_DISPLAY_NAMES.values()) | {
    "DIRECT",
    "REJECT",
}

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Domains the mihomo GEOSITE,PRIVATE category covers (conservative
# subset: localhost + the well-known private suffixes). A custom rule
# matching only these can never fire — the forced private rule wins.
_PRIVATE_DOMAINS = frozenset({"localhost"})
_PRIVATE_SUFFIXES = (
    ".local",
    ".localhost",
    ".lan",
    ".home",
    ".internal",
    ".intranet",
    ".home.arpa",
)


def _validate_domain_value(value: str) -> None:
    """DOMAIN-SUFFIX values: dot-separated DNS labels, no empties."""
    if len(value) > 253:
        raise ValueError(f"invalid domain value (too long): {value!r}")
    for label in value.split("."):
        if not _LABEL_RE.match(label):
            raise ValueError(f"invalid domain value: {value!r}")


def validate_custom_rule(
    rule_type: str,
    value: str,
    target: str,
    *,
    check_target: bool = True,
) -> None:
    """Validate one custom rule; raise :class:`ValueError` if invalid.

    * ``rule_type`` must be a known custom-rule type.
    * ``value`` must be non-empty and contain no whitespace or commas
      (a comma would split the generated ``TYPE,value,target`` CSV
      line and corrupt the rule — M-12).
    * ``IP-CIDR`` values must parse with :mod:`ipaddress`.
    * ``DOMAIN-SUFFIX`` values must be valid DNS labels.
    * ``target`` must be a known group display name, ``DIRECT`` or
      ``REJECT`` (``check_target=False`` skips only this check — the
      diagnostics model keeps reporting legacy rows with a typo'd
      target honestly instead of hiding them).
    """
    if rule_type not in CUSTOM_RULE_TYPES:
        raise ValueError(f"invalid custom rule type: {rule_type!r}")
    value = (value or "").strip()
    if not value:
        raise ValueError("custom rule needs a non-empty value")
    if any(ch.isspace() or ch == "," for ch in value):
        raise ValueError(
            "rule value must not contain spaces or commas"
        )
    if rule_type == "IP-CIDR":
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"invalid IP-CIDR: {value!r}") from None
    elif rule_type == "DOMAIN-SUFFIX":
        _validate_domain_value(value.lower())
    if check_target:
        target = (target or "").strip()
        if target not in VALID_RULE_TARGETS:
            raise ValueError(
                f"invalid rule target: {target!r} "
                f"(valid: {sorted(VALID_RULE_TARGETS)})"
            )


def is_valid_custom_rule(
    rule: dict[str, Any], *, check_target: bool = True
) -> bool:
    """True when :func:`validate_custom_rule` accepts this rule dict."""
    try:
        validate_custom_rule(
            str(rule.get("type") or ""),
            str(rule.get("value") or ""),
            str(rule.get("target") or ""),
            check_target=check_target,
        )
    except ValueError:
        return False
    return True


def invalid_reason(
    rule: dict[str, Any], *, check_target: bool = True
) -> str | None:
    """The validation error for a rule dict, or None when it is valid."""
    try:
        validate_custom_rule(
            str(rule.get("type") or ""),
            str(rule.get("value") or ""),
            str(rule.get("target") or ""),
            check_target=check_target,
        )
    except ValueError as exc:
        return str(exc)
    return None


def filter_valid_custom_rules(
    rules: list[dict[str, Any]], *, check_target: bool = False
) -> list[dict[str, Any]]:
    """Return only the rules the compiler / diagnostics may use.

    Invalid rows (legacy data written before validation existed) are
    dropped here, never emitted into a config and never matched by
    diagnosis — both layers see the same rule set.
    """
    return [
        r for r in rules if is_valid_custom_rule(r, check_target=check_target)
    ]


def is_private_domain(domain: str) -> bool:
    """True when a domain is inside the private namespace (localhost
    or a private suffix) — the forced ``GEOSITE,PRIVATE,DIRECT``
    rule matches it before any custom/business rule can."""
    lowered = (domain or "").strip().lower()
    return lowered in _PRIVATE_DOMAINS or lowered.endswith(
        _PRIVATE_SUFFIXES
    )


def forced_shadow_reason(rule_type: str, value: str) -> str | None:
    """Why a custom rule can never fire, or None when it can.

    Only the mechanically provable cases are flagged: an IP-CIDR
    wholly inside a private range (forced ``GEOIP,PRIVATE,DIRECT``
    matches first) and a domain inside the private namespace
    (forced ``GEOSITE,PRIVATE,DIRECT`` matches first).
    """
    value = (value or "").strip()
    if not value:
        return None
    if rule_type == "IP-CIDR":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None  # invalid values are reported by validation
        if network.is_private:
            return (
                "被强制规则覆盖，未生效：该地址段属于私有地址，"
                "强制规则 GEOIP,PRIVATE,DIRECT 会先命中"
            )
        return None
    if rule_type == "DOMAIN-SUFFIX":
        lowered = value.lower()
        if lowered in _PRIVATE_DOMAINS or lowered.endswith(
            _PRIVATE_SUFFIXES
        ):
            return (
                "被强制规则覆盖，未生效：该域名属于私有域名范围，"
                "强制规则 GEOSITE,PRIVATE,DIRECT 会先命中"
            )
        return None
    if rule_type == "DOMAIN-KEYWORD":
        if value.lower() == "localhost":
            return (
                "被强制规则覆盖，未生效：该关键词只匹配私有域名，"
                "强制规则 GEOSITE,PRIVATE,DIRECT 会先命中"
            )
        return None
    return None
