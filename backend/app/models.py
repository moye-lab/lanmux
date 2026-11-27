"""Pydantic data models for LanMux (Phase 1: data layer).

These models describe the rows stored in SQLite (see ``database.py``) and
the inputs consumed by the config compiler (see ``config_builder.py``).
API schemas for Phase 2 will build on these, not replace them.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# Business group keys (stable identifiers) -> display names used in the
# generated mihomo config (proxy-group names and rule targets) and in the
# panel. All display names are English (v0.8.0 decision).
GroupKey = Literal[
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

GROUP_DISPLAY_NAMES: dict[str, str] = {
    "youtube": "YouTube",
    "telegram": "Telegram",
    "netflix": "Netflix",
    "tiktok": "TikTok",
    "spotify": "Spotify",
    "twitter": "Twitter",
    "facebook": "Facebook",
    "streaming": "Streaming",
    "ai": "AI",
    "google": "Google",
    "apple": "Apple",
    "microsoft": "Microsoft",
    "bilibili": "Bilibili",
    "default": "Default",
}

# Groups that intentionally stay unbound: the compiler's empty-group
# fallback makes them DIRECT groups (Apple/Microsoft/Bilibili accounts
# must never log in through an overseas proxy IP). The installer never
# inherits bindings into these (see :func:`app.init_lanmux.migrate_groups`).
DIRECT_GROUPS: frozenset[str] = frozenset({"apple", "microsoft", "bilibili"})

GroupRole = Literal["main", "backup"]
GroupMode = Literal["fallback", "url-test"]
CustomRuleType = Literal["DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR"]


class Node(BaseModel):
    """One VPS node. ``proxy`` is the mihomo proxy dict produced by
    :mod:`app.uri_parser` (its ``name`` should match ``name``)."""

    id: int | None = None
    name: str
    uri: str
    proxy: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: str | None = None


class GroupBinding(BaseModel):
    """One node bound to one business group.

    ``role``: ``main`` is tried first, ``backup`` nodes follow in
    insertion order. ``mode`` selects the mihomo proxy-group type;
    when bindings of one group disagree, the main binding's mode wins.
    """

    id: int | None = None
    group_key: GroupKey
    node_id: int
    role: GroupRole = "backup"
    mode: GroupMode = "fallback"


class CustomRule(BaseModel):
    """One user-defined rule, inserted after the forced rules and before
    the business rules. ``target`` is a business-group display name
    (e.g. ``YouTube``), ``DIRECT`` or ``REJECT``.

    ``sort_order`` is the generation order (L-04): rules compile in
    this order, and the panel lists them in this order. ``shadowed``
    (M-14) means a forced rule provably matches first, so this rule
    never fires; ``shadow_reason`` explains why. ``invalid_reason``
    is set for legacy rows that fail today's validation (they are
    never compiled or diagnosed — see ``rule_validation``).
    """

    id: int | None = None
    type: CustomRuleType
    value: str
    target: str
    enabled: bool = True
    sort_order: int = 0
    shadowed: bool = False
    shadow_reason: str | None = None
    invalid_reason: str | None = None


class Settings(BaseModel):
    """LanMux settings (key-value rows in SQLite, typed on read).

    ``ss_password`` and ``mihomo_secret`` are empty until the user sets
    them; :mod:`app.config_builder` refuses to compile while either is
    empty instead of emitting a ``${...}`` placeholder.
    """

    lan_ip: str = "127.0.0.1"
    ss_port: int = 10001
    ss_cipher: str = "aes-128-gcm"
    ss_password: str = ""
    mixed_port: int = 7890
    mixed_auth_user: str = ""
    mixed_auth_pass: str = ""
    mihomo_secret: str = ""
    admin_password_hash: str = ""
    # Port of the mihomo external controller (0.0.0.0:<port>).
    controller_port: int = 9090
    # Directory holding the metacubexd static files, rendered as
    # mihomo's ``external-ui`` (served at <controller>/ui/). Empty
    # means no ``external-ui`` key is emitted. Set by the installer
    # (Phase 4); not editable via the settings API.
    external_ui: str = ""


# ----------------------------------------------------------------------
# Phase 2: API request/response schemas
# ----------------------------------------------------------------------

class NodeOut(BaseModel):
    """One node as returned by the API (with last speedtest result)."""

    id: int
    name: str
    uri: str
    proxy: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: str | None = None
    last_delay_ms: int | None = None
    last_delay_at: str | None = None
    last_online: bool | None = None
    # Sanitized summary of the last speedtest failure (None when the
    # last probe succeeded or the node was never probed). Never holds
    # a URI, password or UUID (see nodes._sanitize_probe_error).
    last_error: str | None = None
    # Cumulative / consecutive speedtest failures (see
    # routers/nodes._store_result): failure_count never decreases,
    # consecutive_failures resets to 0 on the next success.
    failure_count: int = 0
    consecutive_failures: int = 0


class NodeCreate(BaseModel):
    uri: str
    name: str | None = None  # override the name parsed from the URI


class NodeUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    # Re-parse ``uri`` (replaces the proxy) or set ``proxy`` directly.
    # If both are given, ``uri`` wins.
    uri: str | None = None
    proxy: dict[str, Any] | None = None


class NodeBatchActionRequest(BaseModel):
    """Bulk enable, disable or delete nodes in a single config reload."""

    action: Literal["enable", "disable", "delete"]
    ids: list[int] = Field(default_factory=list)


class BatchImportRequest(BaseModel):
    text: str  # one URI per line; blank lines are skipped


class BatchImportError(BaseModel):
    line: int
    uri: str
    error: str


class BatchImportResult(BaseModel):
    imported: list[NodeOut] = Field(default_factory=list)
    errors: list[BatchImportError] = Field(default_factory=list)
    # Partial-submit semantics (L-21 / M-20 / L-06): ``partial`` is
    # True when at least one non-blank line was not imported (failed
    # or deduplicated). ``duplicates`` counts lines skipped as
    # duplicates (same URI or same name as an earlier line in this
    # batch or as a node already in the database); ``skipped`` counts
    # blank lines. ``imported`` always reflects the actual number of
    # rows written. ``warnings`` carries per-line non-fatal notices
    # (unknown/duplicate parameters, name truncation, ...).
    partial: bool = False
    duplicates: int = 0
    skipped: int = 0
    warnings: list[str] = Field(default_factory=list)
    reload: dict[str, Any] = Field(default_factory=dict)


class SpeedtestResult(BaseModel):
    id: int
    name: str
    online: bool
    delay_ms: int | None = None
    error: str | None = None


class BindingUpdate(BaseModel):
    main: int | None = None
    backups: list[int] = Field(default_factory=list)
    mode: GroupMode = "fallback"


class GroupBindingOut(BaseModel):
    group_key: str
    display_name: str
    main: int | None = None
    backups: list[int] = Field(default_factory=list)
    mode: GroupMode = "fallback"


class CustomRuleCreate(BaseModel):
    type: CustomRuleType
    value: str
    target: str
    enabled: bool = True


class CustomRuleUpdate(BaseModel):
    type: CustomRuleType | None = None
    value: str | None = None
    target: str | None = None
    enabled: bool | None = None


class CustomRuleMove(BaseModel):
    """Move a custom rule one step in generation order (L-04)."""

    direction: Literal["up", "down"]


class SettingsOut(BaseModel):
    """Desensitized settings — secrets are never returned, only flags."""

    lan_ip: str
    ss_port: int
    ss_cipher: str
    ss_password_set: bool
    mixed_port: int
    mixed_auth_user: str
    mixed_auth_pass_set: bool
    mihomo_secret_set: bool
    controller_port: int


class SettingsUpdate(BaseModel):
    """Partial update — only provided (non-None) fields change."""

    lan_ip: str | None = None
    ss_port: int | None = None
    ss_cipher: str | None = None
    ss_password: str | None = None
    mixed_port: int | None = None
    mixed_auth_user: str | None = None
    mixed_auth_pass: str | None = None
    mihomo_secret: str | None = None
    controller_port: int | None = None


class AdminPasswordChange(BaseModel):
    current_password: str
    new_password: str


class LoginRequest(BaseModel):
    password: str


class RouteCheckRequest(BaseModel):
    """Route diagnosis input: a bare domain or a full URL."""

    domain: str


class SetupRequest(BaseModel):
    """First-run setup: set the admin password (only when none exists).

    ``setup_token`` is the one-time token printed in the startup log
    when no admin password exists (H-02); it is required and becomes
    invalid as soon as setup succeeds.
    """

    password: str
    setup_token: str = ""


class LoginResponse(BaseModel):
    token: str
    expires_in: int = 86400  # seconds (24h)
