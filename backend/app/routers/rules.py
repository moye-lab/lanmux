"""Group bindings + custom rules routes.

Every mutation recompiles + safe-reloads the live config; the
``reload`` object in the response reports the outcome (see
:func:`app.deps.apply_and_report`).

Bindings: per business group, one main node + any number of backup
nodes + a mode (``fallback`` / ``url-test``). ``url-test`` groups omit
``tolerance`` (mihomo default 50 — locked decision).

Custom rule targets must be a business-group display name, ``DIRECT``
or ``REJECT``. Rule values are validated with the shared validator
(:mod:`app.rule_validation`, M-12) — unknown target, comma/space in
the value, invalid CIDR or invalid domain all return 400. Rules are
listed in generation order (``sort_order``, L-04) and each carries a
``shadowed`` flag when a forced rule provably matches first (M-14).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_auth
from ..config_service import ConfigService
from ..database import Database
from ..deps import apply_and_report, get_config_service, get_db
from ..models import (
    GROUP_DISPLAY_NAMES,
    BindingUpdate,
    CustomRule,
    CustomRuleCreate,
    CustomRuleMove,
    CustomRuleUpdate,
    GroupBindingOut,
)
from ..rule_validation import (
    VALID_RULE_TARGETS,
    forced_shadow_reason,
    invalid_reason,
    validate_custom_rule,
)

router = APIRouter(
    prefix="/api/rules",
    tags=["rules"],
    dependencies=[Depends(require_auth)],
)

VALID_TARGETS = set(VALID_RULE_TARGETS)


def _validate_group_key(group_key: str) -> None:
    if group_key not in GROUP_DISPLAY_NAMES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown group: {group_key!r} "
            f"(valid: {sorted(GROUP_DISPLAY_NAMES)})",
        )


def _validate_target(target: str) -> None:
    try:
        validate_custom_rule("DOMAIN-SUFFIX", "example.org", target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _validate_value(rule_type: str, value: str) -> None:
    try:
        validate_custom_rule(rule_type, value, "DIRECT")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _rule_out(rule: dict[str, Any]) -> CustomRule:
    """A rule row as the API returns it, with shadow/validity flags."""
    reason = forced_shadow_reason(
        str(rule.get("type") or ""), str(rule.get("value") or "")
    )
    return CustomRule(
        **{
            **rule,
            "shadowed": reason is not None,
            "shadow_reason": reason,
            "invalid_reason": invalid_reason(rule),
        }
    )


def _bindings_out(db: Database, group_key: str) -> GroupBindingOut:
    rows = db.list_bindings(group_key)
    main = next((r for r in rows if r["role"] == "main"), None)
    mode = main["mode"] if main else (rows[0]["mode"] if rows else "fallback")
    return GroupBindingOut(
        group_key=group_key,
        display_name=GROUP_DISPLAY_NAMES[group_key],
        main=main["node_id"] if main else None,
        backups=[r["node_id"] for r in rows if r["role"] == "backup"],
        mode=mode,
    )


# ---------------------------------------------------------------- bindings
@router.get("/bindings", response_model=dict[str, GroupBindingOut])
def list_bindings(db: Database = Depends(get_db)):
    return {
        key: _bindings_out(db, key) for key in GROUP_DISPLAY_NAMES
    }


@router.get("/bindings/{group_key}", response_model=GroupBindingOut)
def get_binding(group_key: str, db: Database = Depends(get_db)):
    _validate_group_key(group_key)
    return _bindings_out(db, group_key)


@router.put("/bindings/{group_key}", response_model=dict)
def update_binding(
    group_key: str,
    body: BindingUpdate,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    _validate_group_key(group_key)
    node_ids = [body.main] if body.main is not None else []
    node_ids += body.backups
    if len(set(node_ids)) != len(node_ids):
        raise HTTPException(
            status_code=400,
            detail="main node and backup nodes must be distinct",
        )
    for node_id in node_ids:
        if db.get_node(node_id) is None:
            raise HTTPException(
                status_code=400, detail=f"unknown node id: {node_id}"
            )
    # M-24: one transaction (clear + inserts share a lock hold and a
    # single commit) — concurrent PUTs can no longer interleave into
    # two mains. The DB layer re-validates and raises ValueError on a
    # stale check (node deleted between the checks above and the
    # write); that is a 400, not a 500.
    try:
        db.replace_bindings(group_key, body.main, body.backups, body.mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "binding": _bindings_out(db, group_key),
        "reload": apply_and_report(service),
    }


# -------------------------------------------------------------- custom rules
@router.get("/custom", response_model=list[CustomRule])
def list_custom_rules(db: Database = Depends(get_db)):
    # Generation order (sort_order, L-03): the panel lists rules in
    # the exact order they are compiled into the config.
    return [_rule_out(r) for r in db.list_custom_rules()]


@router.post("/custom", response_model=dict)
def create_custom_rule(
    body: CustomRuleCreate,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    _validate_target(body.target)
    _validate_value(body.type, body.value)
    rule_id = db.add_custom_rule(
        body.type, body.value.strip(), body.target, body.enabled
    )
    rule = db.get_custom_rule(rule_id)
    assert rule is not None
    return {"rule": _rule_out(rule), "reload": apply_and_report(service)}


@router.put("/custom/{rule_id}", response_model=dict)
def update_custom_rule(
    rule_id: int,
    body: CustomRuleUpdate,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    rule = db.get_custom_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"rule {rule_id} not found")
    # Validate the merged rule, not just the changed fields: a type
    # change can invalidate the existing value (and vice versa).
    merged_type = body.type or rule["type"]
    merged_value = (
        body.value.strip() if body.value is not None else rule["value"]
    )
    merged_target = body.target if body.target is not None else rule["target"]
    try:
        validate_custom_rule(merged_type, merged_value, merged_target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    fields: dict[str, Any] = {}
    if body.type is not None:
        fields["type"] = body.type
    if body.value is not None:
        fields["value"] = body.value.strip()
    if body.target is not None:
        fields["target"] = body.target
    if body.enabled is not None:
        fields["enabled"] = body.enabled
    if fields:
        db.update_custom_rule(rule_id, **fields)
    updated = db.get_custom_rule(rule_id)
    assert updated is not None
    return {
        "rule": _rule_out(updated),
        "reload": apply_and_report(service),
    }


@router.post("/custom/{rule_id}/move", response_model=dict)
def move_custom_rule(
    rule_id: int,
    body: CustomRuleMove,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    """Move a rule one step up/down in generation order (L-04).

    Order is persisted (``sort_order``) and reflected in the next
    compiled config. Moving an edge rule is a no-op (``moved`` false).
    """
    rule = db.get_custom_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"rule {rule_id} not found")
    moved = db.move_custom_rule(rule_id, body.direction)
    updated = db.get_custom_rule(rule_id)
    assert updated is not None
    return {
        "rule": _rule_out(updated),
        "moved": moved,
        "reload": apply_and_report(service),
    }


@router.delete("/custom/{rule_id}")
def delete_custom_rule(
    rule_id: int,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    if db.get_custom_rule(rule_id) is None:
        raise HTTPException(status_code=404, detail=f"rule {rule_id} not found")
    db.delete_custom_rule(rule_id)
    return {"ok": True, "reload": apply_and_report(service)}
