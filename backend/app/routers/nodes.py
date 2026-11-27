"""Node management routes.

Import (single URI / batch), CRUD, and speedtests via the mihomo
Controller API. Every mutation recompiles + safe-reloads the live
config; the ``reload`` object in the response reports the outcome
(see :func:`app.deps.apply_and_report` — a failed reload never breaks
the live config, and the DB change is kept as the source of truth).

Speedtest policy (locked): max 5 concurrent probes, 5s timeout per
node. Results are stored on the node row (``last_delay_ms`` /
``last_delay_at`` / ``last_online``). Request-level guard (M-31):
at most 2 concurrent speedtest *requests* (shared with the
diagnostics probes) + per-IP rate limit — the 5-worker pool inside
one request is untouched, and results are never deduped (each run
is a state-changing measurement).
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from ..auth import require_auth
from ..config_builder import HEALTH_CHECK_URL, proxy_names_for_nodes
from ..config_service import ConfigService
from ..database import Database
from ..deps import apply_and_report, get_config_service, get_db, get_mihomo_client
from ..masking import mask_node
from ..mihomo_client import MihomoClient, MihomoError
from ..probe_guard import ProbeBusyError, probe_guard
from ..models import (
    BatchImportError,
    BatchImportRequest,
    BatchImportResult,
    NodeBatchActionRequest,
    NodeCreate,
    NodeOut,
    NodeUpdate,
    SpeedtestResult,
)
from ..uri_parser import (
    mask_uri_for_log,
    normalize_node_name,
    parse_uri,
    parse_uri_with_warnings,
    validate_proxy_dict,
)

router = APIRouter(
    prefix="/api/nodes",
    tags=["nodes"],
    dependencies=[Depends(require_auth)],
)

SPEEDTEST_MAX_WORKERS = 5
SPEEDTEST_TIMEOUT_S = 5

logger = logging.getLogger(__name__)

#: Maximum number of non-blank lines accepted in one batch import
#: (M-20). Larger batches are rejected with HTTP 400 before any
#: row is written.
BATCH_IMPORT_MAX_LINES = 500

_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+")


def _sanitize_probe_error(message: str | None) -> str:
    """Collapse a probe failure to one safe line for storage.

    Probe errors come from mihomo (timeouts, dial failures, HTTP
    errors) and must never carry a node URI, password or UUID into
    the database: URL-shaped substrings are redacted, whitespace is
    collapsed, and the result is capped at 120 characters.
    """
    text = " ".join(str(message or "").split())
    text = _URL_RE.sub("[url]", text)
    return (text[:120] or "probe failed").strip()


def _node_out(node: dict[str, Any], *, reveal: bool = False) -> NodeOut:
    """Node API shape. Masked by default (M-05): list / single reads
    never carry plaintext credentials — ``proxy`` secrets and the
    credential part of ``uri`` are masked. Pass ``reveal=True`` only
    for the explicit per-node export endpoint below."""
    return NodeOut(**(node if reveal else mask_node(node)))


def _get_node_or_404(db: Database, node_id: int) -> dict[str, Any]:
    node = db.get_node(node_id)
    if node is None:
        raise HTTPException(status_code=404, detail=f"node {node_id} not found")
    return node


def _insert_node(
    db: Database,
    uri: str,
    proxy: dict[str, Any],
    warnings: list[str] | None = None,
) -> NodeOut:
    """Validate a parsed proxy dict and write the node row (H-11).

    The parsed proxy is re-checked with the shared
    :func:`validate_proxy_dict` so the import path enforces exactly
    the same rules as the PUT path; the final name runs through the
    length/fallback rules (:func:`normalize_node_name`).
    """
    checked = validate_proxy_dict(proxy, warnings=warnings)
    node_name = normalize_node_name(checked["name"], warnings=warnings)
    checked["name"] = node_name
    node_id = db.add_node(node_name, uri, checked)
    node = db.get_node(node_id)
    assert node is not None  # just inserted
    return _node_out(node)


def _import_one(
    db: Database,
    uri: str,
    name: str | None = None,
    warnings: list[str] | None = None,
) -> NodeOut:
    proxy, parse_warnings = parse_uri_with_warnings(uri)
    if warnings is not None:
        warnings.extend(parse_warnings)
    if name is not None and name.strip():
        proxy["name"] = name.strip()
    return _insert_node(db, uri, proxy, warnings)


def _probe_node(
    client: MihomoClient,
    node: dict[str, Any],
    proxy_name: str,
) -> SpeedtestResult:
    """Delay-test one node (pure probe — no DB access).

    Runs inside the speedtest thread pool; the shared sqlite3
    connection must only be touched from the request thread, so
    storing the result is the caller's job (:func:`_store_result`).
    """
    if not node["enabled"]:
        return SpeedtestResult(
            id=node["id"],
            name=node["name"],
            online=False,
            error="node is disabled",
        )
    try:
        delay = client.test_delay(
            proxy_name, HEALTH_CHECK_URL, timeout=SPEEDTEST_TIMEOUT_S
        )
    except MihomoError as exc:
        return SpeedtestResult(
            id=node["id"], name=node["name"], online=False, error=exc.message
        )
    return SpeedtestResult(
        id=node["id"], name=node["name"], online=True, delay_ms=delay
    )


def _store_result(db: Database, result: SpeedtestResult) -> None:
    """Persist a speedtest result on the node row (request thread).

    A failed probe stores a sanitized one-line reason (``last_error``);
    a successful probe clears it. The write itself is one atomic
    UPDATE (``Database.record_speedtest_result``, M-30) — the old
    read-modify-write (read counters, +1 in Python, write back) lost
    increments under concurrent speedtests.
    """
    if result.error == "node is disabled":
        return
    db.record_speedtest_result(
        result.id,
        online=result.online,
        delay_ms=result.delay_ms,
        last_error=(
            None
            if result.online
            else _sanitize_probe_error(result.error)
        ),
        last_delay_at=datetime.now(timezone.utc).isoformat(),
    )


# ------------------------------------------------------------------- CRUD
@router.get("", response_model=list[NodeOut])
def list_nodes(db: Database = Depends(get_db)):
    return [_node_out(n) for n in db.list_nodes()]


@router.get("/{node_id}", response_model=NodeOut)
def get_node(node_id: int, db: Database = Depends(get_db)):
    return _node_out(_get_node_or_404(db, node_id))


@router.get("/{node_id}/export")
def export_node(node_id: int, db: Database = Depends(get_db)):
    """Return ONE node with plaintext credentials (M-05).

    This is the only read path that reveals secrets, and only for
    the single node the operator explicitly asked to copy / export /
    edit. The reveal is written to the audit log (``audit_log``
    table) so a credential disclosure can be traced; the response
    itself carries a do-not-share warning.
    """
    node = _get_node_or_404(db, node_id)
    db.log_audit(
        "node_export",
        node_id,
        f"exported node {node_id} ({node['name']})",
    )
    logger.info("node_export node_id=%s name=%s", node_id, node["name"])
    return {
        "node": _node_out(node, reveal=True),
        "warning": "包含明文凭证，仅供本次复制/导出使用，请勿分享",
    }


@router.post("", response_model=dict)
def create_node(
    body: NodeCreate,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    warnings: list[str] = []
    try:
        node = _import_one(db, body.uri, body.name, warnings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"node": node, "warnings": warnings, "reload": apply_and_report(service)}


@router.post("/batch", response_model=BatchImportResult)
def batch_import(
    body: BatchImportRequest,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    lines = body.text.splitlines()
    entries = [
        (line_no, raw.strip())
        for line_no, raw in enumerate(lines, start=1)
        if raw.strip()
    ]
    skipped = len(lines) - len(entries)
    if len(entries) > BATCH_IMPORT_MAX_LINES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"batch import limited to {BATCH_IMPORT_MAX_LINES} lines, "
                f"got {len(entries)}"
            ),
        )
    # Dedup (M-20) is by URI and by final node name, against both
    # earlier lines in this batch and nodes already in the database.
    existing = db.list_nodes()
    existing_uris = {n["uri"] for n in existing}
    existing_names = {n["name"] for n in existing}
    seen_uris: set[str] = set()
    seen_names: set[str] = set()
    imported: list[NodeOut] = []
    errors: list[BatchImportError] = []
    warnings: list[str] = []
    duplicates = 0
    for line_no, uri in entries:
        if uri in seen_uris or uri in existing_uris:
            duplicates += 1
            warnings.append(f"line {line_no}: duplicate URI skipped")
            continue
        try:
            proxy, parse_warnings = parse_uri_with_warnings(uri)
        except ValueError as exc:
            errors.append(
                BatchImportError(
                    line=line_no,
                    uri=mask_uri_for_log(uri),
                    error=str(exc),
                )
            )
            continue
        name = normalize_node_name(proxy.get("name"))
        if name in seen_names or name in existing_names:
            duplicates += 1
            warnings.append(
                f"line {line_no}: duplicate node name {name!r} skipped"
            )
            continue
        warnings.extend(
            f"line {line_no}: {w}" for w in parse_warnings
        )
        try:
            imported.append(_insert_node(db, uri, proxy, warnings))
        except ValueError as exc:
            errors.append(
                BatchImportError(
                    line=line_no,
                    uri=mask_uri_for_log(uri),
                    error=str(exc),
                )
            )
            continue
        seen_uris.add(uri)
        seen_names.add(name)
    # One apply for the whole batch (not one per node).
    reload = apply_and_report(service) if imported else {
        "ok": True, "error": None, "stage": None, "rolled_back": False,
    }
    return BatchImportResult(
        imported=imported,
        errors=errors,
        # Partial-submit semantics (L-21): say so explicitly when
        # any line failed or was deduplicated; counts are the actual
        # rows written / failed / deduplicated / blank (L-06).
        partial=bool(errors or duplicates),
        duplicates=duplicates,
        skipped=skipped,
        warnings=warnings,
        reload=reload,
    )


@router.put("/{node_id}", response_model=dict)
def update_node(
    node_id: int,
    body: NodeUpdate,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    node = _get_node_or_404(db, node_id)
    warnings: list[str] = []
    fields: dict[str, Any] = {}
    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(
                status_code=400, detail="node name must not be empty"
            )
        fields["name"] = normalize_node_name(name, warnings=warnings)
    if body.enabled is not None:
        fields["enabled"] = body.enabled
    if body.uri is not None:
        # Re-parse: the proxy is replaced wholesale. The existing
        # name is kept (M-21) unless the request explicitly names
        # a new one — the URI fragment must never silently rename
        # the node.
        try:
            proxy = validate_proxy_dict(
                parse_uri(body.uri), warnings=warnings
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        fields["uri"] = body.uri
        proxy["name"] = fields.get("name", node["name"])
        fields["proxy"] = proxy
    elif body.proxy is not None:
        # PUT proxy JSON gets the same strict validation as URI
        # parsing (H-11): type whitelist, port range, UUID format,
        # required per-type fields. Anything invalid is HTTP 400
        # and nothing is written.
        try:
            proxy = validate_proxy_dict(body.proxy, warnings=warnings)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        proxy["name"] = fields.get("name", node["name"])
        fields["proxy"] = proxy
    if "name" in fields and "proxy" not in fields:
        # Renaming keeps the stored proxy's name in sync.
        proxy = dict(node["proxy"])
        proxy["name"] = fields["name"]
        fields["proxy"] = proxy
    if fields:
        db.update_node(node_id, **fields)
    updated = db.get_node(node_id)
    assert updated is not None
    return {
        "node": _node_out(updated),
        "warnings": warnings,
        "reload": apply_and_report(service),
    }


@router.delete("/{node_id}")
def delete_node(
    node_id: int,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    _get_node_or_404(db, node_id)
    db.delete_node(node_id)
    return {"ok": True, "reload": apply_and_report(service)}


@router.post("/batch-action")
def batch_action(
    body: NodeBatchActionRequest,
    db: Database = Depends(get_db),
    service: ConfigService = Depends(get_config_service),
):
    unique_ids = list(dict.fromkeys(body.ids))
    if not unique_ids:
        raise HTTPException(
            status_code=400, detail="ids must not be empty"
        )
    affected = 0
    for node_id in unique_ids:
        if db.get_node(node_id) is None:
            continue
        if body.action == "enable":
            db.update_node(node_id, enabled=True)
        elif body.action == "disable":
            db.update_node(node_id, enabled=False)
        elif body.action == "delete":
            db.delete_node(node_id)
        affected += 1
    reload = apply_and_report(service) if affected else {
        "ok": True, "error": None, "stage": None, "rolled_back": False,
    }
    return {
        "ok": True,
        "action": body.action,
        "affected": affected,
        "reload": reload,
    }


# -------------------------------------------------------------- speedtest
def _check_probe_rate(request: Request) -> None:
    client_id = (
        request.client.host if request.client is not None else "unknown"
    )
    if not probe_guard.check_rate(client_id):
        raise HTTPException(
            status_code=429,
            detail="too many probe requests; try again in a minute",
        )


@router.post("/speedtest-all")
def speedtest_all(
    request: Request,
    db: Database = Depends(get_db),
    client: MihomoClient = Depends(get_mihomo_client),
):
    # M-31: at most 2 concurrent speedtest *requests* (the probe
    # guard is shared with the diagnostics probes) + per-IP rate
    # limit. The 5-worker pool inside one request is the locked
    # per-request policy and is untouched. Results are NOT deduped:
    # every run is a state-changing measurement (failure counters,
    # last_delay_at) — reusing a previous result would falsify the
    # health data.
    _check_probe_rate(request)
    try:
        with probe_guard.run_probe():
            return _speedtest_all(db, client)
    except ProbeBusyError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


def _speedtest_all(
    db: Database,
    client: MihomoClient,
):
    nodes = [n for n in db.list_nodes() if n["enabled"]]
    names = proxy_names_for_nodes(nodes)
    results: list[SpeedtestResult] = []
    with ThreadPoolExecutor(max_workers=SPEEDTEST_MAX_WORKERS) as pool:
        futures = [
            pool.submit(_probe_node, client, node, names[node["id"]])
            for node in nodes
        ]
        for future in futures:
            results.append(future.result())
    results.sort(key=lambda r: r.id)
    for result in results:
        _store_result(db, result)
    return {"results": results, "tested": len(results)}


@router.post("/{node_id}/speedtest", response_model=SpeedtestResult)
def speedtest_one(
    node_id: int,
    request: Request,
    db: Database = Depends(get_db),
    client: MihomoClient = Depends(get_mihomo_client),
):
    _check_probe_rate(request)
    node = _get_node_or_404(db, node_id)
    names = proxy_names_for_nodes(db.list_nodes())
    proxy_name = names.get(node_id)
    if proxy_name is None:
        # Disabled node (not in the enabled-names map).
        return SpeedtestResult(
            id=node["id"],
            name=node["name"],
            online=False,
            error="node is disabled",
        )
    try:
        with probe_guard.run_probe():
            result = _probe_node(client, node, proxy_name)
    except ProbeBusyError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    _store_result(db, result)
    return result
