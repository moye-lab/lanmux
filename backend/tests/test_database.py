"""Unit tests for app.database (SQLite CRUD + settings defaults)."""

import sqlite3

import pytest

from app.config_builder import build_config, dead_group_keys
from app.database import SCHEMA, Database

_SETTINGS = {
    "lan_ip": "10.0.0.2",
    "ss_port": 10001,
    "ss_cipher": "aes-128-gcm",
    "ss_password": "fake-ss-password",
    "mixed_port": 7890,
    "mihomo_secret": "fake-mihomo-secret",
    "controller_port": 9090,
}


def _proxy(name):
    return {
        "name": name,
        "type": "ss",
        "server": "example.com",
        "port": 8388,
        "cipher": "aes-128-gcm",
        "password": "fake-pass",
    }


@pytest.fixture
def db(tmp_path):
    handle = Database(tmp_path / "lanmux.db")
    yield handle
    handle.close()


def test_nodes_crud(db):
    node_id = db.add_node(
        "Node-A", "ss://fake@example.com:8388",
        {"name": "Node-A", "type": "ss", "server": "example.com",
         "port": 8388, "cipher": "aes-128-gcm", "password": "fake"},
    )
    node = db.get_node(node_id)
    assert node["name"] == "Node-A"
    assert node["proxy"]["server"] == "example.com"
    assert node["enabled"] is True
    assert db.get_node(99999) is None

    db.update_node(node_id, name="Node-A2", enabled=False)
    assert db.get_node(node_id)["name"] == "Node-A2"
    assert db.list_nodes(enabled_only=True) == []
    assert len(db.list_nodes()) == 1

    with pytest.raises(ValueError, match="unknown node field"):
        db.update_node(node_id, nope="x")

    db.delete_node(node_id)
    assert db.list_nodes() == []


def test_add_node_rejects_invalid_proxy_json(db):
    # M-23: writing a proxy that is not valid JSON (or not an object)
    # is refused at the write, not discovered later by readers.
    with pytest.raises(ValueError, match="not valid JSON"):
        db.add_node("Bad", "ss://fake@example.com:8388", "{not json")
    with pytest.raises(ValueError, match="must encode an object"):
        db.add_node("Bad", "ss://fake@example.com:8388", "[1, 2]")
    assert db.list_nodes() == []


def test_corrupt_proxy_json_row_is_skipped_not_fatal(db):
    # M-23: one row with corrupt proxy_json must not 500 the whole
    # node list — it is skipped (with a warning) and the good rows
    # still read.
    good_id = db.add_node(
        "Good", "ss://fake@example.com:8388",
        {"name": "Good", "type": "ss", "server": "example.com",
         "port": 8388, "cipher": "aes-128-gcm", "password": "fake"},
    )
    bad_id = db.add_node(
        "Bad", "ss://fake@example.com:8388",
        {"name": "Bad", "type": "ss"},
    )
    db.conn.execute(
        "UPDATE nodes SET proxy_json = ? WHERE id = ?",
        ("{corrupt", bad_id),
    )
    db.conn.commit()
    nodes = db.list_nodes()
    assert [n["id"] for n in nodes] == [good_id]
    assert db.get_node(good_id)["name"] == "Good"
    assert db.get_node(bad_id) is None  # unreadable row reads as missing
    with pytest.raises(ValueError, match="not valid JSON"):
        db.update_node(bad_id, proxy="{also corrupt")


def test_bindings_upsert_and_delete_keeps_dangling_binding(db):
    """Upsert still dedupes; deleting a node KEEPS its binding rows.

    H-03 fail-closed: the old schema cascaded the delete, so a group
    whose last node was deleted read as "never bound" and silently
    compiled to DIRECT. Now the row survives as a dangling binding
    (node_id points at a deleted node) and the group resolves to
    REJECT via :func:`app.config_builder.dead_group_keys`.
    """
    node_id = db.add_node("N", "ss://fake@example.com:8388", {"type": "ss"})
    db.set_binding("youtube", node_id, role="backup")
    db.set_binding("youtube", node_id, role="main", mode="url-test")
    bindings = db.list_bindings("youtube")
    assert len(bindings) == 1  # upsert, not a duplicate row
    assert bindings[0]["role"] == "main"
    assert bindings[0]["mode"] == "url-test"

    with pytest.raises(ValueError, match="invalid binding role"):
        db.set_binding("youtube", node_id, role="primary")
    with pytest.raises(ValueError, match="invalid binding mode"):
        db.set_binding("youtube", node_id, mode="random")

    # Deleting a referenced node must succeed (no FK / NO ACTION
    # block) and must NOT remove the binding row.
    db.delete_node(node_id)
    assert db.get_node(node_id) is None
    kept = db.list_bindings("youtube")
    assert len(kept) == 1
    assert kept[0]["node_id"] == node_id
    assert kept[0]["role"] == "main"
    assert kept[0]["mode"] == "url-test"
    assert dead_group_keys(db.list_nodes(), db.list_bindings()) == [
        "youtube"
    ]


def test_delete_last_node_group_compiles_to_reject(db):
    """Deleting every bound node leaves the group REJECT, not DIRECT."""
    main_id = db.add_node("A", "ss://a@example.com:8388", _proxy("A"))
    backup_id = db.add_node("B", "ss://b@example.com:8388", _proxy("B"))
    db.set_binding("youtube", main_id, role="main")
    db.set_binding("youtube", backup_id, role="backup")
    db.set_binding("default", main_id, role="main")

    db.delete_node(main_id)
    # One live backup keeps the group proxied.
    assert dead_group_keys(db.list_nodes(), db.list_bindings()) == [
        "default"
    ]

    db.delete_node(backup_id)
    assert len(db.list_bindings("youtube")) == 2  # both rows kept
    config = build_config(
        db.list_nodes(), db.list_bindings(), [], _SETTINGS
    )
    groups = {g["name"]: g for g in config["proxy-groups"]}
    assert groups["YouTube"]["proxies"] == ["REJECT"]
    assert groups["Default"]["proxies"] == ["REJECT"]
    assert set(
        dead_group_keys(db.list_nodes(), db.list_bindings())
    ) == {"youtube", "default"}


def test_recreated_same_name_node_does_not_revive_old_binding(db):
    """A re-added same-name node gets a new id and must NOT revive
    the old dangling binding; only an explicit rebind revives it."""
    old_id = db.add_node("N", "ss://fake@example.com:8388", _proxy("N"))
    db.set_binding("youtube", old_id, role="main")
    db.delete_node(old_id)

    new_id = db.add_node("N", "ss://fake@example.com:8388", _proxy("N"))
    assert new_id != old_id
    assert db.list_bindings("youtube")[0]["node_id"] == old_id
    assert dead_group_keys(db.list_nodes(), db.list_bindings()) == [
        "youtube"
    ]

    db.set_binding("youtube", new_id, role="main")
    assert dead_group_keys(db.list_nodes(), db.list_bindings()) == []


def test_old_schema_migrates_and_keeps_bindings(tmp_path):
    """An old ON DELETE CASCADE database migrates on open: all data
    intact, the FK gone, and deleting a node keeps its bindings.

    The fixture is built with the pre-fix schema (old
    ``group_bindings`` DDL derived from the current SCHEMA by
    restoring the CASCADE clause), then opened through
    :class:`app.database.Database`, which runs the rebuild migration.
    """
    old_schema = SCHEMA.replace(
        "node_id INTEGER NOT NULL,",
        "node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,",
    )
    assert "ON DELETE CASCADE" in old_schema
    path = tmp_path / "lanmux.db"
    raw = sqlite3.connect(str(path))
    try:
        raw.executescript(old_schema)
        raw.execute(
            "INSERT INTO nodes (id, name, uri, proxy_json, enabled)"
            " VALUES (1, 'N1', 'ss://n1@example.com:8388',"
            " '{\"type\": \"ss\"}', 1),"
            " (2, 'N2', 'ss://n2@example.com:8388',"
            " '{\"type\": \"ss\"}', 1)"
        )
        raw.execute(
            "INSERT INTO group_bindings (id, group_key, node_id, role, mode)"
            " VALUES (1, 'youtube', 1, 'main', 'fallback'),"
            " (2, 'youtube', 2, 'backup', 'fallback'),"
            " (3, 'default', 1, 'main', 'fallback')"
        )
        raw.commit()
        assert [
            row[2]  # foreign_key_list: id, seq, table, ...
            for row in raw.execute(
                "PRAGMA foreign_key_list(group_bindings)"
            )
        ] == ["nodes"]
        assert raw.execute(
            "SELECT COUNT(*) FROM group_bindings"
        ).fetchone()[0] == 3
    finally:
        raw.close()

    handle = Database(path)
    try:
        # FK gone, pragma back ON, schema otherwise identical to a
        # fresh database.
        assert handle.conn.execute(
            "PRAGMA foreign_key_list(group_bindings)"
        ).fetchall() == []
        assert handle.conn.execute(
            "PRAGMA foreign_keys"
        ).fetchone()[0] == 1
        assert [n["id"] for n in handle.list_nodes()] == [1, 2]
        assert len(handle.list_bindings()) == 3
        assert handle.list_bindings("youtube")[0]["node_id"] == 1

        # Deleting a referenced node now succeeds and keeps bindings.
        handle.delete_node(1)
        assert handle.get_node(1) is None
        assert [n["id"] for n in handle.list_nodes()] == [2]
        assert handle.get_node(2)["name"] == "N2"
        assert len(handle.list_bindings("youtube")) == 2
        assert len(handle.list_bindings("default")) == 1
        assert dead_group_keys(
            handle.list_nodes(), handle.list_bindings()
        ) == ["default"]

        handle.delete_node(2)
        assert set(
            dead_group_keys(handle.list_nodes(), handle.list_bindings())
        ) == {"youtube", "default"}
        assert len(handle.list_bindings()) == 3  # nothing lost
    finally:
        handle.close()

    # Migration is idempotent: reopening keeps data and stays FK-free.
    fresh = Database(tmp_path / "fresh.db")
    try:
        fresh_info = [
            tuple(r)
            for r in fresh.conn.execute(
                "PRAGMA table_info(group_bindings)"
            )
        ]
        fresh_idx = sorted(
            tuple(r)
            for r in fresh.conn.execute(
                "PRAGMA index_list(group_bindings)"
            )
        )
    finally:
        fresh.close()
    reopened = Database(path)
    try:
        assert reopened.conn.execute(
            "PRAGMA foreign_key_list(group_bindings)"
        ).fetchall() == []
        assert [
            tuple(r)
            for r in reopened.conn.execute(
                "PRAGMA table_info(group_bindings)"
            )
        ] == fresh_info
        assert sorted(
            tuple(r)
            for r in reopened.conn.execute(
                "PRAGMA index_list(group_bindings)"
            )
        ) == fresh_idx
        assert len(reopened.list_bindings()) == 3
        assert reopened.list_nodes() == []
    finally:
        reopened.close()


def test_bindings_order_main_first(db):
    main_id = db.add_node("M", "ss://m@example.com:8388", {"type": "ss"})
    backup_id = db.add_node("B", "ss://b@example.com:8388", {"type": "ss"})
    db.set_binding("ai", backup_id, role="backup")
    db.set_binding("ai", main_id, role="main")
    ordered = [b["node_id"] for b in db.list_bindings("ai")]
    assert ordered == [main_id, backup_id]

    db.clear_bindings("ai")
    assert db.list_bindings("ai") == []


def test_custom_rules_crud(db):
    rule_id = db.add_custom_rule("DOMAIN-SUFFIX", "example.org", "YouTube")
    assert db.list_custom_rules()[0]["value"] == "example.org"
    with pytest.raises(ValueError, match="invalid custom rule type"):
        db.add_custom_rule("DOMAIN", "x", "DIRECT")
    db.update_custom_rule(rule_id, target="REJECT", enabled=False)
    assert db.list_custom_rules(enabled_only=True) == []
    db.delete_custom_rule(rule_id)
    assert db.list_custom_rules() == []


def test_custom_rules_order_and_move(db):
    # L-04: new rules append in creation order; move swaps sort_order
    # with the neighbour; moving an edge rule is a no-op.
    a = db.add_custom_rule("DOMAIN-SUFFIX", "a.example", "YouTube")
    b = db.add_custom_rule("DOMAIN-SUFFIX", "b.example", "YouTube")
    c = db.add_custom_rule("DOMAIN-SUFFIX", "c.example", "YouTube")
    assert [r["value"] for r in db.list_custom_rules()] == [
        "a.example", "b.example", "c.example",
    ]
    assert db.move_custom_rule(b, "up") is True
    assert [r["value"] for r in db.list_custom_rules()] == [
        "b.example", "a.example", "c.example",
    ]
    assert db.move_custom_rule(b, "up") is False  # already first
    assert db.move_custom_rule(c, "down") is False  # already last
    assert db.move_custom_rule(b, "down") is True
    assert [r["value"] for r in db.list_custom_rules()] == [
        "a.example", "b.example", "c.example",
    ]
    assert db.move_custom_rule(999999, "up") is False
    with pytest.raises(ValueError, match="invalid direction"):
        db.move_custom_rule(a, "sideways")


def test_custom_rules_sort_order_migration_backfills_from_id(tmp_path):
    # L-04: a pre-sort_order database gains the column by additive
    # migration (ALTER TABLE ADD COLUMN) and keeps its old order:
    # sort_order is backfilled from the row id. No table is rebuilt.
    import sqlite3

    legacy = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(legacy))
    conn.executescript(
        "CREATE TABLE custom_rules ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " type TEXT NOT NULL,"
        " value TEXT NOT NULL,"
        " target TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ");"
        "CREATE TABLE nodes (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " name TEXT NOT NULL, uri TEXT NOT NULL, proxy_json TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL DEFAULT (datetime('now')));"
        "CREATE TABLE group_bindings (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " group_key TEXT NOT NULL, node_id INTEGER NOT NULL,"
        " role TEXT NOT NULL DEFAULT 'backup',"
        " mode TEXT NOT NULL DEFAULT 'fallback');"
        "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
    )
    conn.execute(
        "INSERT INTO custom_rules (type, value, target, enabled)"
        " VALUES ('DOMAIN-SUFFIX', 'old-b.example', 'YouTube', 1)"
    )
    conn.execute(
        "INSERT INTO custom_rules (type, value, target, enabled)"
        " VALUES ('DOMAIN-SUFFIX', 'old-a.example', 'YouTube', 1)"
    )
    conn.commit()
    conn.close()

    handle = Database(legacy)
    try:
        rules = handle.list_custom_rules()
        # Creation order preserved (ids 1, 2 -> sort_order 1, 2).
        assert [r["value"] for r in rules] == [
            "old-b.example", "old-a.example",
        ]
        assert [r["sort_order"] for r in rules] == [1, 2]
        # Re-opening is idempotent: the backfill must not re-run and
        # clobber an order the user has since changed.
        handle.move_custom_rule(rules[1]["id"], "up")
        handle.close()
        handle = Database(legacy)
        assert [r["value"] for r in handle.list_custom_rules()] == [
            "old-a.example", "old-b.example",
        ]
    finally:
        handle.close()


def test_settings_defaults_and_overrides(db):
    settings = db.get_settings()
    assert settings.ss_port == 10001
    assert settings.ss_cipher == "aes-128-gcm"
    assert settings.mixed_port == 7890
    assert settings.mihomo_secret == ""
    assert db.get_setting("missing-key") is None
    assert db.get_setting("missing-key", "fallback") == "fallback"

    db.set_setting("ss_port", 10002)
    db.set_setting("mihomo_secret", "fake-secret")
    settings = db.get_settings()
    assert settings.ss_port == 10002
    assert settings.mihomo_secret == "fake-secret"
    assert settings.mixed_port == 7890  # untouched default kept
