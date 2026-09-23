"""Schema v5+v6 — sync provenance columns + ATT&CK overlay tables."""

from __future__ import annotations

import json

import pytest

from scg.graph import SCG


def test_schema_version_is_current(g: SCG) -> None:
    rows, _ = g.execute_sql("SELECT value FROM _meta WHERE key='schema_version'")
    assert rows[0]["value"] == "8"


def test_app_telemetry_control_instance_have_sync_columns(g: SCG) -> None:
    for table in ("app", "telemetry", "control_instance"):
        rows, _ = g.execute_sql(f"PRAGMA table_info({table})")
        cols = {r["name"] for r in rows}
        assert "last_synced_at" in cols, f"{table} missing last_synced_at"
        assert "synced_by" in cols, f"{table} missing synced_by"


def test_sync_session_table_exists(g: SCG) -> None:
    rows, _ = g.execute_sql(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='sync_session'"
    )
    assert rows, "sync_session table missing"


def test_upsert_app_without_synced_by_leaves_provenance_null(g: SCG) -> None:
    g.upsert_app("app:hand", "Hand-authored", "alice", "prod", "internal")
    rows, _ = g.execute_sql(
        "SELECT synced_by, last_synced_at FROM app WHERE id='app:hand'"
    )
    assert rows[0]["synced_by"] is None
    assert rows[0]["last_synced_at"] is None


def test_upsert_app_with_synced_by_sets_provenance(g: SCG) -> None:
    g.upsert_app(
        "app:aws:111", "sandbox", "owner", "prod", "internal",
        synced_by="cartography",
    )
    rows, _ = g.execute_sql(
        "SELECT synced_by, last_synced_at FROM app WHERE id='app:aws:111'"
    )
    assert rows[0]["synced_by"] == "cartography"
    assert rows[0]["last_synced_at"] is not None


def test_hand_authored_update_preserves_prior_sync_provenance(g: SCG) -> None:
    """A connector-written row that's later edited by hand must keep its provenance."""
    g.upsert_app(
        "app:aws:222", "first-sync", "owner", "prod", "internal",
        synced_by="cartography",
    )
    rows, _ = g.execute_sql("SELECT last_synced_at FROM app WHERE id='app:aws:222'")
    original_synced_at = rows[0]["last_synced_at"]

    # Hand-authored re-write (no synced_by) must not nuke the provenance.
    g.upsert_app("app:aws:222", "hand-edit", "owner", "prod", "internal")
    rows, _ = g.execute_sql(
        "SELECT synced_by, last_synced_at FROM app WHERE id='app:aws:222'"
    )
    assert rows[0]["synced_by"] == "cartography"
    assert rows[0]["last_synced_at"] == original_synced_at


def test_upsert_telemetry_threads_synced_by(g: SCG) -> None:
    g.upsert_telemetry(
        "tel:cloudtrail", "CloudTrail", "aws", "ops",
        synced_by="cartography",
    )
    rows, _ = g.execute_sql(
        "SELECT synced_by FROM telemetry WHERE id='tel:cloudtrail'"
    )
    assert rows[0]["synced_by"] == "cartography"


def test_upsert_control_instance_threads_synced_by(g: SCG) -> None:
    g.upsert_app("app:x", "X", "owner", "prod", "internal")
    g.upsert_control("ctrl:mfa", "MFA", "preventive", "ops")
    g.upsert_control_instance("app:x", "ctrl:mfa", "ops", synced_by="cartography")
    rows, _ = g.execute_sql(
        "SELECT synced_by FROM control_instance WHERE id='app:x:ctrl:mfa'"
    )
    assert rows[0]["synced_by"] == "cartography"


def test_sync_session_lifecycle_ok(g: SCG) -> None:
    sid = g.start_sync_session("cartography")
    assert sid > 0

    running = g.get_sync_session(sid)
    assert running is not None
    assert running["status"] == "running"
    assert running["completed_at"] is None

    g.complete_sync_session(
        sid,
        status="ok",
        nodes_upserted=5,
        edges_upserted=3,
        metadata={"aws_accounts": 2, "cloudtrails": 2},
    )

    done = g.get_sync_session(sid)
    assert done is not None
    assert done["status"] == "ok"
    assert done["nodes_upserted"] == 5
    assert done["edges_upserted"] == 3
    assert done["completed_at"] is not None
    assert done["error_message"] is None
    assert json.loads(done["metadata"]) == {"aws_accounts": 2, "cloudtrails": 2}


def test_sync_session_lifecycle_error(g: SCG) -> None:
    sid = g.start_sync_session("cartography")
    g.complete_sync_session(sid, status="error", error_message="neo4j unreachable")
    done = g.get_sync_session(sid)
    assert done["status"] == "error"
    assert done["error_message"] == "neo4j unreachable"
    assert done["nodes_upserted"] == 0


def test_sync_session_lifecycle_stale_source(g: SCG) -> None:
    """Stale-source is a distinct terminal status — bridge refused to write."""
    sid = g.start_sync_session("cartography")
    g.complete_sync_session(sid, status="stale_source", error_message="cartography >24h old")
    assert g.get_sync_session(sid)["status"] == "stale_source"


def test_complete_sync_session_rejects_unknown_status(g: SCG) -> None:
    sid = g.start_sync_session("cartography")
    with pytest.raises(ValueError, match="status must be"):
        g.complete_sync_session(sid, status="finished")


def test_list_sync_sessions_filters_and_orders(g: SCG) -> None:
    a = g.start_sync_session("cartography")
    g.complete_sync_session(a, status="ok")
    b = g.start_sync_session("siem")
    g.complete_sync_session(b, status="error", error_message="x")
    c = g.start_sync_session("cartography")
    g.complete_sync_session(c, status="ok")

    cart_only = g.list_sync_sessions(connector_name="cartography")
    assert [r["id"] for r in cart_only] == [c, a]

    errors_only = g.list_sync_sessions(status="error")
    assert [r["id"] for r in errors_only] == [b]


def test_crashed_session_is_discoverable(g: SCG) -> None:
    """A session that started but never completed shows as status='running'."""
    sid = g.start_sync_session("cartography")
    # … process dies here, complete_sync_session never called.
    crashed = g.list_sync_sessions(status="running")
    assert [r["id"] for r in crashed] == [sid]


def test_migration_from_v4_preserves_data_and_adds_sync_columns(tmp_path) -> None:
    """A pre-v5 DB opens cleanly: existing rows survive, sync columns appear."""
    import sqlite3
    db_path = tmp_path / "v4.db"

    # Forge a v4 DB by writing the v4 schema shape directly. We only need
    # the tables the v5 migration touches.
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE app (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL,
            env TEXT NOT NULL, exposure TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE telemetry (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, source_system TEXT NOT NULL,
            owner TEXT NOT NULL, retention_days INTEGER, last_verified TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE control (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL,
            owner TEXT NOT NULL, effectiveness REAL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE control_instance (
            id TEXT PRIMARY KEY, app_id TEXT NOT NULL, ctrl_id TEXT NOT NULL,
            owner TEXT NOT NULL, effectiveness REAL, notes TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(app_id, ctrl_id)
        );
        CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO _meta(key, value) VALUES ('schema_version', '4');
        INSERT INTO app(id, name, owner, env, exposure)
            VALUES ('app:legacy', 'Legacy', 'alice', 'prod', 'internal');
        INSERT INTO telemetry(id, name, source_system, owner)
            VALUES ('tel:legacy', 'Legacy Tel', 'syslog', 'ops');
    """)
    conn.commit()
    conn.close()

    # Opening through SCG runs _init_schema + _migrate.
    g = SCG(str(db_path))
    try:
        rows, _ = g.execute_sql("SELECT value FROM _meta WHERE key='schema_version'")
        assert rows[0]["value"] == "8"

        # Data preserved.
        app = g.get_app("app:legacy")
        assert app is not None and app["name"] == "Legacy"
        tel = g.get_telemetry("tel:legacy")
        assert tel is not None and tel["source_system"] == "syslog"

        # New columns present and null for legacy rows.
        assert app["last_synced_at"] is None
        assert app["synced_by"] is None
        assert tel["last_synced_at"] is None
        # v7 backfill: legacy telemetry is treated as confirmed-present.
        assert tel["sync_state"] == "confirmed"
        assert tel["unconfirmed_reason"] is None

        # sync_session table is usable.
        sid = g.start_sync_session("cartography")
        g.complete_sync_session(sid, status="ok", nodes_upserted=1)
        assert g.get_sync_session(sid)["status"] == "ok"
    finally:
        g.close()


def test_migration_from_v6_adds_telemetry_sync_state(tmp_path) -> None:
    """A v6 DB gains sync_state/unconfirmed_reason; existing rows backfill 'confirmed'."""
    import sqlite3
    db_path = tmp_path / "v6.db"

    # v6 telemetry shape: has the v5 sync columns but no sync_state yet.
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE telemetry (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, source_system TEXT NOT NULL,
            owner TEXT NOT NULL, retention_days INTEGER, last_verified TEXT,
            last_synced_at TEXT, synced_by TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO _meta(key, value) VALUES ('schema_version', '6');
        INSERT INTO telemetry(id, name, source_system, owner)
            VALUES ('tel:legacy', 'Legacy Tel', 'syslog', 'ops');
    """)
    conn.commit()
    conn.close()

    g = SCG(str(db_path))
    try:
        rows, _ = g.execute_sql("SELECT value FROM _meta WHERE key='schema_version'")
        assert rows[0]["value"] == "8"

        # Pre-existing row is backfilled as confirmed (it came from a real sync).
        legacy = g.get_telemetry("tel:legacy")
        assert legacy["sync_state"] == "confirmed"
        assert legacy["unconfirmed_reason"] is None

        # An unconfirmed source (collector errored) is representable end to end.
        g.upsert_telemetry(
            "tel:cloudwatch-logs:123", "CloudWatch Logs", "aws_cloudwatch", "unknown",
            sync_state="unconfirmed",
            unconfirmed_reason="cloudwatch sync errored 2026-06-21T14:04Z",
        )
        cw = g.get_telemetry("tel:cloudwatch-logs:123")
        assert cw["sync_state"] == "unconfirmed"
        assert "cloudwatch" in cw["unconfirmed_reason"]
    finally:
        g.close()


def test_unconfirmed_telemetry_rejects_coverage_edges(g: SCG) -> None:
    """T3 invariant: unconfirmed telemetry is informational only — add_edge
    must refuse coverage-implying PRODUCES/POWERS edges until the source is
    confirmed."""
    g.upsert_app("app:a", "App A", "owner", "prod", "internet")
    g.upsert_detection("det:d", "Det D", "rule", "owner", confidence=0.5)
    g.upsert_telemetry(
        "tel:u", "Unverified Logs", "src", "owner",
        sync_state="unconfirmed", unconfirmed_reason="collector errored",
    )

    with pytest.raises(ValueError, match="unconfirmed"):
        g.add_edge("PRODUCES", "app:a", "tel:u")
    with pytest.raises(ValueError, match="unconfirmed"):
        g.add_edge("POWERS", "tel:u", "det:d")
    assert g.list_edges() == []

    # Confirming the source lifts the block.
    g.upsert_telemetry("tel:u", "Unverified Logs", "src", "owner",
                       sync_state="confirmed")
    g.add_edge("PRODUCES", "app:a", "tel:u")
    g.add_edge("POWERS", "tel:u", "det:d")
    assert len(g.list_edges()) == 2
