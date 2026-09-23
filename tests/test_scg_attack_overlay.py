"""Schema v6 — ATT&CK overlay node tables, ttp provenance, new edge types."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from scg.graph import SCG


# ----------------------------------------------------------- v6 schema shape


def test_overlay_tables_exist(g: SCG) -> None:
    rows, _ = g.execute_sql(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name IN ('tactic','mitigation','data_source','data_component')"
    )
    assert {r["name"] for r in rows} == {"tactic", "mitigation", "data_source", "data_component"}


def test_ttp_table_has_v6_columns(g: SCG) -> None:
    rows, _ = g.execute_sql("PRAGMA table_info(ttp)")
    cols = {r["name"] for r in rows}
    for c in ("is_subtechnique", "revoked_by_id", "platforms",
              "source", "source_version", "external_url",
              "last_synced_at", "local_notes"):
        assert c in cols, f"ttp missing column {c}"


def test_overlay_tables_have_provenance_and_local_notes(g: SCG) -> None:
    for table in ("tactic", "mitigation", "data_source", "data_component"):
        rows, _ = g.execute_sql(f"PRAGMA table_info({table})")
        cols = {r["name"] for r in rows}
        for c in ("source", "source_version", "external_url",
                  "last_synced_at", "local_notes"):
            assert c in cols, f"{table} missing {c}"


# ----------------------------------------------------------- upserts round-trip


def test_upsert_tactic_round_trip(g: SCG) -> None:
    g.upsert_tactic(
        "tac:TA0001", "TA0001", "Initial Access", "initial-access",
        description="Adversary tries to get into network.",
        source="mitre-attack", source_version="15.1",
        external_url="https://attack.mitre.org/tactics/TA0001/",
    )
    rows, _ = g.execute_sql("SELECT * FROM tactic WHERE id='tac:TA0001'")
    assert len(rows) == 1
    r = rows[0]
    assert r["mitre_id"] == "TA0001"
    assert r["short_name"] == "initial-access"
    assert r["source"] == "mitre-attack"
    assert r["source_version"] == "15.1"
    assert r["last_synced_at"] is not None
    assert r["local_notes"] is None


def test_upsert_mitigation_round_trip(g: SCG) -> None:
    g.upsert_mitigation("mit:M1017", "M1017", "User Training",
                        description="Train users to spot phishing.",
                        source="mitre-attack", source_version="15.1")
    rows, _ = g.execute_sql("SELECT * FROM mitigation WHERE id='mit:M1017'")
    assert rows[0]["mitre_id"] == "M1017"
    assert rows[0]["source_version"] == "15.1"


def test_upsert_data_source_and_component(g: SCG) -> None:
    g.upsert_data_source("ds:DS0029", "DS0029", "Network Traffic",
                         source="mitre-attack", source_version="15.1")
    g.upsert_data_component(
        "dc:DS0029.network-traffic-content", "DS0029.network-traffic-content",
        "Network Traffic Content", "ds:DS0029",
        source="mitre-attack", source_version="15.1",
    )
    rows, _ = g.execute_sql(
        "SELECT data_source_id FROM data_component WHERE id='dc:DS0029.network-traffic-content'"
    )
    assert rows[0]["data_source_id"] == "ds:DS0029"


# ----------------------------------------------------------- ttp v6 fields


def test_upsert_ttp_carries_subtechnique_provenance_and_platforms(g: SCG) -> None:
    # Sub-technique IDs use a "." in the body — this also serves as the
    # ID-format regression guard for issue #5 in the adversarial review.
    g.upsert_ttp(
        "ttp:T1566.001",
        "Spearphishing Attachment",
        description="Malicious email attachment.",
        mitre_id="T1566.001",
        is_subtechnique=True,
        platforms=["macOS", "Windows", "Linux"],
        source="mitre-attack",
        source_version="15.1",
        external_url="https://attack.mitre.org/techniques/T1566/001",
    )
    rows, _ = g.execute_sql("SELECT * FROM ttp WHERE id='ttp:T1566.001'")
    assert len(rows) == 1
    r = rows[0]
    assert r["is_subtechnique"] == 1
    assert json.loads(r["platforms"]) == ["macOS", "Windows", "Linux"]
    assert r["source"] == "mitre-attack"
    assert r["source_version"] == "15.1"
    assert r["last_synced_at"] is not None


def test_upsert_ttp_does_not_overwrite_local_notes(g: SCG) -> None:
    """The loader must never clobber human-edited local_notes."""
    g.upsert_ttp("ttp:T1566", "Phishing", "MITRE description", mitre_id="T1566",
                 source="mitre-attack", source_version="15.1")
    # Human annotates the row directly.
    g.execute_sql("UPDATE ttp SET local_notes='our-internal-context' WHERE id='ttp:T1566'")
    # Loader re-promotes the same technique (e.g. after a re-sync).
    g.upsert_ttp("ttp:T1566", "Phishing", "MITRE description updated", mitre_id="T1566",
                 source="mitre-attack", source_version="15.2")
    rows, _ = g.execute_sql("SELECT description, source_version, local_notes FROM ttp WHERE id='ttp:T1566'")
    assert rows[0]["description"] == "MITRE description updated"
    assert rows[0]["source_version"] == "15.2"
    assert rows[0]["local_notes"] == "our-internal-context"


# ----------------------------------------------------------- new edge types


def test_overlay_edges_can_be_added(g: SCG) -> None:
    g.upsert_app("app:portal", "Portal", "alice", "prod", "internet")
    g.upsert_tactic("tac:TA0001", "TA0001", "Initial Access", "initial-access",
                    source="mitre-attack", source_version="15.1")
    g.upsert_mitigation("mit:M1017", "M1017", "User Training",
                        source="mitre-attack", source_version="15.1")
    g.upsert_data_source("ds:DS0029", "DS0029", "Network Traffic",
                         source="mitre-attack", source_version="15.1")
    g.upsert_data_component(
        "dc:DS0029.network-traffic-content", "DS0029.network-traffic-content",
        "Network Traffic Content", "ds:DS0029",
        source="mitre-attack", source_version="15.1",
    )
    g.upsert_ttp("ttp:T1566", "Phishing", mitre_id="T1566",
                 source="mitre-attack", source_version="15.1")
    g.upsert_ttp("ttp:T1566.001", "Spearphishing Attachment",
                 mitre_id="T1566.001", is_subtechnique=True,
                 source="mitre-attack", source_version="15.1")

    edge_attrs = {"source": "mitre-attack", "source_version": "15.1"}
    g.add_edge("ACHIEVES", "ttp:T1566", "tac:TA0001", attrs=edge_attrs)
    g.add_edge("SUBTECHNIQUE_OF", "ttp:T1566.001", "ttp:T1566", attrs=edge_attrs)
    g.add_edge("MITIGATED_BY_REF", "ttp:T1566.001", "mit:M1017", attrs=edge_attrs)
    g.add_edge("DETECTED_VIA", "ttp:T1566.001", "dc:DS0029.network-traffic-content",
               attrs=edge_attrs)

    rows, _ = g.execute_sql(
        "SELECT edge_type, from_id, to_id, attrs FROM edge "
        "WHERE edge_type IN ('ACHIEVES','SUBTECHNIQUE_OF','MITIGATED_BY_REF','DETECTED_VIA') "
        "ORDER BY edge_type"
    )
    by_type = {r["edge_type"]: r for r in rows}
    assert set(by_type) == {"ACHIEVES", "SUBTECHNIQUE_OF", "MITIGATED_BY_REF", "DETECTED_VIA"}
    # Every overlay edge carries provenance in attrs.
    for r in rows:
        assert json.loads(r["attrs"]) == edge_attrs


def test_edge_check_rejects_unknown_overlay_edge(g: SCG) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        g.add_edge("HUGS", "ttp:T1566", "tac:TA0001")


# ----------------------------------------------------------- migration from v5


def test_migration_from_v5_adds_overlay_tables(tmp_path: Path) -> None:
    """A v5 DB upgrades cleanly to the current schema version without data loss."""
    db_path = tmp_path / "legacy_v5.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE app (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL,
            env TEXT NOT NULL, exposure TEXT NOT NULL,
            last_synced_at TEXT, synced_by TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE ttp (
            id TEXT PRIMARY KEY, mitre_id TEXT, name TEXT NOT NULL, description TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE edge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            edge_type TEXT NOT NULL CHECK(edge_type IN (
                'HAS_TI','DESCRIBES','DETECTED_BY','MITIGATED_BY',
                'PRODUCES','POWERS','HAS_CI','IMPLEMENTED_BY')),
            from_id TEXT NOT NULL, to_id TEXT NOT NULL, attrs TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(edge_type, from_id, to_id)
        );
        CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO _meta(key, value) VALUES ('schema_version', '5');
        INSERT INTO ttp(id, mitre_id, name, description) VALUES ('ttp:T1566','T1566','Phishing','legacy desc');
        INSERT INTO edge(edge_type, from_id, to_id) VALUES ('HAS_TI','app:x','x:ttp:T1566:v1');
    """)
    conn.commit()
    conn.close()

    g = SCG(str(db_path))
    try:
        rows, _ = g.execute_sql("SELECT value FROM _meta WHERE key='schema_version'")
        assert rows[0]["value"] == "8"
        # Legacy ttp row preserved.
        rows, _ = g.execute_sql("SELECT name, description, source FROM ttp WHERE id='ttp:T1566'")
        assert rows[0]["name"] == "Phishing"
        assert rows[0]["description"] == "legacy desc"
        assert rows[0]["source"] is None  # never mutated by migration
        # New overlay edge type is now legal.
        g.upsert_tactic("tac:TA0001", "TA0001", "Initial Access", "initial-access")
        g.add_edge("ACHIEVES", "ttp:T1566", "tac:TA0001")
        rows, _ = g.execute_sql("SELECT COUNT(*) c FROM edge WHERE edge_type='ACHIEVES'")
        assert rows[0]["c"] == 1
        # Legacy edge preserved.
        rows, _ = g.execute_sql("SELECT COUNT(*) c FROM edge WHERE edge_type='HAS_TI'")
        assert rows[0]["c"] == 1
    finally:
        g.close()
