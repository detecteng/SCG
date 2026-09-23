"""
Security Coverage Graph (SCG) — core library.

Usage:
    from scg.graph import SCG
    g = SCG("scg.db")          # or SCG(":memory:") for tests
    g.upsert_app("ecom", "E-Commerce", "alice", "prod", "internet")
    ...
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any, Callable

_SCHEMA_PATH: Path = Path(__file__).parent / "schema.sql"
_STATUSES: tuple[str, ...] = ("covered", "partial", "gap", "unknown")

_log = logging.getLogger(__name__)

# Edge accessor: (node_id, edge_type) -> matching edge dicts. The status
# evaluator is written against these so the same code runs on the database,
# on an in-memory bulk index, and on impact_analysis' doomed-filtered view.
EdgeFn = Callable[[str, str], list[dict[str, Any]]]


def _row_to_dict(cursor: sqlite3.Cursor, row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)


def _requirement_group(edge: dict[str, Any]) -> Any:
    """POWERS edges carry attrs.requirement_group; an ungrouped edge is group 1."""
    attrs = edge.get("attrs")
    if isinstance(attrs, str):
        attrs = json.loads(attrs)
    group = (attrs or {}).get("requirement_group")
    return 1 if group is None else group


def _evaluate_status(
    ti_id: str,
    app_id: str,
    out: EdgeFn,
    inc: EdgeFn,
    tel_state: Callable[[str], str | None],
    ci_type: Callable[[str], str | None],
) -> str:
    """Computed status of one ThreatInstance (paper §3.2 precedence).

        preventive ControlInstance            -> covered
        else operable detection               -> partial
        else a detection that only unconfirmed
             telemetry could satisfy          -> unknown
        else                                  -> gap

    A detection is operable when every telemetry in at least one of its POWERS
    requirement groups is confirmed and PRODUCED by the instance's app (§3.3).
    A group the app fully PRODUCES but that includes unconfirmed telemetry is
    unknown rather than gap: those edges are kept but no longer count as
    evidence (§3.4). A group missing any PRODUCES edge is absent.
    """
    if any(ci_type(e["to_id"]) == "preventive" for e in out(ti_id, "MITIGATED_BY")):
        return "covered"
    produced = {e["to_id"] for e in out(app_id, "PRODUCES")}
    candidate = False
    for det in out(ti_id, "DETECTED_BY"):
        groups: dict[Any, list[str]] = {}
        for p in inc(det["to_id"], "POWERS"):
            groups.setdefault(_requirement_group(p), []).append(p["from_id"])
        for group in groups.values():
            states = [tel_state(t) for t in group]
            if all(t in produced and s == "confirmed" for t, s in zip(group, states)):
                return "partial"
            if all(t in produced for t in group) and "unconfirmed" in states:
                candidate = True
    return "unknown" if candidate else "gap"


class SCG:
    def __init__(self, db_path: str | None = None) -> None:
        if db_path is None:
            db_path = os.environ.get("SCG_DB_PATH", "scg.db")
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        _log.info("open db_path=%s", db_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        sql = _SCHEMA_PATH.read_text()
        self._conn.executescript(sql)
        self._conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """Apply incremental schema migrations based on schema_version in _meta."""
        row = self._fetchone("SELECT value FROM _meta WHERE key='schema_version'")
        version = int(row["value"]) if row else 1
        if version < 2:
            # Recreate edge table with HAS_IC and IMPLEMENTED_BY in the CHECK constraint.
            # SQLite does not support ALTER COLUMN, so we use CREATE/INSERT/DROP/RENAME.
            self._execute("""
                CREATE TABLE IF NOT EXISTS edge_v2 (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    edge_type  TEXT NOT NULL CHECK(edge_type IN (
                                   'HAS_TI','DESCRIBES','DETECTED_BY','MITIGATED_BY',
                                   'PRODUCES','POWERS','HAS_IC','IMPLEMENTED_BY')),
                    from_id    TEXT NOT NULL,
                    to_id      TEXT NOT NULL,
                    attrs      TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(edge_type, from_id, to_id)
                )
            """)
            self._execute("INSERT OR IGNORE INTO edge_v2 SELECT * FROM edge")
            self._execute("DROP TABLE edge")
            self._execute("ALTER TABLE edge_v2 RENAME TO edge")
            self._execute("""
                CREATE TABLE IF NOT EXISTS control_instance (
                    id            TEXT PRIMARY KEY,
                    app_id        TEXT NOT NULL REFERENCES app(id),
                    ctrl_id       TEXT NOT NULL REFERENCES control(id),
                    owner         TEXT NOT NULL,
                    effectiveness REAL CHECK(effectiveness BETWEEN 0 AND 1),
                    notes         TEXT,
                    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(app_id, ctrl_id)
                )
            """)
            self._execute(
                "INSERT OR REPLACE INTO _meta(key, value) VALUES ('schema_version', '2')"
            )
            self._conn.commit()
        if version < 3:
            # Rename HAS_IC → HAS_CI for naming consistency with HAS_TI
            # (Has Control Instance — abbreviation now matches noun order).
            self._execute("""
                CREATE TABLE IF NOT EXISTS edge_v3 (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    edge_type  TEXT NOT NULL CHECK(edge_type IN (
                                   'HAS_TI','DESCRIBES','DETECTED_BY','MITIGATED_BY',
                                   'PRODUCES','POWERS','HAS_CI','IMPLEMENTED_BY')),
                    from_id    TEXT NOT NULL,
                    to_id      TEXT NOT NULL,
                    attrs      TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(edge_type, from_id, to_id)
                )
            """)
            self._execute("""
                INSERT OR IGNORE INTO edge_v3 (id, edge_type, from_id, to_id, attrs, created_at)
                SELECT id,
                       CASE WHEN edge_type='HAS_IC' THEN 'HAS_CI' ELSE edge_type END,
                       from_id, to_id, attrs, created_at
                FROM edge
            """)
            self._execute("DROP TABLE edge")
            self._execute("ALTER TABLE edge_v3 RENAME TO edge")
            self._execute("CREATE INDEX IF NOT EXISTS idx_edge_from ON edge(from_id)")
            self._execute("CREATE INDEX IF NOT EXISTS idx_edge_to   ON edge(to_id)")
            self._execute("CREATE INDEX IF NOT EXISTS idx_edge_type ON edge(edge_type)")
            self._execute(
                "INSERT OR REPLACE INTO _meta(key, value) VALUES ('schema_version', '3')"
            )
            self._conn.commit()
        if version < 5:
            # Add sync provenance columns + sync_session audit table.
            # ALTER TABLE ADD COLUMN is supported by SQLite — no rebuild needed.
            for table in ("app", "telemetry", "control_instance"):
                cols = {r["name"] for r in self._fetchall(f"PRAGMA table_info({table})")}
                if "last_synced_at" not in cols:
                    self._execute(f"ALTER TABLE {table} ADD COLUMN last_synced_at TEXT")
                if "synced_by" not in cols:
                    self._execute(f"ALTER TABLE {table} ADD COLUMN synced_by TEXT")
            self._execute("""
                CREATE TABLE IF NOT EXISTS sync_session (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    connector_name  TEXT NOT NULL,
                    started_at      TEXT NOT NULL,
                    completed_at    TEXT,
                    nodes_upserted  INTEGER NOT NULL DEFAULT 0,
                    edges_upserted  INTEGER NOT NULL DEFAULT 0,
                    status          TEXT NOT NULL CHECK(status IN ('running','ok','error','stale_source')),
                    error_message   TEXT,
                    metadata        TEXT
                )
            """)
            self._execute(
                "CREATE INDEX IF NOT EXISTS idx_sync_session_connector "
                "ON sync_session(connector_name, started_at)"
            )
            self._execute(
                "INSERT OR REPLACE INTO _meta(key, value) VALUES ('schema_version', '5')"
            )
            self._conn.commit()

        if version < 4:
            # Add version_id column to threat_instance and broaden uniqueness
            # to (app_id, ttp_id, version_id). SQLite does not support changing
            # a UNIQUE constraint via ALTER TABLE, so we rebuild the table.
            # Existing rows are migrated with version_id='v1' and id is rewritten
            # from "app_id:ttp_id" to "app_id:ttp_id:v1"; edges referencing the
            # old TI id are updated in lockstep so coverage materialization
            # continues to resolve.
            self._execute("""
                CREATE TABLE IF NOT EXISTS threat_instance_v4 (
                    id                   TEXT PRIMARY KEY,
                    app_id               TEXT NOT NULL REFERENCES app(id),
                    ttp_id               TEXT NOT NULL REFERENCES ttp(id),
                    version_id           TEXT NOT NULL DEFAULT 'v1',
                    likelihood           REAL CHECK(likelihood BETWEEN 0 AND 1),
                    impact               REAL CHECK(impact BETWEEN 0 AND 1),
                    priority             INTEGER CHECK(priority BETWEEN 1 AND 5),
                    last_reviewed        TEXT,
                    has_detection        INTEGER NOT NULL DEFAULT 0,
                    has_control          INTEGER NOT NULL DEFAULT 0,
                    effective_confidence REAL,
                    last_computed_at     TEXT,
                    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at           TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(app_id, ttp_id, version_id)
                )
            """)
            self._execute("""
                INSERT OR IGNORE INTO threat_instance_v4 (
                    id, app_id, ttp_id, version_id, likelihood, impact, priority,
                    last_reviewed, has_detection, has_control, effective_confidence,
                    last_computed_at, created_at, updated_at)
                SELECT
                    app_id || ':' || ttp_id || ':v1',
                    app_id, ttp_id, 'v1', likelihood, impact, priority,
                    last_reviewed, has_detection, has_control, effective_confidence,
                    last_computed_at, created_at, updated_at
                FROM threat_instance
            """)
            # Rewrite edge endpoints that reference TI ids in the old two-element form.
            # The old TI id pattern is "<app_id>:<ttp_id>"; the new is suffixed with ":v1".
            # Only DETECTED_BY (from_id), MITIGATED_BY (from_id), HAS_TI (to_id),
            # DESCRIBES (to_id) can reference a TI; rewrite each.
            self._execute("""
                UPDATE edge SET from_id = from_id || ':v1'
                WHERE edge_type IN ('DETECTED_BY','MITIGATED_BY')
                  AND from_id IN (SELECT app_id || ':' || ttp_id FROM threat_instance)
            """)
            self._execute("""
                UPDATE edge SET to_id = to_id || ':v1'
                WHERE edge_type IN ('HAS_TI','DESCRIBES')
                  AND to_id IN (SELECT app_id || ':' || ttp_id FROM threat_instance)
            """)
            self._execute("DROP TABLE threat_instance")
            self._execute("ALTER TABLE threat_instance_v4 RENAME TO threat_instance")
            self._execute("CREATE INDEX IF NOT EXISTS idx_ti_priority ON threat_instance(priority)")
            self._execute("CREATE INDEX IF NOT EXISTS idx_ti_app      ON threat_instance(app_id)")
            self._execute(
                "INSERT OR REPLACE INTO _meta(key, value) VALUES ('schema_version', '4')"
            )
            self._conn.commit()

        if version < 6:
            # ATT&CK overlay: add provenance + local_notes columns to the existing
            # ttp table, create tactic/mitigation/data_source/data_component node
            # tables, and broaden the edge CHECK constraint with the five new
            # overlay edge types. Column adds use ALTER TABLE; the edge CHECK
            # rebuild follows the same CREATE/INSERT/DROP/RENAME pattern as v2/v3.
            ttp_cols = {r["name"] for r in self._fetchall("PRAGMA table_info(ttp)")}
            for col, decl in (
                ("is_subtechnique", "INTEGER NOT NULL DEFAULT 0"),
                ("revoked_by_id",   "TEXT"),
                ("platforms",       "TEXT"),
                ("source",          "TEXT"),
                ("source_version",  "TEXT"),
                ("external_url",    "TEXT"),
                ("last_synced_at",  "TEXT"),
                ("local_notes",     "TEXT"),
            ):
                if col not in ttp_cols:
                    self._execute(f"ALTER TABLE ttp ADD COLUMN {col} {decl}")

            self._execute("""
                CREATE TABLE IF NOT EXISTS tactic (
                    id              TEXT PRIMARY KEY,
                    mitre_id        TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    short_name      TEXT NOT NULL,
                    description     TEXT,
                    source          TEXT,
                    source_version  TEXT,
                    external_url    TEXT,
                    last_synced_at  TEXT,
                    local_notes     TEXT,
                    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            self._execute("""
                CREATE TABLE IF NOT EXISTS mitigation (
                    id              TEXT PRIMARY KEY,
                    mitre_id        TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    description     TEXT,
                    source          TEXT,
                    source_version  TEXT,
                    external_url    TEXT,
                    last_synced_at  TEXT,
                    local_notes     TEXT,
                    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            self._execute("""
                CREATE TABLE IF NOT EXISTS data_source (
                    id              TEXT PRIMARY KEY,
                    mitre_id        TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    description     TEXT,
                    source          TEXT,
                    source_version  TEXT,
                    external_url    TEXT,
                    last_synced_at  TEXT,
                    local_notes     TEXT,
                    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            self._execute("""
                CREATE TABLE IF NOT EXISTS data_component (
                    id              TEXT PRIMARY KEY,
                    mitre_id        TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    description     TEXT,
                    data_source_id  TEXT NOT NULL REFERENCES data_source(id),
                    source          TEXT,
                    source_version  TEXT,
                    external_url    TEXT,
                    last_synced_at  TEXT,
                    local_notes     TEXT,
                    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            self._execute(
                "CREATE INDEX IF NOT EXISTS idx_data_component_ds ON data_component(data_source_id)"
            )

            # Edge CHECK rebuild — add ACHIEVES, SUBTECHNIQUE_OF, MITIGATED_BY_REF,
            # DETECTED_VIA, REVOKED_BY to the allowlist.
            self._execute("""
                CREATE TABLE IF NOT EXISTS edge_v6 (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    edge_type  TEXT NOT NULL CHECK(edge_type IN (
                                   'HAS_TI','DESCRIBES','DETECTED_BY','MITIGATED_BY',
                                   'PRODUCES','POWERS','HAS_CI','IMPLEMENTED_BY',
                                   'ACHIEVES','SUBTECHNIQUE_OF','MITIGATED_BY_REF',
                                   'DETECTED_VIA','REVOKED_BY')),
                    from_id    TEXT NOT NULL,
                    to_id      TEXT NOT NULL,
                    attrs      TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    UNIQUE(edge_type, from_id, to_id)
                )
            """)
            self._execute("INSERT OR IGNORE INTO edge_v6 SELECT * FROM edge")
            self._execute("DROP TABLE edge")
            self._execute("ALTER TABLE edge_v6 RENAME TO edge")
            self._execute("CREATE INDEX IF NOT EXISTS idx_edge_from ON edge(from_id)")
            self._execute("CREATE INDEX IF NOT EXISTS idx_edge_to   ON edge(to_id)")
            self._execute("CREATE INDEX IF NOT EXISTS idx_edge_type ON edge(edge_type)")

            self._execute(
                "INSERT OR REPLACE INTO _meta(key, value) VALUES ('schema_version', '6')"
            )
            self._conn.commit()
        if version < 7:
            # Telemetry sync_state: distinguish "confirmed present" from "we
            # couldn't check" (a collector errored). Every existing row came
            # from a successful sync, so backfill 'confirmed'. The CHECK lives in
            # schema.sql + the upsert_telemetry guard; ALTER just adds the column
            # with a default (SQLite can't add a CHECK retroactively).
            cols = {r["name"] for r in self._fetchall("PRAGMA table_info(telemetry)")}
            if "sync_state" not in cols:
                self._execute(
                    "ALTER TABLE telemetry ADD COLUMN sync_state TEXT NOT NULL "
                    "DEFAULT 'confirmed'"
                )
            if "unconfirmed_reason" not in cols:
                self._execute("ALTER TABLE telemetry ADD COLUMN unconfirmed_reason TEXT")
            self._execute(
                "INSERT OR REPLACE INTO _meta(key, value) VALUES ('schema_version', '7')"
            )
            self._conn.commit()
        if version < 8:
            # Four-state posture + auditable engineer override (paper §3.2).
            # Existing rows get their status computed immediately.
            cols = {r["name"] for r in self._fetchall("PRAGMA table_info(threat_instance)")}
            for col in ("computed_status", "effective_status", "override_status",
                        "override_by", "override_reason", "override_at"):
                if col not in cols:
                    self._execute(f"ALTER TABLE threat_instance ADD COLUMN {col} TEXT")
            self._execute(
                "INSERT OR REPLACE INTO _meta(key, value) VALUES ('schema_version', '8')"
            )
            self._conn.commit()
            self.recompute_coverage()

    def _execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, params)

    def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        cur = self._execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        cur = self._execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

    def _now(self) -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ------------------------------------------------------------------
    # Node upserts
    # ------------------------------------------------------------------

    def upsert_app(
        self,
        id: str,
        name: str,
        owner: str,
        env: str,
        exposure: str,
        *,
        synced_by: str | None = None,
    ) -> None:
        """Insert or update an App node.

        When `synced_by` is provided, sets `last_synced_at=now()` and
        `synced_by=<name>` so the row carries provenance from whichever
        connector wrote it. Hand-authored writes (CLI, tests) omit it.
        """
        now = self._now()
        last_synced_at = now if synced_by else None
        self._execute(
            """
            INSERT INTO app(id, name, owner, env, exposure,
                            last_synced_at, synced_by, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, owner=excluded.owner,
                env=excluded.env, exposure=excluded.exposure,
                last_synced_at=COALESCE(excluded.last_synced_at, app.last_synced_at),
                synced_by=COALESCE(excluded.synced_by, app.synced_by),
                updated_at=excluded.updated_at
            """,
            (id, name, owner, env, exposure, last_synced_at, synced_by, now, now),
        )
        self._conn.commit()
        _log.debug("upsert_app id=%s synced_by=%s", id, synced_by)

    def upsert_ttp(
        self,
        id: str,
        name: str,
        description: str = "",
        mitre_id: str | None = None,
        *,
        is_subtechnique: bool = False,
        revoked_by_id: str | None = None,
        platforms: list[str] | None = None,
        source: str | None = None,
        source_version: str | None = None,
        external_url: str | None = None,
    ) -> None:
        """Insert or update a TTP node.

        The keyword-only fields carry ATT&CK overlay metadata. `source` is
        the canonical provenance marker — set to ``"mitre-attack"`` for rows
        written by the refdata loader; left ``None`` for seed/human-authored
        rows so the loader never overwrites them.

        ``local_notes`` is deliberately not accepted here: it is human-edited
        and must never be touched by automated writes. Edit it via SQL or a
        future dedicated method.
        """
        now = self._now()
        last_synced_at = now if source else None
        platforms_json = json.dumps(platforms) if platforms else None
        self._execute(
            """
            INSERT INTO ttp(id, mitre_id, name, description,
                            is_subtechnique, revoked_by_id, platforms,
                            source, source_version, external_url, last_synced_at,
                            created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                mitre_id=excluded.mitre_id, name=excluded.name,
                description=excluded.description,
                is_subtechnique=excluded.is_subtechnique,
                revoked_by_id=excluded.revoked_by_id,
                platforms=excluded.platforms,
                source=COALESCE(excluded.source, ttp.source),
                source_version=COALESCE(excluded.source_version, ttp.source_version),
                external_url=COALESCE(excluded.external_url, ttp.external_url),
                last_synced_at=COALESCE(excluded.last_synced_at, ttp.last_synced_at),
                updated_at=excluded.updated_at
            """,
            (id, mitre_id, name, description,
             int(is_subtechnique), revoked_by_id, platforms_json,
             source, source_version, external_url, last_synced_at,
             now, now),
        )
        self._conn.commit()
        _log.debug("upsert_ttp id=%s mitre_id=%s source=%s", id, mitre_id, source)

    # ------------------------------------------------------------------
    # ATT&CK overlay upserts (v6)
    # ------------------------------------------------------------------
    #
    # `local_notes` is intentionally excluded from every signature below:
    # the refdata loader is the only caller and must NEVER overwrite human
    # annotations. Hand-edit `local_notes` via SQL.

    def upsert_tactic(
        self,
        id: str,
        mitre_id: str,
        name: str,
        short_name: str,
        description: str = "",
        *,
        source: str | None = None,
        source_version: str | None = None,
        external_url: str | None = None,
    ) -> None:
        """Insert or update a Tactic node."""
        now = self._now()
        last_synced_at = now if source else None
        self._execute(
            """
            INSERT INTO tactic(id, mitre_id, name, short_name, description,
                               source, source_version, external_url, last_synced_at,
                               created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                mitre_id=excluded.mitre_id, name=excluded.name,
                short_name=excluded.short_name, description=excluded.description,
                source=COALESCE(excluded.source, tactic.source),
                source_version=COALESCE(excluded.source_version, tactic.source_version),
                external_url=COALESCE(excluded.external_url, tactic.external_url),
                last_synced_at=COALESCE(excluded.last_synced_at, tactic.last_synced_at),
                updated_at=excluded.updated_at
            """,
            (id, mitre_id, name, short_name, description,
             source, source_version, external_url, last_synced_at, now, now),
        )
        self._conn.commit()
        _log.debug("upsert_tactic id=%s mitre_id=%s source=%s", id, mitre_id, source)

    def upsert_mitigation(
        self,
        id: str,
        mitre_id: str,
        name: str,
        description: str = "",
        *,
        source: str | None = None,
        source_version: str | None = None,
        external_url: str | None = None,
    ) -> None:
        """Insert or update a Mitigation node (MITRE's recommended mitigation)."""
        now = self._now()
        last_synced_at = now if source else None
        self._execute(
            """
            INSERT INTO mitigation(id, mitre_id, name, description,
                                   source, source_version, external_url, last_synced_at,
                                   created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                mitre_id=excluded.mitre_id, name=excluded.name,
                description=excluded.description,
                source=COALESCE(excluded.source, mitigation.source),
                source_version=COALESCE(excluded.source_version, mitigation.source_version),
                external_url=COALESCE(excluded.external_url, mitigation.external_url),
                last_synced_at=COALESCE(excluded.last_synced_at, mitigation.last_synced_at),
                updated_at=excluded.updated_at
            """,
            (id, mitre_id, name, description,
             source, source_version, external_url, last_synced_at, now, now),
        )
        self._conn.commit()
        _log.debug("upsert_mitigation id=%s mitre_id=%s source=%s", id, mitre_id, source)

    def upsert_data_source(
        self,
        id: str,
        mitre_id: str,
        name: str,
        description: str = "",
        *,
        source: str | None = None,
        source_version: str | None = None,
        external_url: str | None = None,
    ) -> None:
        """Insert or update a DataSource node."""
        now = self._now()
        last_synced_at = now if source else None
        self._execute(
            """
            INSERT INTO data_source(id, mitre_id, name, description,
                                    source, source_version, external_url, last_synced_at,
                                    created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                mitre_id=excluded.mitre_id, name=excluded.name,
                description=excluded.description,
                source=COALESCE(excluded.source, data_source.source),
                source_version=COALESCE(excluded.source_version, data_source.source_version),
                external_url=COALESCE(excluded.external_url, data_source.external_url),
                last_synced_at=COALESCE(excluded.last_synced_at, data_source.last_synced_at),
                updated_at=excluded.updated_at
            """,
            (id, mitre_id, name, description,
             source, source_version, external_url, last_synced_at, now, now),
        )
        self._conn.commit()
        _log.debug("upsert_data_source id=%s mitre_id=%s source=%s", id, mitre_id, source)

    def upsert_data_component(
        self,
        id: str,
        mitre_id: str,
        name: str,
        data_source_id: str,
        description: str = "",
        *,
        source: str | None = None,
        source_version: str | None = None,
        external_url: str | None = None,
    ) -> None:
        """Insert or update a DataComponent node tied to its parent DataSource."""
        now = self._now()
        last_synced_at = now if source else None
        self._execute(
            """
            INSERT INTO data_component(id, mitre_id, name, description, data_source_id,
                                       source, source_version, external_url, last_synced_at,
                                       created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                mitre_id=excluded.mitre_id, name=excluded.name,
                description=excluded.description, data_source_id=excluded.data_source_id,
                source=COALESCE(excluded.source, data_component.source),
                source_version=COALESCE(excluded.source_version, data_component.source_version),
                external_url=COALESCE(excluded.external_url, data_component.external_url),
                last_synced_at=COALESCE(excluded.last_synced_at, data_component.last_synced_at),
                updated_at=excluded.updated_at
            """,
            (id, mitre_id, name, description, data_source_id,
             source, source_version, external_url, last_synced_at, now, now),
        )
        self._conn.commit()
        _log.debug("upsert_data_component id=%s mitre_id=%s ds=%s", id, mitre_id, data_source_id)

    def upsert_threat_instance(
        self,
        app_id: str,
        ttp_id: str,
        version_id: str = "v1",
        likelihood: float | None = None,
        impact: float | None = None,
        priority: int | None = None,
        last_reviewed: str | None = None,
    ) -> str:
        """
        Insert or update the canonical (App, TTP, version) ThreatInstance.
        Returns the canonical id "app_id:ttp_id:version_id".

        version_id distinguishes successive assessments for the same (app, ttp)
        pair so prior assessments may be retained when re-evaluating coverage.
        Defaults to "v1".
        """
        ti_id = f"{app_id}:{ttp_id}:{version_id}"
        now = self._now()
        self._execute(
            """
            INSERT INTO threat_instance(
                id, app_id, ttp_id, version_id, likelihood, impact, priority,
                last_reviewed, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                likelihood=excluded.likelihood, impact=excluded.impact,
                priority=excluded.priority, last_reviewed=excluded.last_reviewed,
                updated_at=excluded.updated_at
            """,
            (ti_id, app_id, ttp_id, version_id, likelihood, impact, priority,
             last_reviewed, now, now),
        )
        self._conn.commit()
        self._recompute_ti_coverage(ti_id)
        _log.debug("upsert_threat_instance id=%s priority=%s", ti_id, priority)
        return ti_id

    def upsert_detection(
        self,
        id: str,
        name: str,
        type: str,
        owner: str,
        confidence: float | None = None,
        telemetry_sources: list[str] | None = None,
    ) -> None:
        """Insert or update a Detection node."""
        now = self._now()
        ts_json = json.dumps(telemetry_sources) if telemetry_sources is not None else None
        self._execute(
            """
            INSERT INTO detection(id, name, type, owner, confidence, telemetry_sources,
                                  created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, type=excluded.type, owner=excluded.owner,
                confidence=excluded.confidence, telemetry_sources=excluded.telemetry_sources,
                updated_at=excluded.updated_at
            """,
            (id, name, type, owner, confidence, ts_json, now, now),
        )
        self._conn.commit()
        _log.debug("upsert_detection id=%s type=%s confidence=%s", id, type, confidence)

    def upsert_control(
        self,
        id: str,
        name: str,
        type: str,
        owner: str,
        effectiveness: float | None = None,
    ) -> None:
        """Insert or update a Control node."""
        now = self._now()
        self._execute(
            """
            INSERT INTO control(id, name, type, owner, effectiveness, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, type=excluded.type, owner=excluded.owner,
                effectiveness=excluded.effectiveness, updated_at=excluded.updated_at
            """,
            (id, name, type, owner, effectiveness, now, now),
        )
        self._conn.commit()
        self._recompute_many(self._tis_depending_on(id))
        _log.debug("upsert_control id=%s type=%s", id, type)

    def upsert_control_instance(
        self,
        app_id: str,
        ctrl_id: str,
        owner: str,
        effectiveness: float | None = None,
        notes: str | None = None,
        *,
        synced_by: str | None = None,
    ) -> str:
        """
        Insert or update the concrete (App, Control) ControlInstance.
        Returns the canonical id "app_id:ctrl_id". See `upsert_app` for `synced_by`.
        """
        ci_id = f"{app_id}:{ctrl_id}"
        now = self._now()
        last_synced_at = now if synced_by else None
        self._execute(
            """
            INSERT INTO control_instance(
                id, app_id, ctrl_id, owner, effectiveness, notes,
                last_synced_at, synced_by, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                owner=excluded.owner, effectiveness=excluded.effectiveness,
                notes=excluded.notes,
                last_synced_at=COALESCE(excluded.last_synced_at, control_instance.last_synced_at),
                synced_by=COALESCE(excluded.synced_by, control_instance.synced_by),
                updated_at=excluded.updated_at
            """,
            (ci_id, app_id, ctrl_id, owner, effectiveness, notes,
             last_synced_at, synced_by, now, now),
        )
        self._conn.commit()
        _log.debug("upsert_control_instance id=%s synced_by=%s", ci_id, synced_by)
        return ci_id

    def upsert_telemetry(
        self,
        id: str,
        name: str,
        source_system: str,
        owner: str,
        retention_days: int | None = None,
        last_verified: str | None = None,
        *,
        sync_state: str = "confirmed",
        unconfirmed_reason: str | None = None,
        synced_by: str | None = None,
    ) -> None:
        """Insert or update a Telemetry node. See `upsert_app` for `synced_by`.

        `sync_state='unconfirmed'` marks a source the collector could not verify
        (e.g. its sync module errored) — a known blind spot, not a confirmed
        gap. `unconfirmed_reason` carries why. Such nodes are informational only:
        add_edge rejects new PRODUCES/POWERS edges for them, and edges kept from
        when the source was confirmed no longer imply coverage — instances that
        depended on them compute as `unknown`, not `gap` (paper §3.4).
        """
        if sync_state not in ("confirmed", "unconfirmed"):
            raise ValueError(
                f"upsert_telemetry: sync_state must be confirmed/unconfirmed, "
                f"got {sync_state!r}"
            )
        now = self._now()
        last_synced_at = now if synced_by else None
        self._execute(
            """
            INSERT INTO telemetry(id, name, source_system, owner, retention_days,
                                  last_verified, last_synced_at, synced_by,
                                  sync_state, unconfirmed_reason,
                                  created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, source_system=excluded.source_system,
                owner=excluded.owner, retention_days=excluded.retention_days,
                last_verified=excluded.last_verified,
                last_synced_at=COALESCE(excluded.last_synced_at, telemetry.last_synced_at),
                synced_by=COALESCE(excluded.synced_by, telemetry.synced_by),
                sync_state=excluded.sync_state,
                unconfirmed_reason=excluded.unconfirmed_reason,
                updated_at=excluded.updated_at
            """,
            (id, name, source_system, owner, retention_days, last_verified,
             last_synced_at, synced_by, sync_state, unconfirmed_reason, now, now),
        )
        self._conn.commit()
        self._recompute_many(self._tis_depending_on(id))
        _log.debug("upsert_telemetry id=%s source_system=%s sync_state=%s synced_by=%s",
                   id, source_system, sync_state, synced_by)

    # ------------------------------------------------------------------
    # Sync session audit (provenance for connector-driven writes)
    # ------------------------------------------------------------------

    def start_sync_session(self, connector_name: str) -> int:
        """Open a new sync session for `connector_name`. Returns session id.

        Connectors call this at the top of their `sync()` method, do their
        upserts, then call `complete_sync_session(...)` with a terminal
        status. A row with status='running' that never gets completed is a
        crashed sync — surfaced by `list_sync_sessions(status='running')`.
        """
        cur = self._execute(
            "INSERT INTO sync_session(connector_name, started_at, status) "
            "VALUES(?,?,'running')",
            (connector_name, self._now()),
        )
        self._conn.commit()
        session_id = cur.lastrowid
        assert session_id is not None
        _log.debug("start_sync_session id=%d connector=%s", session_id, connector_name)
        return session_id

    def complete_sync_session(
        self,
        session_id: int,
        *,
        status: str,
        nodes_upserted: int = 0,
        edges_upserted: int = 0,
        metadata: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> None:
        """Close a sync session with a terminal status.

        `status` must be one of 'ok', 'error', 'stale_source'. `metadata`
        is serialized as JSON — connectors should put per-mapping row
        counts and null rates here for the observability story.
        """
        if status not in ("ok", "error", "stale_source"):
            raise ValueError(
                f"complete_sync_session: status must be ok/error/stale_source, got {status!r}"
            )
        self._execute(
            "UPDATE sync_session SET completed_at=?, status=?, "
            "    nodes_upserted=?, edges_upserted=?, metadata=?, error_message=? "
            "WHERE id=?",
            (
                self._now(), status, nodes_upserted, edges_upserted,
                json.dumps(metadata) if metadata is not None else None,
                error_message, session_id,
            ),
        )
        self._conn.commit()
        _log.info(
            "complete_sync_session id=%d status=%s nodes=%d edges=%d",
            session_id, status, nodes_upserted, edges_upserted,
        )

    def get_sync_session(self, session_id: int) -> dict[str, Any] | None:
        """Return a sync session by id, or None if not found."""
        return self._fetchone("SELECT * FROM sync_session WHERE id = ?", (session_id,))

    def list_sync_sessions(
        self,
        connector_name: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Recent sync sessions, newest first."""
        return self._fetchall(
            """
            SELECT * FROM sync_session
            WHERE (? IS NULL OR connector_name = ?)
              AND (? IS NULL OR status         = ?)
            ORDER BY started_at DESC, id DESC
            LIMIT ?
            """,
            (connector_name, connector_name, status, status, limit),
        )

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def add_edge(
        self,
        edge_type: str,
        from_id: str,
        to_id: str,
        attrs: dict[str, Any] | None = None,
    ) -> None:
        """
        Add a directed edge. Idempotent (UNIQUE on edge_type+from_id+to_id).
        Recomputes the ThreatInstances whose status the edge can change
        (DETECTED_BY, MITIGATED_BY, POWERS, PRODUCES) — edge-local, never the
        whole table. POWERS edges take `attrs={"requirement_group": n}`
        (default 1): telemetry in one group is conjunctive, separate groups are
        alternatives (paper §3.3).

        Enforces the T3 invariant: telemetry with sync_state='unconfirmed' is
        informational only, so PRODUCES/POWERS edges touching it are rejected
        with ValueError until the source is confirmed.
        """
        if edge_type in ("PRODUCES", "POWERS"):
            tel_id = to_id if edge_type == "PRODUCES" else from_id
            tel = self._fetchone(
                "SELECT sync_state, unconfirmed_reason FROM telemetry WHERE id = ?",
                (tel_id,),
            )
            if tel and tel["sync_state"] == "unconfirmed":
                raise ValueError(
                    f"add_edge: {edge_type} edge rejected — telemetry {tel_id!r} "
                    f"is unconfirmed ({tel['unconfirmed_reason'] or 'no reason recorded'}); "
                    "coverage-implying edges require a confirmed source"
                )
        attrs_json = json.dumps(attrs) if attrs is not None else None
        now = self._now()
        self._execute(
            """
            INSERT INTO edge(edge_type, from_id, to_id, attrs, created_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(edge_type, from_id, to_id) DO UPDATE SET
                attrs=excluded.attrs
            """,
            (edge_type, from_id, to_id, attrs_json, now),
        )
        self._conn.commit()
        _log.debug("add_edge type=%s from=%s to=%s", edge_type, from_id, to_id)
        self._recompute_many(self._tis_affected_by_edge(edge_type, from_id, to_id))

    def remove_edge(self, edge_type: str, from_id: str, to_id: str) -> None:
        """Remove a directed edge. Recomputes the ThreatInstances it affected."""
        affected = self._tis_affected_by_edge(edge_type, from_id, to_id)
        self._execute(
            "DELETE FROM edge WHERE edge_type=? AND from_id=? AND to_id=?",
            (edge_type, from_id, to_id),
        )
        self._conn.commit()
        _log.debug("remove_edge type=%s from=%s to=%s", edge_type, from_id, to_id)
        self._recompute_many(affected)

    # ------------------------------------------------------------------
    # Coverage materialization
    # ------------------------------------------------------------------

    _MAPPED_SQL = """
        UPDATE threat_instance SET
            has_detection = (
                SELECT COUNT(*) > 0 FROM edge
                WHERE edge_type = 'DETECTED_BY' AND from_id = threat_instance.id
            ),
            has_control = (
                SELECT COUNT(*) > 0 FROM edge
                WHERE edge_type = 'MITIGATED_BY' AND from_id = threat_instance.id
            ),
            effective_confidence = (
                SELECT AVG(d.confidence)
                FROM edge e JOIN detection d ON d.id = e.to_id
                WHERE e.edge_type = 'DETECTED_BY' AND e.from_id = threat_instance.id
            ),
            last_computed_at = ?,
            updated_at = ?
        {where}
    """

    _STATUS_SQL = """
        UPDATE threat_instance SET
            computed_status = ?,
            effective_status = COALESCE(override_status, ?)
        WHERE id = ?
    """

    def _db_out(self, node_id: str, edge_type: str) -> list[dict[str, Any]]:
        return self.list_edges(from_id=node_id, edge_type=edge_type)

    def _db_in(self, node_id: str, edge_type: str) -> list[dict[str, Any]]:
        return self.list_edges(to_id=node_id, edge_type=edge_type)

    def _tel_state(self, tel_id: str) -> str | None:
        row = self._fetchone("SELECT sync_state FROM telemetry WHERE id = ?", (tel_id,))
        return row["sync_state"] if row else None

    def _ci_type(self, ci_id: str) -> str | None:
        row = self._fetchone(
            "SELECT c.type FROM control_instance ci JOIN control c ON c.id = ci.ctrl_id "
            "WHERE ci.id = ?",
            (ci_id,),
        )
        return row["type"] if row else None

    def _recompute_ti_coverage(self, threat_instance_id: str) -> None:
        """Recompute materialized coverage fields for one ThreatInstance."""
        ti = self._fetchone(
            "SELECT app_id FROM threat_instance WHERE id = ?", (threat_instance_id,)
        )
        if not ti:
            return
        now = self._now()
        self._execute(self._MAPPED_SQL.format(where="WHERE id = ?"),
                      (now, now, threat_instance_id))
        status = _evaluate_status(threat_instance_id, ti["app_id"], self._db_out,
                                  self._db_in, self._tel_state, self._ci_type)
        self._execute(self._STATUS_SQL, (status, status, threat_instance_id))
        self._conn.commit()

    def _recompute_many(self, threat_instance_ids: set[str]) -> None:
        for ti_id in threat_instance_ids:
            self._recompute_ti_coverage(ti_id)

    def recompute_coverage(self, threat_instance_id: str | None = None) -> None:
        """
        Recompute materialized coverage fields.
        Pass a specific id to update one row; pass None to recompute all rows.

        The full recompute reads the four status-bearing edge types once into an
        in-memory index and evaluates every instance against it (O(|E|)),
        rather than issuing per-instance queries.
        """
        if threat_instance_id:
            self._recompute_ti_coverage(threat_instance_id)
            return
        now = self._now()
        self._execute(self._MAPPED_SQL.format(where=""), (now, now))

        out_idx: dict[tuple[str, str], list[dict[str, Any]]] = {}
        in_idx: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for e in self._fetchall(
            "SELECT edge_type, from_id, to_id, attrs FROM edge "
            "WHERE edge_type IN ('DETECTED_BY','MITIGATED_BY','PRODUCES','POWERS')"
        ):
            out_idx.setdefault((e["from_id"], e["edge_type"]), []).append(e)
            in_idx.setdefault((e["to_id"], e["edge_type"]), []).append(e)
        tel_state = {r["id"]: r["sync_state"]
                     for r in self._fetchall("SELECT id, sync_state FROM telemetry")}
        ci_type = {r["id"]: r["type"] for r in self._fetchall(
            "SELECT ci.id, c.type FROM control_instance ci JOIN control c ON c.id = ci.ctrl_id"
        )}
        rows = []
        for ti in self._fetchall("SELECT id, app_id FROM threat_instance"):
            status = _evaluate_status(
                ti["id"], ti["app_id"],
                lambda n, t: out_idx.get((n, t), []),
                lambda n, t: in_idx.get((n, t), []),
                tel_state.get, ci_type.get,
            )
            rows.append((status, status, ti["id"]))
        self._conn.executemany(self._STATUS_SQL, rows)
        self._conn.commit()

    def _tis_depending_on(self, node_id: str) -> set[str]:
        """ThreatInstances whose computed status can depend on `node_id`.

        Local by construction: each case is one or two index seeks
        (idx_edge_to_type / idx_edge_from_type / idx_ti_app).
        """
        rows = self._fetchall(
            """
            SELECT id FROM threat_instance WHERE id = ? OR app_id = ?
            UNION
            SELECT from_id FROM edge
            WHERE to_id = ? AND edge_type IN ('DETECTED_BY','MITIGATED_BY')
            UNION
            SELECT e_det.from_id FROM edge e_pow
              JOIN edge e_det ON e_det.to_id = e_pow.to_id AND e_det.edge_type = 'DETECTED_BY'
            WHERE e_pow.from_id = ? AND e_pow.edge_type = 'POWERS'
            UNION
            SELECT e_mit.from_id FROM edge e_impl
              JOIN edge e_mit ON e_mit.to_id = e_impl.to_id AND e_mit.edge_type = 'MITIGATED_BY'
            WHERE e_impl.from_id = ? AND e_impl.edge_type = 'IMPLEMENTED_BY'
            """,
            (node_id,) * 5,
        )
        return {r["id"] for r in rows}

    def _tis_affected_by_edge(self, edge_type: str, from_id: str, to_id: str) -> set[str]:
        """ThreatInstances whose computed status a single edge write can change."""
        if edge_type in ("DETECTED_BY", "MITIGATED_BY"):
            return {from_id}
        if edge_type == "POWERS":
            return {e["from_id"] for e in self.list_edges(to_id=to_id, edge_type="DETECTED_BY")}
        if edge_type == "PRODUCES":
            rows = self._fetchall(
                """
                SELECT e_det.from_id AS id FROM edge e_pow
                  JOIN edge e_det ON e_det.to_id = e_pow.to_id
                                 AND e_det.edge_type = 'DETECTED_BY'
                  JOIN threat_instance ti ON ti.id = e_det.from_id
                WHERE e_pow.from_id = ? AND e_pow.edge_type = 'POWERS'
                  AND ti.app_id = ?
                """,
                (to_id, from_id),
            )
            return {r["id"] for r in rows}
        return set()

    # ------------------------------------------------------------------
    # Security-engineer override (paper §3.2)
    # ------------------------------------------------------------------

    def set_status_override(
        self, threat_instance_id: str, status: str, engineer: str, reason: str,
    ) -> None:
        """Replace the computed status with an engineer's assessment.

        Used when structural control presence overstates real effectiveness or
        scope. The override records who, why, and when, so the effective status
        stays auditable; the computed status keeps being maintained underneath.
        """
        if status not in _STATUSES:
            raise ValueError(f"set_status_override: status must be one of {_STATUSES}, "
                             f"got {status!r}")
        if not engineer or not engineer.strip() or not reason or not reason.strip():
            raise ValueError("set_status_override: engineer and reason are required")
        cur = self._execute(
            """
            UPDATE threat_instance SET
                override_status = ?, override_by = ?, override_reason = ?,
                override_at = ?, effective_status = ?
            WHERE id = ?
            """,
            (status, engineer, reason, self._now(), status, threat_instance_id),
        )
        if cur.rowcount == 0:
            raise ValueError(f"set_status_override: no ThreatInstance {threat_instance_id!r}")
        self._conn.commit()

    def clear_status_override(self, threat_instance_id: str) -> None:
        """Drop an override; the effective status reverts to the computed one."""
        self._execute(
            """
            UPDATE threat_instance SET
                override_status = NULL, override_by = NULL, override_reason = NULL,
                override_at = NULL, effective_status = computed_status
            WHERE id = ?
            """,
            (threat_instance_id,),
        )
        self._conn.commit()

    def analyze(self) -> None:
        """Refresh SQLite's table statistics (runs ANALYZE).

        The coverage analytics join edges in both directions (e.g.
        Telemetry-POWERS-Detection on `to_id` while DETECTED_BY drives on
        `from_id`). Without statistics SQLite cannot tell which composite edge
        index to drive from and falls back to the UNIQUE autoindex's
        `edge_type` prefix — turning `false_coverage_check` into an O(n^2) scan.
        With statistics it picks `idx_edge_to_type` / `idx_edge_from_type` and
        the same query is linear.

        Bulk writers (connector syncs, the seed loader) should call this once
        after a large batch of upserts; it is cheap relative to the sync itself
        and only needs re-running after the graph's shape changes materially.
        `close()` also issues `PRAGMA optimize` so a long-lived connection keeps
        its stats fresh for the next session.
        """
        self._conn.execute("ANALYZE")
        self._conn.commit()

    # ------------------------------------------------------------------
    # Impact analysis (read-only simulation)
    # ------------------------------------------------------------------

    def impact_analysis(self, node_id: str) -> dict[str, Any]:
        """
        Simulate deletion of node_id without modifying the database.

        Returns a dict describing what would be deleted and which surviving
        ThreatInstances would see coverage degradation.

        Return shape:
        {
            "node_id":   str,
            "node_type": str,
            "node_label": str,
            "nodes_to_delete": [{"id": str, "type": str, "label": str}],
            "edges_to_delete": [{"id": int, "edge_type": str, "from_id": str, "to_id": str}],
            "coverage_changes": [
                {"ti_id": str, "app_id": str, "ttp_id": str,
                 "current_status": str, "new_status": str}   # effective status
            ],
        }
        Raises ValueError if node_id is not found.
        """
        # Step 1: Resolve node type + label
        node_type: str | None = None
        node_label: str | None = None

        row = self._fetchone("SELECT id, name FROM app WHERE id = ?", (node_id,))
        if row:
            node_type, node_label = "App", row["name"]

        if not node_type:
            row = self._fetchone("SELECT id, name FROM ttp WHERE id = ?", (node_id,))
            if row:
                node_type, node_label = "TTP", row["name"]

        if not node_type:
            row = self._fetchone(
                "SELECT ti.id, a.name AS app_name, t.name AS ttp_name "
                "FROM threat_instance ti "
                "JOIN app a ON a.id = ti.app_id "
                "JOIN ttp t ON t.id = ti.ttp_id "
                "WHERE ti.id = ?",
                (node_id,),
            )
            if row:
                node_type = "ThreatInstance"
                node_label = f"{row['app_name']} \u2192 {row['ttp_name']}"

        if not node_type:
            row = self._fetchone("SELECT id, name FROM detection WHERE id = ?", (node_id,))
            if row:
                node_type, node_label = "Detection", row["name"]

        if not node_type:
            row = self._fetchone("SELECT id, name FROM control WHERE id = ?", (node_id,))
            if row:
                node_type, node_label = "Control", row["name"]

        if not node_type:
            row = self._fetchone(
                "SELECT ci.id, a.name AS app_name, c.name AS ctrl_name "
                "FROM control_instance ci "
                "JOIN app a ON a.id = ci.app_id "
                "JOIN control c ON c.id = ci.ctrl_id "
                "WHERE ci.id = ?",
                (node_id,),
            )
            if row:
                node_type = "ControlInstance"
                node_label = f"{row['app_name']} \u2192 {row['ctrl_name']}"

        if not node_type:
            row = self._fetchone("SELECT id, name FROM telemetry WHERE id = ?", (node_id,))
            if row:
                node_type, node_label = "Telemetry", row["name"]

        if not node_type:
            raise ValueError(f"Node not found: {node_id!r}")

        # Step 2: Lazy, index-backed adjacency. Rather than loading the entire
        # edge table (O(|E|) — the prior implementation's scaling hotspot), fetch
        # only the edges incident to nodes we actually touch. Every lookup hits
        # idx_edge_from / idx_edge_to, and each node's adjacency is read at most
        # once. Cost becomes O((|doomed| + |affected|) * degree).
        _from_cache: dict[str, list[dict[str, Any]]] = {}
        _to_cache: dict[str, list[dict[str, Any]]] = {}

        def edges_from(nid: str) -> list[dict[str, Any]]:
            cached = _from_cache.get(nid)
            if cached is None:
                cached = self.list_edges(from_id=nid)
                _from_cache[nid] = cached
            return cached

        def edges_to(nid: str) -> list[dict[str, Any]]:
            cached = _to_cache.get(nid)
            if cached is None:
                cached = self.list_edges(to_id=nid)
                _to_cache[nid] = cached
            return cached

        # Step 3: Build doomed sets via cascade rules
        doomed_node_ids: set[str] = set()
        doomed_edge_ids: set[int] = set()
        doomed_edges: dict[int, dict[str, Any]] = {}

        def doom_node_and_edges(nid: str) -> None:
            doomed_node_ids.add(nid)
            for e in edges_from(nid) + edges_to(nid):
                doomed_edge_ids.add(e["id"])
                doomed_edges[e["id"]] = e

        doom_node_and_edges(node_id)

        if node_type == "App":
            # Cascade to all ThreatInstances (HAS_TI) and ControlInstances (HAS_CI)
            for e in edges_from(node_id):
                if e["edge_type"] in ("HAS_TI", "HAS_CI"):
                    doom_node_and_edges(e["to_id"])

        elif node_type == "TTP":
            # Cascade to all ThreatInstances described by this TTP
            for e in edges_from(node_id):
                if e["edge_type"] == "DESCRIBES":
                    doom_node_and_edges(e["to_id"])

        elif node_type == "Control":
            # Cascade to all ControlInstances via IMPLEMENTED_BY
            for e in edges_from(node_id):
                if e["edge_type"] == "IMPLEMENTED_BY":
                    doom_node_and_edges(e["to_id"])

        # Detection, Telemetry, ControlInstance, ThreatInstance: only the node itself + its edges

        # Step 4: Find surviving TIs whose coverage may be affected. Only the
        # doomed nodes' own adjacency can matter: a DETECTED_BY/MITIGATED_BY edge
        # into a doomed node, or — for decommissioned telemetry — a DETECTED_BY
        # edge into a detection the telemetry POWERS. Scan those lists, never
        # the whole edge table.
        affected_ti_ids: set[str] = set()
        for nid in list(doomed_node_ids):
            for e in edges_to(nid):
                if (e["edge_type"] in ("DETECTED_BY", "MITIGATED_BY")
                        and e["from_id"] not in doomed_node_ids):
                    affected_ti_ids.add(e["from_id"])
            for e in edges_from(nid):
                if e["edge_type"] == "POWERS":
                    for d in edges_to(e["to_id"]):
                        if (d["edge_type"] == "DETECTED_BY"
                                and d["from_id"] not in doomed_node_ids):
                            affected_ti_ids.add(d["from_id"])

        # Step 5: Simulate the effective status of each affected TI with the
        # same evaluator the materialized status uses, over a view of the
        # neighborhood that hides doomed nodes and edges.
        def alive(e: dict[str, Any]) -> bool:
            return (e["id"] not in doomed_edge_ids
                    and e["from_id"] not in doomed_node_ids
                    and e["to_id"] not in doomed_node_ids)

        def sim_out(nid: str, edge_type: str) -> list[dict[str, Any]]:
            return [e for e in edges_from(nid) if e["edge_type"] == edge_type and alive(e)]

        def sim_in(nid: str, edge_type: str) -> list[dict[str, Any]]:
            return [e for e in edges_to(nid) if e["edge_type"] == edge_type and alive(e)]

        def sim_tel_state(tel_id: str) -> str | None:
            return None if tel_id in doomed_node_ids else self._tel_state(tel_id)

        def sim_ci_type(ci_id: str) -> str | None:
            return None if ci_id in doomed_node_ids else self._ci_type(ci_id)

        coverage_changes: list[dict[str, Any]] = []
        for ti_id in affected_ti_ids:
            ti_row = self._fetchone(
                "SELECT * FROM threat_instance WHERE id = ?", (ti_id,)
            )
            if not ti_row:
                continue
            current = ti_row["effective_status"]
            new_sim = ti_row["override_status"] or _evaluate_status(
                ti_id, ti_row["app_id"], sim_out, sim_in, sim_tel_state, sim_ci_type)
            if current != new_sim:
                coverage_changes.append({
                    "ti_id": ti_id,
                    "app_id": ti_row["app_id"],
                    "ttp_id": ti_row["ttp_id"],
                    "version_id": ti_row.get("version_id"),
                    "current_status": current,
                    "new_status": new_sim,
                })

        # Step 6: Build nodes_to_delete metadata
        nodes_to_delete: list[dict[str, Any]] = []
        for nid in doomed_node_ids:
            r = self._fetchone("SELECT 'App' AS type, name AS label FROM app WHERE id=?", (nid,))
            if not r:
                r = self._fetchone(
                    "SELECT 'ThreatInstance' AS type, "
                    "(a.name || ' \u2192 ' || t.name) AS label "
                    "FROM threat_instance ti "
                    "JOIN app a ON a.id = ti.app_id "
                    "JOIN ttp t ON t.id = ti.ttp_id "
                    "WHERE ti.id=?",
                    (nid,),
                )
            if not r:
                r = self._fetchone("SELECT 'Detection' AS type, name AS label FROM detection WHERE id=?", (nid,))
            if not r:
                r = self._fetchone("SELECT 'Control' AS type, name AS label FROM control WHERE id=?", (nid,))
            if not r:
                r = self._fetchone(
                    "SELECT 'ControlInstance' AS type, "
                    "(a.name || ' \u2192 ' || c.name) AS label "
                    "FROM control_instance ci "
                    "JOIN app a ON a.id = ci.app_id "
                    "JOIN control c ON c.id = ci.ctrl_id "
                    "WHERE ci.id=?",
                    (nid,),
                )
            if not r:
                r = self._fetchone("SELECT 'Telemetry' AS type, name AS label FROM telemetry WHERE id=?", (nid,))
            if not r:
                r = self._fetchone("SELECT 'TTP' AS type, name AS label FROM ttp WHERE id=?", (nid,))
            if r:
                nodes_to_delete.append({"id": nid, "type": r["type"], "label": r["label"]})

        # Step 7: Build edges_to_delete list from the edges we already collected
        # while dooming, sorted to match list_edges()' (edge_type, from, to) order.
        edges_to_delete = [
            {"id": e["id"], "edge_type": e["edge_type"], "from_id": e["from_id"], "to_id": e["to_id"]}
            for e in sorted(
                doomed_edges.values(),
                key=lambda e: (e["edge_type"], e["from_id"], e["to_id"]),
            )
        ]

        return {
            "node_id": node_id,
            "node_type": node_type,
            "node_label": node_label,
            "nodes_to_delete": nodes_to_delete,
            "edges_to_delete": edges_to_delete,
            "coverage_changes": coverage_changes,
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_coverage_for_app(self, app_id: str) -> list[dict[str, Any]]:
        """
        Return all ThreatInstances for an app with coverage status.
        Ordered by priority descending (5=highest risk first).
        """
        return self._fetchall(
            """
            SELECT ti.id, ti.app_id, ti.ttp_id, ti.likelihood, ti.impact,
                   ti.priority, ti.last_reviewed, ti.has_detection, ti.has_control,
                   ti.effective_confidence, ti.last_computed_at,
                   ti.effective_status, ti.computed_status, ti.override_status,
                   t.mitre_id, t.name AS ttp_name, t.description AS ttp_description
            FROM threat_instance ti
              JOIN ttp t ON t.id = ti.ttp_id
            WHERE ti.app_id = ?
            ORDER BY ti.priority DESC NULLS LAST
            """,
            (app_id,),
        )

    def get_coverage_for_ttp(self, ttp_id: str) -> list[dict[str, Any]]:
        """
        Return all ThreatInstances for a TTP across all apps.
        Ordered by exposure (internet first) then priority descending.
        """
        return self._fetchall(
            """
            SELECT ti.id, ti.app_id, ti.ttp_id, ti.likelihood, ti.impact,
                   ti.priority, ti.has_detection, ti.has_control,
                   ti.effective_confidence, ti.last_computed_at,
                   ti.effective_status, ti.computed_status, ti.override_status,
                   a.name AS app_name, a.env, a.exposure
            FROM threat_instance ti
              JOIN app a ON a.id = ti.app_id
            WHERE ti.ttp_id = ?
            ORDER BY
                CASE a.exposure WHEN 'internet' THEN 0 ELSE 1 END,
                ti.priority DESC NULLS LAST
            """,
            (ttp_id,),
        )

    def list_detection_gaps(self, app_id: str | None = None) -> list[dict[str, Any]]:
        """
        Return ThreatInstances with no DETECTED_BY edge (has_detection=0).
        Optionally filter to a single app. Ordered by priority descending.
        """
        return self._fetchall(
            """
            SELECT ti.id, ti.priority, ti.likelihood, ti.impact,
                   ti.has_control, ti.effective_confidence,
                   a.id AS app_id, a.name AS app_name, a.env, a.exposure,
                   t.id AS ttp_id, t.name AS ttp_name, t.mitre_id
            FROM threat_instance ti
              JOIN app a ON a.id = ti.app_id
              JOIN ttp t ON t.id = ti.ttp_id
            WHERE ti.has_detection = 0
              AND (? IS NULL OR ti.app_id = ?)
            ORDER BY ti.priority DESC NULLS LAST
            """,
            (app_id, app_id),
        )

    def list_mitigation_gaps(self, app_id: str | None = None) -> list[dict[str, Any]]:
        """
        Return ThreatInstances with no MITIGATED_BY edge (has_control=0).
        Optionally filter to a single app. Ordered by priority descending.
        """
        return self._fetchall(
            """
            SELECT ti.id, ti.priority, ti.likelihood, ti.impact,
                   ti.has_detection, ti.effective_confidence,
                   a.id AS app_id, a.name AS app_name, a.env, a.exposure,
                   t.id AS ttp_id, t.name AS ttp_name, t.mitre_id
            FROM threat_instance ti
              JOIN app a ON a.id = ti.app_id
              JOIN ttp t ON t.id = ti.ttp_id
            WHERE ti.has_control = 0
              AND (? IS NULL OR ti.app_id = ?)
            ORDER BY ti.priority DESC NULLS LAST
            """,
            (app_id, app_id),
        )

    def list_mitre_recommendation_gaps(
        self, app_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        For every (App, TTP, MITRE-recommended-mitigation) triple bound into
        the SCG, surface the cases where the App has no ControlInstance whose
        Control name matches the mitigation name.

        This is the headline ATT&CK overlay query: "where does MITRE
        recommend a mitigation we don't actually implement?"

        Coverage match is intentionally crude in v1 — case-insensitive
        substring match between `mitigation.name` and `control.name`
        (substring tested in both directions to absorb naming variance
        like "User Training" vs "Annual User Security Training"). False
        positives are expected; the query is a starting point for a
        richer ATT&CK-to-control mapping, not a final verdict.

        Args:
            app_id: Optional filter — restrict to one App.

        Returns:
            Rows with `app_id`, `app_name`, `ttp_id`, `ttp_mitre_id`,
            `ttp_name`, `mitigation_id`, `mitigation_mitre_id`,
            `mitigation_name`. Ordered by app_name, ttp_mitre_id, mitigation_mitre_id.
        """
        return self._fetchall(
            """
            SELECT DISTINCT
                a.id AS app_id, a.name AS app_name,
                t.id AS ttp_id, t.mitre_id AS ttp_mitre_id, t.name AS ttp_name,
                m.id AS mitigation_id, m.mitre_id AS mitigation_mitre_id,
                m.name AS mitigation_name
            FROM threat_instance ti
              JOIN app a       ON a.id = ti.app_id
              JOIN ttp t       ON t.id = ti.ttp_id
              JOIN edge e_rec  ON e_rec.from_id = ti.ttp_id
                              AND e_rec.edge_type = 'MITIGATED_BY_REF'
              JOIN mitigation m ON m.id = e_rec.to_id
            WHERE (? IS NULL OR ti.app_id = ?)
              AND NOT EXISTS (
                SELECT 1
                FROM control_instance ci
                  JOIN control c ON c.id = ci.ctrl_id
                WHERE ci.app_id = a.id
                  AND (
                       INSTR(LOWER(c.name), LOWER(m.name)) > 0
                    OR INSTR(LOWER(m.name), LOWER(c.name)) > 0
                  )
              )
            ORDER BY a.name, t.mitre_id, m.mitre_id
            """,
            (app_id, app_id),
        )

    def telemetry_powering_detection(self, detection_id: str) -> list[dict[str, Any]]:
        """Return all Telemetry nodes linked to a Detection via POWERS edges."""
        return self._fetchall(
            """
            SELECT tel.*
            FROM telemetry tel
              JOIN edge e ON e.from_id = tel.id AND e.edge_type = 'POWERS'
            WHERE e.to_id = ?
            """,
            (detection_id,),
        )

    def false_coverage_check(self, app_id: str | None = None) -> list[dict[str, Any]]:
        """
        False coverage (paper §3.3): a DETECTED_BY mapping whose detection is
        not operable for the instance's app — no POWERS requirement group has
        all of its telemetry PRODUCED by that app.

        Evaluated as an anti-join; no rule is executed. A mapping with a group
        the app fully PRODUCES is excluded even when that group's telemetry is
        unconfirmed: that is T3 `unknown` (we could not check), not proof that
        the data path is absent.

        Pass `app_id` to scope the scan to a single application (indexed via
        idx_ti_app) — useful on large estates where a full-graph scan is wasteful
        and analysis is naturally per-app. None (default) scans all apps.

        Returns one row per missing telemetry input of each falsely covering
        mapping (telemetry columns are NULL for a detection with no POWERS edge):
            threat_instance_id, app_id, app_name,
            detection_id, detection_name,
            telemetry_id, telemetry_name, source_system
        """
        # Append the app predicate as a plain equality (not `? IS NULL OR ...`)
        # only when scoping, so idx_ti_app drives the scan for one app instead
        # of a full threat_instance scan.
        app_clause = "AND ti.app_id = ?" if app_id is not None else ""
        params = (app_id,) if app_id is not None else ()
        # A requirement group is satisfiable unless the app does not PRODUCE one
        # of its members; the mapping is false coverage when no group is.
        return self._fetchall(
            f"""
            SELECT DISTINCT
                ti.id    AS threat_instance_id,
                ti.app_id,
                a.name   AS app_name,
                d.id     AS detection_id,
                d.name   AS detection_name,
                tel.id   AS telemetry_id,
                tel.name AS telemetry_name,
                tel.source_system
            FROM threat_instance ti
              JOIN app a            ON a.id = ti.app_id
              JOIN edge e_det       ON e_det.from_id = ti.id
                                   AND e_det.edge_type = 'DETECTED_BY'
              JOIN detection d      ON d.id = e_det.to_id
              LEFT JOIN edge e_pow  ON e_pow.to_id = d.id
                                   AND e_pow.edge_type = 'POWERS'
              LEFT JOIN telemetry tel ON tel.id = e_pow.from_id
            WHERE NOT EXISTS (
                SELECT 1 FROM edge grp
                WHERE grp.to_id = d.id AND grp.edge_type = 'POWERS'
                  AND NOT EXISTS (
                    SELECT 1 FROM edge mem
                    WHERE mem.to_id = d.id AND mem.edge_type = 'POWERS'
                      AND COALESCE(json_extract(mem.attrs, '$.requirement_group'), 1)
                        = COALESCE(json_extract(grp.attrs, '$.requirement_group'), 1)
                      AND NOT EXISTS (
                        SELECT 1 FROM edge p
                        WHERE p.edge_type = 'PRODUCES'
                          AND p.from_id = ti.app_id AND p.to_id = mem.from_id)))
              AND (tel.id IS NULL OR NOT EXISTS (
                    SELECT 1 FROM edge ep
                    WHERE ep.edge_type = 'PRODUCES'
                      AND ep.from_id = ti.app_id AND ep.to_id = tel.id))
              {app_clause}
            ORDER BY ti.app_id, ti.id
            """,
            params,
        )

    # ------------------------------------------------------------------
    # Node reads
    # ------------------------------------------------------------------

    def get_app(self, id: str) -> dict[str, Any] | None:
        """Return an App node by id, or None if not found."""
        return self._fetchone("SELECT * FROM app WHERE id = ?", (id,))

    def get_ttp(self, id: str) -> dict[str, Any] | None:
        """Return a TTP node by id, or None if not found."""
        return self._fetchone("SELECT * FROM ttp WHERE id = ?", (id,))

    def get_threat_instance(self, id: str) -> dict[str, Any] | None:
        """Return a ThreatInstance with joined app/ttp names, or None."""
        return self._fetchone(
            """
            SELECT ti.*, a.name AS app_name, t.name AS ttp_name, t.mitre_id
            FROM threat_instance ti
              JOIN app a ON a.id = ti.app_id
              JOIN ttp t ON t.id = ti.ttp_id
            WHERE ti.id = ?
            """,
            (id,),
        )

    def get_detection(self, id: str) -> dict[str, Any] | None:
        """Return a Detection node by id, or None if not found."""
        return self._fetchone("SELECT * FROM detection WHERE id = ?", (id,))

    def get_control(self, id: str) -> dict[str, Any] | None:
        """Return a Control node by id, or None if not found."""
        return self._fetchone("SELECT * FROM control WHERE id = ?", (id,))

    def get_telemetry(self, id: str) -> dict[str, Any] | None:
        """Return a Telemetry node by id, or None if not found."""
        return self._fetchone("SELECT * FROM telemetry WHERE id = ?", (id,))

    def list_apps(self) -> list[dict[str, Any]]:
        """Return all App nodes ordered by name."""
        return self._fetchall("SELECT * FROM app ORDER BY name")

    def list_ttps(self) -> list[dict[str, Any]]:
        """Return all TTP nodes ordered by mitre_id, then name."""
        return self._fetchall("SELECT * FROM ttp ORDER BY mitre_id NULLS LAST, name")

    def list_threat_instances(
        self,
        app_id: str | None = None,
        ttp_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return ThreatInstances with joined app/ttp names.
        Optionally filter by app_id and/or ttp_id. Ordered by priority desc.
        """
        return self._fetchall(
            """
            SELECT ti.*, a.name AS app_name, t.name AS ttp_name, t.mitre_id
            FROM threat_instance ti
              JOIN app a ON a.id = ti.app_id
              JOIN ttp t ON t.id = ti.ttp_id
            WHERE (? IS NULL OR ti.app_id = ?)
              AND (? IS NULL OR ti.ttp_id = ?)
            ORDER BY ti.priority DESC NULLS LAST
            """,
            (app_id, app_id, ttp_id, ttp_id),
        )

    def list_detections(self) -> list[dict[str, Any]]:
        """Return all Detection nodes ordered by name."""
        return self._fetchall("SELECT * FROM detection ORDER BY name")

    def list_controls(self) -> list[dict[str, Any]]:
        """Return all Control nodes ordered by name."""
        return self._fetchall("SELECT * FROM control ORDER BY name")

    def list_control_instances(
        self,
        app_id: str | None = None,
        ctrl_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return ControlInstances with joined app/control names.
        Optionally filter by app_id and/or ctrl_id. Ordered by app_id, ctrl_id.
        """
        return self._fetchall(
            """
            SELECT ci.*, a.name AS app_name, c.name AS ctrl_name, c.type AS ctrl_type
            FROM control_instance ci
              JOIN app a     ON a.id = ci.app_id
              JOIN control c ON c.id = ci.ctrl_id
            WHERE (? IS NULL OR ci.app_id  = ?)
              AND (? IS NULL OR ci.ctrl_id = ?)
            ORDER BY ci.app_id, ci.ctrl_id
            """,
            (app_id, app_id, ctrl_id, ctrl_id),
        )

    def list_apps_implementing(self, ctrl_id: str) -> list[dict[str, Any]]:
        """Return all App nodes that implement the given Control catalog node."""
        return self._fetchall(
            """
            SELECT a.*
            FROM app a
              JOIN control_instance ci ON ci.app_id = a.id
            WHERE ci.ctrl_id = ?
            ORDER BY a.name
            """,
            (ctrl_id,),
        )

    def list_telemetry(self) -> list[dict[str, Any]]:
        """Return all Telemetry nodes ordered by name."""
        return self._fetchall("SELECT * FROM telemetry ORDER BY name")

    # ------------------------------------------------------------------
    # Edge reads
    # ------------------------------------------------------------------

    def list_edges(
        self,
        from_id: str | None = None,
        to_id: str | None = None,
        edge_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return edges matching any combination of from_id, to_id, edge_type.
        Pass None for any parameter to skip that filter.
        Returns all edges if all parameters are None.

        The WHERE clause is built from only the predicates actually supplied so
        SQLite can use idx_edge_from / idx_edge_to / idx_edge_type. The
        `(? IS NULL OR col = ?)` idiom defeats those indexes — it forces a full
        table SCAN — which is the difference between an O(degree) index seek and
        an O(|E|) scan on every call (the impact_analysis / delete_node hotspot).
        """
        clauses: list[str] = []
        params: list[Any] = []
        if from_id is not None:
            clauses.append("from_id = ?")
            params.append(from_id)
        if to_id is not None:
            clauses.append("to_id = ?")
            params.append(to_id)
        if edge_type is not None:
            clauses.append("edge_type = ?")
            params.append(edge_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return self._fetchall(
            f"""
            SELECT id, edge_type, from_id, to_id, attrs, created_at
            FROM edge
            {where}
            ORDER BY edge_type, from_id, to_id
            """,
            tuple(params),
        )

    # ------------------------------------------------------------------
    # Node deletes
    # ------------------------------------------------------------------

    def delete_node(self, node_id: str) -> bool:
        """
        Delete a node by id from whichever node table it lives in.

        Cascade behaviour:
        - App or TTP: also deletes all ThreatInstances that reference it,
          plus those TIs' connected edges.
        - Any node type: removes all edges where from_id or to_id equals
          node_id.

        Recomputes coverage on exactly the surviving ThreatInstances whose
        coverage depended on a removed node — not the whole table — so the
        materialized status stays consistent without an O(all TIs) sweep.

        Returns True if the node was found and deleted, False otherwise.
        """
        # ControlInstances cascade-deleted by an App/Control deletion can change
        # coverage on surviving TIs of OTHER apps (a TI may be MITIGATED_BY a CI
        # owned by a security-tool app). Resolve them up front so we know the full
        # set of coverage targets being removed.
        ci_rows = self._fetchall(
            "SELECT id FROM control_instance WHERE app_id = ? OR ctrl_id = ?",
            (node_id, node_id),
        )
        removed_targets = {node_id} | {ci["id"] for ci in ci_rows}

        # Surviving TIs whose materialized coverage depends on a removed target
        # (a local lookup per target — see _tis_depending_on). Captured before
        # we delete the edges.
        affected_ti_ids: set[str] = set()
        for target in removed_targets:
            affected_ti_ids |= self._tis_depending_on(target)

        # Cascade through threat_instances for App/TTP deletions
        ti_rows = self._fetchall(
            "SELECT id FROM threat_instance WHERE app_id = ? OR ttp_id = ?",
            (node_id, node_id),
        )
        for ti in ti_rows:
            self._execute(
                "DELETE FROM edge WHERE from_id = ? OR to_id = ?",
                (ti["id"], ti["id"]),
            )
        self._execute(
            "DELETE FROM threat_instance WHERE app_id = ? OR ttp_id = ?",
            (node_id, node_id),
        )
        # Cascade through control_instances for App/Control deletions
        for ci in ci_rows:
            self._execute(
                "DELETE FROM edge WHERE from_id = ? OR to_id = ?",
                (ci["id"], ci["id"]),
            )
        self._execute(
            "DELETE FROM control_instance WHERE app_id = ? OR ctrl_id = ?",
            (node_id, node_id),
        )
        # Remove all edges directly attached to this node
        self._execute(
            "DELETE FROM edge WHERE from_id = ? OR to_id = ?",
            (node_id, node_id),
        )
        # Delete from the owning table
        deleted = False
        for table in ("app", "ttp", "threat_instance", "detection", "control",
                      "control_instance", "telemetry"):
            cur = self._execute(f"DELETE FROM {table} WHERE id = ?", (node_id,))
            if cur.rowcount > 0:
                deleted = True
                break
        self._conn.commit()
        if deleted:
            # Recompute only surviving TIs that lost a coverage edge. TIs deleted
            # by the cascade above are gone, so skip them (a recompute on a missing
            # id would no-op anyway).
            deleted_ti_ids = {ti["id"] for ti in ti_rows}
            for ti_id in affected_ti_ids - deleted_ti_ids:
                self._recompute_ti_coverage(ti_id)
        return deleted

    # ------------------------------------------------------------------
    # Graph summary
    # ------------------------------------------------------------------

    def graph_summary(self) -> dict[str, Any]:
        """
        Return a snapshot of entity counts and edge-type distribution.
        Useful for agent orientation before issuing queries.

        Returns a dict with keys: app, ttp, threat_instance, detection,
        control, telemetry (int counts) and edges (dict of edge_type → count).
        """
        counts: dict[str, Any] = {}
        for table in ("app", "ttp", "threat_instance", "detection", "control",
                      "control_instance", "telemetry"):
            row = self._fetchone(f"SELECT COUNT(*) AS n FROM {table}")
            counts[table] = row["n"] if row else 0
        edge_rows = self._fetchall(
            "SELECT edge_type, COUNT(*) AS n FROM edge GROUP BY edge_type ORDER BY edge_type"
        )
        counts["edges"] = {r["edge_type"]: r["n"] for r in edge_rows}
        return counts

    # ------------------------------------------------------------------
    # Raw SQL access
    # ------------------------------------------------------------------

    def execute_sql(self, sql: str) -> tuple[list[dict[str, Any]], int]:
        """
        Execute arbitrary SQL and return (rows, rowcount).
        - SELECT: rows populated, rowcount = -1 (use len(rows)).
        - INSERT/UPDATE/DELETE: rows empty, rowcount = affected row count.
        Commits automatically for non-SELECT statements.
        """
        cur = self._execute(sql.strip())
        rows = [dict(r) for r in cur.fetchall()]
        if not rows and cur.rowcount >= 0:
            self._conn.commit()
        return rows, cur.rowcount

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def close(self) -> None:
        # PRAGMA optimize is SQLite's recommended pre-close hook: it runs ANALYZE
        # only on tables whose statistics are missing or stale, keeping the query
        # planner's index choices (idx_edge_*_type) sound for the next session at
        # negligible cost. Never let a stats refresh block teardown.
        try:
            self._conn.execute("PRAGMA optimize")
        except sqlite3.Error:
            pass
        self._conn.close()
        _log.info("close db_path=%s", self._db_path)

    def __enter__(self) -> "SCG":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
