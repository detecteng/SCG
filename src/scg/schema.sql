PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS app (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    owner           TEXT NOT NULL,
    env             TEXT NOT NULL CHECK(env IN ('prod','dev')),
    exposure        TEXT NOT NULL CHECK(exposure IN ('internet','internal')),
    last_synced_at  TEXT,
    synced_by       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ttp (
    id              TEXT PRIMARY KEY,
    mitre_id        TEXT,
    name            TEXT NOT NULL,
    description     TEXT,
    -- ATT&CK overlay (v6)
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    revoked_by_id   TEXT,
    platforms       TEXT,                    -- JSON array, informational
    -- Provenance: source='mitre-attack' marks mirror-derived rows; NULL = seed/human
    source          TEXT,
    source_version  TEXT,
    external_url    TEXT,
    last_synced_at  TEXT,
    local_notes     TEXT,                    -- human-authored, NEVER touched by the loader
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ATT&CK overlay node tables. Every row carries provenance + local_notes
-- so the refdata loader can re-sync MITRE content without clobbering
-- human edits stored in `local_notes`.

CREATE TABLE IF NOT EXISTS tactic (
    id              TEXT PRIMARY KEY,        -- "tac:TA0001"
    mitre_id        TEXT NOT NULL,           -- "TA0001"
    name            TEXT NOT NULL,
    short_name      TEXT NOT NULL,           -- e.g. "initial-access"
    description     TEXT,
    source          TEXT,
    source_version  TEXT,
    external_url    TEXT,
    last_synced_at  TEXT,
    local_notes     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS mitigation (
    id              TEXT PRIMARY KEY,        -- "mit:M1032"
    mitre_id        TEXT NOT NULL,           -- "M1032"
    name            TEXT NOT NULL,
    description     TEXT,
    source          TEXT,
    source_version  TEXT,
    external_url    TEXT,
    last_synced_at  TEXT,
    local_notes     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS data_source (
    id              TEXT PRIMARY KEY,        -- "ds:DS0017"
    mitre_id        TEXT NOT NULL,           -- "DS0017"
    name            TEXT NOT NULL,
    description     TEXT,
    source          TEXT,
    source_version  TEXT,
    external_url    TEXT,
    last_synced_at  TEXT,
    local_notes     TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS data_component (
    id              TEXT PRIMARY KEY,        -- "dc:DS0017.command-execution"
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
);
CREATE INDEX IF NOT EXISTS idx_data_component_ds ON data_component(data_source_id);

-- Canonical (App, TTP, version) tuple. id = "app_id:ttp_id:version_id"
CREATE TABLE IF NOT EXISTS threat_instance (
    id                   TEXT PRIMARY KEY,
    app_id               TEXT NOT NULL REFERENCES app(id),
    ttp_id               TEXT NOT NULL REFERENCES ttp(id),
    version_id           TEXT NOT NULL DEFAULT 'v1',
    likelihood           REAL CHECK(likelihood BETWEEN 0 AND 1),
    impact               REAL CHECK(impact BETWEEN 0 AND 1),
    priority             INTEGER CHECK(priority BETWEEN 1 AND 5),
    last_reviewed        TEXT,
    -- Materialized coverage (recomputed on each coverage-affecting edge write)
    has_detection        INTEGER NOT NULL DEFAULT 0,
    has_control          INTEGER NOT NULL DEFAULT 0,
    effective_confidence REAL,
    -- Four-state posture (paper §3.2). computed_status follows the defensive
    -- precedence; an engineer override (status + identity + reason + time)
    -- replaces it; effective_status = override_status ?? computed_status.
    computed_status      TEXT CHECK(computed_status IN ('covered','partial','gap','unknown')),
    effective_status     TEXT CHECK(effective_status IN ('covered','partial','gap','unknown')),
    override_status      TEXT CHECK(override_status IN ('covered','partial','gap','unknown')),
    override_by          TEXT,
    override_reason      TEXT,
    override_at          TEXT,
    last_computed_at     TEXT,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at           TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, ttp_id, version_id)
);

CREATE INDEX IF NOT EXISTS idx_ti_priority ON threat_instance(priority);
CREATE INDEX IF NOT EXISTS idx_ti_app      ON threat_instance(app_id);
-- idx_ti_ttp lets the App/TTP delete cascade (app_id=? OR ttp_id=?) resolve via
-- a MULTI-INDEX OR instead of scanning threat_instance.
CREATE INDEX IF NOT EXISTS idx_ti_ttp      ON threat_instance(ttp_id);

CREATE TABLE IF NOT EXISTS detection (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    type              TEXT NOT NULL CHECK(type IN ('rule','EDR','ML','DLP')),
    owner             TEXT NOT NULL,
    confidence        REAL CHECK(confidence BETWEEN 0 AND 1),
    telemetry_sources TEXT,   -- JSON array; informational only (POWERS edges are authoritative)
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_detection_confidence ON detection(confidence);

CREATE TABLE IF NOT EXISTS control (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    type          TEXT NOT NULL CHECK(type IN ('preventive','detective','compensating')),
    owner         TEXT NOT NULL,
    effectiveness REAL CHECK(effectiveness BETWEEN 0 AND 1),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Concrete (App, Control) pair — the specific implementation of a control in the environment.
-- id = "app_id:ctrl_id"  e.g. "app:duo:ctrl:mfa"
CREATE TABLE IF NOT EXISTS control_instance (
    id              TEXT PRIMARY KEY,
    app_id          TEXT NOT NULL REFERENCES app(id),
    ctrl_id         TEXT NOT NULL REFERENCES control(id),
    owner           TEXT NOT NULL,
    effectiveness   REAL CHECK(effectiveness BETWEEN 0 AND 1),
    notes           TEXT,
    last_synced_at  TEXT,
    synced_by       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_id, ctrl_id)
);

-- UNIQUE(app_id, ctrl_id) already indexes app_id as a prefix; idx_ci_ctrl adds
-- the ctrl_id side so the App/Control delete cascade and list_apps_implementing
-- resolve by index instead of scanning control_instance.
CREATE INDEX IF NOT EXISTS idx_ci_ctrl ON control_instance(ctrl_id);

CREATE TABLE IF NOT EXISTS telemetry (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL,
    source_system      TEXT NOT NULL,
    owner              TEXT NOT NULL,
    retention_days     INTEGER,
    last_verified      TEXT,
    last_synced_at     TEXT,
    synced_by          TEXT,
    sync_state         TEXT NOT NULL DEFAULT 'confirmed'
                       CHECK(sync_state IN ('confirmed','unconfirmed')),
    unconfirmed_reason TEXT,        -- why it's gray, e.g. "cloudwatch sync errored 2026-06-21T14:04Z"
    created_at         TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

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
);

CREATE INDEX IF NOT EXISTS idx_sync_session_connector ON sync_session(connector_name, started_at);

CREATE INDEX IF NOT EXISTS idx_telemetry_last_verified ON telemetry(last_verified);

-- All directed relationships in one table.
-- edge_type values map 1-to-1 to the schema relationships:
--   (App)-[:HAS_TI]->(ThreatInstance)
--   (TTP)-[:DESCRIBES]->(ThreatInstance)
--   (ThreatInstance)-[:DETECTED_BY]->(Detection)
--   (ThreatInstance)-[:MITIGATED_BY]->(ControlInstance)
--   (App)-[:PRODUCES]->(Telemetry)
--   (Telemetry)-[:POWERS]->(Detection)   attrs.requirement_group (default 1):
--        telemetry in one group is conjunctive; separate groups are alternatives
--   (App)-[:HAS_CI]->(ControlInstance)
--   (Control)-[:IMPLEMENTED_BY]->(ControlInstance)
CREATE TABLE IF NOT EXISTS edge (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    edge_type  TEXT NOT NULL CHECK(edge_type IN (
                   'HAS_TI','DESCRIBES','DETECTED_BY','MITIGATED_BY','PRODUCES','POWERS',
                   'HAS_CI','IMPLEMENTED_BY',
                   -- ATT&CK overlay edges (v6). MITIGATED_BY_REF is "what MITRE
                   -- recommends" — distinct from MITIGATED_BY which links to a
                   -- concrete control_instance ("what we actually do").
                   'ACHIEVES','SUBTECHNIQUE_OF','MITIGATED_BY_REF','DETECTED_VIA','REVOKED_BY')),
    from_id    TEXT NOT NULL,
    to_id      TEXT NOT NULL,
    attrs      TEXT,                    -- JSON; carries {source,source_version} for refdata-promoted edges
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(edge_type, from_id, to_id)
);

CREATE INDEX IF NOT EXISTS idx_edge_from  ON edge(from_id);
CREATE INDEX IF NOT EXISTS idx_edge_to    ON edge(to_id);
CREATE INDEX IF NOT EXISTS idx_edge_type  ON edge(edge_type);
-- Composite (endpoint, type) indexes for the coverage joins. The UNIQUE
-- autoindex is (edge_type, from_id, to_id), so a join on (to_id=?, edge_type=?)
-- — e.g. Telemetry-POWERS-Detection — cannot seek to_id (it is the 3rd column)
-- and degrades to a per-row scan, making false_coverage_check O(n^2). These let
-- both directions seek precisely: (from_id,type) for DETECTED_BY/MITIGATED_BY,
-- (to_id,type) for POWERS and reverse coverage lookups.
CREATE INDEX IF NOT EXISTS idx_edge_from_type ON edge(from_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_edge_to_type   ON edge(to_id, edge_type);

-- Schema version tracking for future migrations.
CREATE TABLE IF NOT EXISTS _meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO _meta(key, value) VALUES ('schema_version', '8');
