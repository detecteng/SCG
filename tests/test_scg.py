"""
SCG test suite — 9 tests covering constraints, id formation, and all key queries.
"""

import sqlite3
import pytest
from scg.graph import SCG


# ===========================================================================
# Helpers
# ===========================================================================

def _seed_minimal(g: SCG) -> tuple[str, str, str]:
    """Seed one app, one ttp, one threat_instance. Returns (app_id, ttp_id, ti_id)."""
    g.upsert_app("app:foo", "Foo App", "owner", "prod", "internet")
    g.upsert_ttp("ttp:bar", "Bar TTP")
    ti_id = g.upsert_threat_instance("app:foo", "ttp:bar")
    return "app:foo", "ttp:bar", ti_id


# ===========================================================================
# Test 1 — ThreatInstance id format
# ===========================================================================

def test_threat_instance_id_format(g: SCG) -> None:
    """upsert_threat_instance returns 'app_id:ttp_id:version_id' and the row exists with that PK."""
    g.upsert_app("app:ecom", "E-Commerce", "alice", "prod", "internet")
    g.upsert_ttp("ttp:T1190", "Exploit Public-Facing")

    ti_id = g.upsert_threat_instance("app:ecom", "ttp:T1190")

    assert ti_id == "app:ecom:ttp:T1190:v1"
    row = g._fetchone("SELECT * FROM threat_instance WHERE id=?", (ti_id,))
    assert row is not None
    assert row["app_id"] == "app:ecom"
    assert row["ttp_id"] == "ttp:T1190"
    assert row["version_id"] == "v1"


# ===========================================================================
# Test 2 — Upsert is idempotent (no duplicate row)
# ===========================================================================

def test_upsert_is_idempotent(g: SCG) -> None:
    """Calling upsert_threat_instance twice with same (app, ttp) leaves exactly one row."""
    _seed_minimal(g)

    # Second upsert with updated fields — should not raise or duplicate.
    g.upsert_threat_instance("app:foo", "ttp:bar", priority=3, likelihood=0.5)

    rows = g._fetchall("SELECT * FROM threat_instance WHERE app_id='app:foo'")
    assert len(rows) == 1
    assert rows[0]["priority"] == 3
    assert rows[0]["likelihood"] == pytest.approx(0.5)


# ===========================================================================
# Test 3 — Detection gaps returns only undetected ThreatInstances
# ===========================================================================

def test_detection_gap_detection(g: SCG) -> None:
    """list_detection_gaps returns TIs with no DETECTED_BY edge."""
    g.upsert_app("app:a", "A", "o", "prod", "internet")
    g.upsert_ttp("ttp:t1", "T1")
    g.upsert_ttp("ttp:t2", "T2")
    g.upsert_detection("det:d1", "Det1", "rule", "o", confidence=0.8)

    ti1 = g.upsert_threat_instance("app:a", "ttp:t1")
    ti2 = g.upsert_threat_instance("app:a", "ttp:t2")

    # Only ti1 gets a detection.
    g.add_edge("DETECTED_BY", ti1, "det:d1")

    gaps = g.list_detection_gaps()
    gap_ids = [r["id"] for r in gaps]

    assert ti2 in gap_ids
    assert ti1 not in gap_ids


# ===========================================================================
# Test 4 — Coverage materializes on DETECTED_BY edge add
# ===========================================================================

def test_coverage_materialization_on_edge_add(g: SCG) -> None:
    """Adding DETECTED_BY edge sets has_detection=1 and effective_confidence."""
    app_id, ttp_id, ti_id = _seed_minimal(g)
    g.upsert_detection("det:d1", "Det1", "rule", "owner", confidence=0.85)

    row_before = g._fetchone("SELECT * FROM threat_instance WHERE id=?", (ti_id,))
    assert row_before["has_detection"] == 0

    g.add_edge("DETECTED_BY", ti_id, "det:d1")

    row_after = g._fetchone("SELECT * FROM threat_instance WHERE id=?", (ti_id,))
    assert row_after["has_detection"] == 1
    assert row_after["effective_confidence"] == pytest.approx(0.85)
    assert row_after["last_computed_at"] is not None


# ===========================================================================
# Test 5 — False coverage check
# ===========================================================================

def test_false_coverage_check(g: SCG) -> None:
    """
    Detection powered by telemetry not produced by the TI's own app
    appears in false_coverage_check().
    """
    g.upsert_app("app:a", "App A", "o", "prod", "internet")
    g.upsert_app("app:b", "App B", "o", "prod", "internet")
    g.upsert_ttp("ttp:t1", "T1")
    g.upsert_telemetry("tel:waf", "WAF Logs", "WAF", "o", retention_days=90)
    g.upsert_detection("det:d1", "SQLi Det", "rule", "o", confidence=0.9)

    ti_b = g.upsert_threat_instance("app:b", "ttp:t1")

    # App A produces the telemetry, App B does NOT.
    g.add_edge("PRODUCES", "app:a", "tel:waf")
    g.add_edge("POWERS",   "tel:waf", "det:d1")
    # App B's TI is "detected" by det:d1 — but without the telemetry.
    g.add_edge("DETECTED_BY", ti_b, "det:d1")

    results = g.false_coverage_check()
    assert len(results) == 1
    r = results[0]
    assert r["threat_instance_id"] == ti_b
    assert r["app_id"] == "app:b"
    assert r["detection_id"] == "det:d1"
    assert r["telemetry_id"] == "tel:waf"


# ===========================================================================
# Test 6 — get_coverage_for_app ordering
# ===========================================================================

def test_get_coverage_for_app_ordering(g: SCG) -> None:
    """get_coverage_for_app returns rows ordered by priority descending."""
    g.upsert_app("app:x", "X", "o", "prod", "internet")
    for ttp_id, prio in [("ttp:low", 1), ("ttp:mid", 3), ("ttp:high", 5)]:
        g.upsert_ttp(ttp_id, ttp_id)
        g.upsert_threat_instance("app:x", ttp_id, priority=prio)

    rows = g.get_coverage_for_app("app:x")
    priorities = [r["priority"] for r in rows]
    assert priorities == [5, 3, 1]


# ===========================================================================
# Test 7 — telemetry_powering_detection
# ===========================================================================

def test_telemetry_powering_detection(g: SCG) -> None:
    """Returns all telemetry nodes linked to a detection via POWERS."""
    g.upsert_detection("det:d1", "Det1", "ML", "o")
    g.upsert_telemetry("tel:t1", "T1", "sys1", "o")
    g.upsert_telemetry("tel:t2", "T2", "sys2", "o")
    g.upsert_telemetry("tel:t3", "T3", "sys3", "o")

    g.add_edge("POWERS", "tel:t1", "det:d1")
    g.add_edge("POWERS", "tel:t2", "det:d1")
    # tel:t3 is NOT wired to det:d1

    result_ids = {r["id"] for r in g.telemetry_powering_detection("det:d1")}
    assert result_ids == {"tel:t1", "tel:t2"}
    assert "tel:t3" not in result_ids


# ===========================================================================
# Test 8 — CHECK constraint on app.env
# ===========================================================================

def test_check_constraint_env(g: SCG) -> None:
    """Inserting an app with an invalid env value raises IntegrityError."""
    with pytest.raises(sqlite3.IntegrityError):
        g.upsert_app("app:bad", "Bad App", "o", "staging", "internet")


# ===========================================================================
# Test 9 — recompute_coverage bulk refresh
# ===========================================================================

def test_recompute_coverage_bulk(g: SCG) -> None:
    """
    Manually zero out coverage fields, then recompute_coverage() restores them.
    """
    app_id, ttp_id, ti_id = _seed_minimal(g)
    g.upsert_detection("det:d1", "D1", "rule", "o", confidence=0.7)
    g.upsert_control("ctrl:c1", "C1", "preventive", "o")
    g.add_edge("DETECTED_BY",  ti_id, "det:d1")
    g.add_edge("MITIGATED_BY", ti_id, "ctrl:c1")

    # Verify materialized correctly after edge adds.
    row = g._fetchone("SELECT * FROM threat_instance WHERE id=?", (ti_id,))
    assert row["has_detection"] == 1
    assert row["has_control"] == 1

    # Manually corrupt the materialized fields.
    g._execute(
        "UPDATE threat_instance SET has_detection=0, has_control=0, effective_confidence=NULL WHERE id=?",
        (ti_id,),
    )
    g._conn.commit()

    row_corrupt = g._fetchone("SELECT * FROM threat_instance WHERE id=?", (ti_id,))
    assert row_corrupt["has_detection"] == 0

    # Bulk recompute restores values.
    g.recompute_coverage()

    row_fixed = g._fetchone("SELECT * FROM threat_instance WHERE id=?", (ti_id,))
    assert row_fixed["has_detection"] == 1
    assert row_fixed["has_control"] == 1
    assert row_fixed["effective_confidence"] == pytest.approx(0.7)


# ===========================================================================
# Test 10 — version_id distinguishes successive assessments
# ===========================================================================

def test_version_id_distinguishes_assessments(g: SCG) -> None:
    """
    Two upserts with the same (app, ttp) but different version_id values
    produce two coexisting threat_instance rows with distinct canonical ids.
    """
    g.upsert_app("app:portal", "Portal", "o", "prod", "internet")
    g.upsert_ttp("ttp:T1190", "Exploit Public-Facing")

    ti_v1 = g.upsert_threat_instance("app:portal", "ttp:T1190", version_id="v1", priority=2)
    ti_v2 = g.upsert_threat_instance("app:portal", "ttp:T1190", version_id="v2", priority=4)

    assert ti_v1 != ti_v2
    assert ti_v1 == "app:portal:ttp:T1190:v1"
    assert ti_v2 == "app:portal:ttp:T1190:v2"

    rows = g._fetchall(
        "SELECT id, version_id, priority FROM threat_instance "
        "WHERE app_id='app:portal' AND ttp_id='ttp:T1190' "
        "ORDER BY version_id"
    )
    assert len(rows) == 2
    assert rows[0]["version_id"] == "v1"
    assert rows[0]["priority"] == 2
    assert rows[1]["version_id"] == "v2"
    assert rows[1]["priority"] == 4


# ===========================================================================
# Test 11 — TI id derivation is deterministic
# ===========================================================================

def test_ti_id_derivation_is_deterministic(g: SCG) -> None:
    """
    Repeated upsert with the same (app, ttp, version) tuple returns the same id
    and produces exactly one row.
    """
    g.upsert_app("app:foo", "Foo", "o", "prod", "internet")
    g.upsert_ttp("ttp:bar", "Bar")

    first = g.upsert_threat_instance("app:foo", "ttp:bar", version_id="v1")
    second = g.upsert_threat_instance("app:foo", "ttp:bar", version_id="v1")
    third = g.upsert_threat_instance("app:foo", "ttp:bar", version_id="v1", priority=3)

    assert first == second == third == "app:foo:ttp:bar:v1"
    rows = g._fetchall(
        "SELECT id FROM threat_instance WHERE app_id='app:foo' AND ttp_id='ttp:bar'"
    )
    assert len(rows) == 1


# ===========================================================================
# Test 12 — default version_id is "v1"
# ===========================================================================

def test_default_version_id_is_v1(g: SCG) -> None:
    """
    Omitting version_id produces a TI with version_id == "v1" and id suffix ":v1".
    """
    g.upsert_app("app:foo", "Foo", "o", "prod", "internet")
    g.upsert_ttp("ttp:bar", "Bar")

    ti_id = g.upsert_threat_instance("app:foo", "ttp:bar")

    assert ti_id.endswith(":v1")
    row = g._fetchone("SELECT version_id FROM threat_instance WHERE id=?", (ti_id,))
    assert row is not None
    assert row["version_id"] == "v1"


# ===========================================================================
# Test bonus — seeded dataset coverage matrix
# ===========================================================================

def test_seeded_coverage_matrix(seeded: SCG) -> None:
    """
    After loading seed data, verify the three coverage states are present
    and false_coverage_check() surfaces the expected false-coverage TIs.

    Coverage states:
      Entra:T1078.004 → covered (impossible-travel + Conditional Access)
      AWS:T1580       → partial (CloudTrail discovery detection, no control)
      GCP:T1078.004   → gap     (no detection, no control)

    False coverage (detection powered by telemetry the app does not produce):
      AWS:T1530          → S3 Mass Download powered by CloudTrail S3 data events (not enabled)
      EP-Cat-B:T1003.001 → LSASS/Sysmon rule mapped to a legacy host running no Sysmon
      GCP:T1530          → GCS egress powered by GCP Data Access logs (off by default)
    """
    covered = seeded.get_threat_instance("app:entra:ttp:T1078.004:v1")
    assert (covered["has_detection"], covered["has_control"]) == (1, 1)

    partial = seeded.get_threat_instance("app:aws:ttp:T1580:v1")
    assert (partial["has_detection"], partial["has_control"]) == (1, 0)

    gap = seeded.get_threat_instance("app:gcp:ttp:T1078.004:v1")
    assert (gap["has_detection"], gap["has_control"]) == (0, 0)

    assert covered["effective_status"] == "covered"
    assert partial["effective_status"] == "partial"
    assert gap["effective_status"] == "gap"

    fc = seeded.false_coverage_check()
    fc_ti_ids = {r["threat_instance_id"] for r in fc}
    assert fc_ti_ids == {
        "app:aws:ttp:T1530:v1",
        "app:ep-cat-b:ttp:T1003.001:v1",
        "app:gcp:ttp:T1530:v1",
    }


# ===========================================================================
# Test — false_coverage_check app_id filter (scoping for large estates)
# ===========================================================================

def test_false_coverage_app_filter(seeded: SCG) -> None:
    """The optional app_id filter scopes the scan; unfiltered = union of apps."""
    all_rows = seeded.false_coverage_check()
    assert {r["threat_instance_id"] for r in all_rows} == {
        "app:aws:ttp:T1530:v1",
        "app:ep-cat-b:ttp:T1003.001:v1",
        "app:gcp:ttp:T1530:v1",
    }

    aws_only = seeded.false_coverage_check(app_id="app:aws")
    assert [r["threat_instance_id"] for r in aws_only] == ["app:aws:ttp:T1530:v1"]

    epb_only = seeded.false_coverage_check(app_id="app:ep-cat-b")
    assert [r["threat_instance_id"] for r in epb_only] == ["app:ep-cat-b:ttp:T1003.001:v1"]

    # An app with no false coverage returns nothing.
    assert seeded.false_coverage_check(app_id="app:entra") == []


# ===========================================================================
# Test — impact_analysis is read-only and reports the right coverage cliff
# ===========================================================================

def test_impact_analysis_detection_is_readonly(seeded: SCG) -> None:
    """
    Retiring the Sysmon LSASS rule removes two DETECTED_BY mappings (fan-out 2)
    but changes no effective status: EP-Cat-A:T1003.001 is covered by
    Credential Guard (and keeps its EDR path), and EP-Cat-B:T1003.001 is
    already a gap because that mapping is false coverage (§3.3).
    The simulation must not mutate the graph.
    """
    res = seeded.impact_analysis("det:sysmon-lsass")
    assert res["node_type"] == "Detection"
    assert res["coverage_changes"] == []

    retired = [e for e in res["edges_to_delete"] if e["edge_type"] == "DETECTED_BY"]
    assert {e["from_id"] for e in retired} == {
        "app:ep-cat-a:ttp:T1003.001:v1", "app:ep-cat-b:ttp:T1003.001:v1",
    }

    # read-only: materialized coverage is untouched after the simulation
    assert seeded.get_threat_instance("app:ep-cat-a:ttp:T1003.001:v1")["has_detection"] == 1
    assert seeded.get_threat_instance("app:ep-cat-b:ttp:T1003.001:v1")["has_detection"] == 1


def test_impact_analysis_telemetry_decommission(seeded: SCG) -> None:
    """
    Decommissioning a telemetry source degrades the instances whose only
    operable detection it powers (§3.6): without directory-replication
    monitoring, AD:T1003.006 drops from partial to gap.
    """
    res = seeded.impact_analysis("tel:ds-repl")
    changes = {c["ti_id"]: (c["current_status"], c["new_status"])
               for c in res["coverage_changes"]}
    assert changes == {"app:ad:ttp:T1003.006:v1": ("partial", "gap")}
    assert seeded.get_threat_instance("app:ad:ttp:T1003.006:v1")["effective_status"] == "partial"


def test_impact_analysis_app_cascades_to_cross_app_controls(seeded: SCG) -> None:
    """
    Deleting the WAF app cascades its ControlInstance, which is implemented on
    the WAF (fronting infrastructure) but mitigates the Web App's T1190 exploit
    instance — degrading it from covered -> partial.
    """
    res = seeded.impact_analysis("app:waf")
    changes = {c["ti_id"]: (c["current_status"], c["new_status"])
               for c in res["coverage_changes"]}
    assert changes == {
        "app:webapp:ttp:T1190:v1": ("covered", "partial"),
    }


# ===========================================================================
# Test — delete_node recomputes exactly the surviving affected TIs
# ===========================================================================

def test_delete_detection_scoped_recompute(seeded: SCG) -> None:
    """
    Deleting the Sysmon LSASS rule clears has_detection on EP-Cat-B:T1003.001
    (its only detection) but leaves EP-Cat-A:T1003.001 detected (EDR remains).
    """
    assert seeded.delete_node("det:sysmon-lsass") is True

    assert seeded.get_threat_instance("app:ep-cat-b:ttp:T1003.001:v1")["has_detection"] == 0
    assert seeded.get_threat_instance("app:ep-cat-a:ttp:T1003.001:v1")["has_detection"] == 1
    assert seeded.get_detection("det:sysmon-lsass") is None


def test_delete_app_recomputes_cross_app_control_dependents(seeded: SCG) -> None:
    """
    Deleting the WAF app removes its ControlInstance; the surviving Web App
    T1190 instance it mitigated loses has_control but keeps has_detection.
    """
    assert seeded.delete_node("app:waf") is True

    webapp = seeded.get_threat_instance("app:webapp:ttp:T1190:v1")
    assert (webapp["has_control"], webapp["has_detection"]) == (0, 1)
    assert seeded.get_app("app:waf") is None
