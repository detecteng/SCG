"""Tests for `list_mitre_recommendation_gaps` (graph) and
`scg gaps mitre-recommendations` (CLI).

These tests stand up a v6 SCG with two apps + a promoted T1566.001
overlay (via direct upserts; no refdata dep) and verify:

  * gaps are reported when no control_instance matches a recommended
    mitigation,
  * a control whose name contains the mitigation name removes the gap,
  * the substring match is symmetric (mitigation-in-control AND
    control-in-mitigation both count as a match),
  * `--app` filters to one application,
  * CLI prints non-empty output for the gaps case.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scg.graph import SCG


def _seed_overlay(g: SCG) -> None:
    """Two apps; one bound to T1566.001; T1566.001 has MITIGATED_BY_REF to
    two mitigations (User Training, Antivirus)."""
    g.upsert_app("app:portal", "Portal", "alice", "prod", "internet")
    g.upsert_app("app:warehouse", "Warehouse", "bob", "prod", "internal")
    g.upsert_tactic("tac:TA0001", "TA0001", "Initial Access", "initial-access",
                    source="mitre-attack", source_version="15.1")
    g.upsert_ttp("ttp:T1566.001", "Spearphishing Attachment",
                 mitre_id="T1566.001", is_subtechnique=True,
                 source="mitre-attack", source_version="15.1")
    g.upsert_mitigation("mit:M1017", "M1017", "User Training",
                        source="mitre-attack", source_version="15.1")
    g.upsert_mitigation("mit:M1049", "M1049", "Antivirus/Antimalware",
                        source="mitre-attack", source_version="15.1")
    attrs = {"source": "mitre-attack", "source_version": "15.1"}
    g.add_edge("MITIGATED_BY_REF", "ttp:T1566.001", "mit:M1017", attrs=attrs)
    g.add_edge("MITIGATED_BY_REF", "ttp:T1566.001", "mit:M1049", attrs=attrs)
    g.upsert_threat_instance("app:portal", "ttp:T1566.001", priority=4)
    g.upsert_threat_instance("app:warehouse", "ttp:T1566.001", priority=2)


# ---------------------------------------------------------------- graph API


def test_gap_reported_when_no_control_matches(g: SCG) -> None:
    _seed_overlay(g)
    rows = g.list_mitre_recommendation_gaps()
    # 2 apps * 2 recommended mitigations = 4 gap rows
    assert len(rows) == 4
    mitre_ids = {(r["app_id"], r["mitigation_mitre_id"]) for r in rows}
    assert ("app:portal", "M1017") in mitre_ids
    assert ("app:portal", "M1049") in mitre_ids
    assert ("app:warehouse", "M1017") in mitre_ids
    assert ("app:warehouse", "M1049") in mitre_ids


def test_matching_control_removes_the_gap(g: SCG) -> None:
    _seed_overlay(g)
    # Portal has a control that semantically covers User Training.
    g.upsert_control("ctrl:training", "Annual User Training", "preventive", "alice")
    g.upsert_control_instance("app:portal", "ctrl:training", "alice")

    rows = g.list_mitre_recommendation_gaps()
    portal = [r for r in rows if r["app_id"] == "app:portal"]
    portal_mits = {r["mitigation_mitre_id"] for r in portal}
    # Portal still has the Antivirus gap; User Training is closed.
    assert portal_mits == {"M1049"}
    # Warehouse, unaffected, still shows both gaps.
    warehouse = [r for r in rows if r["app_id"] == "app:warehouse"]
    assert {r["mitigation_mitre_id"] for r in warehouse} == {"M1017", "M1049"}


def test_match_is_symmetric_either_direction(g: SCG) -> None:
    """Substring match works in both directions so naming variance doesn't
    create false gaps (issue #9 — the crude v1 mapping)."""
    _seed_overlay(g)
    # Control name SHORTER than the mitigation name — control "Training" is
    # a substring of "User Training". A naive one-directional match would
    # miss this and report a false gap.
    g.upsert_control("ctrl:training", "Training", "preventive", "alice")
    g.upsert_control_instance("app:portal", "ctrl:training", "alice")

    rows = g.list_mitre_recommendation_gaps(app_id="app:portal")
    assert all(r["mitigation_mitre_id"] != "M1017" for r in rows)


def test_app_filter(g: SCG) -> None:
    _seed_overlay(g)
    rows = g.list_mitre_recommendation_gaps(app_id="app:portal")
    assert {r["app_id"] for r in rows} == {"app:portal"}
    assert len(rows) == 2


# ---------------------------------------------------------------- CLI


def test_cli_prints_gap_rows(g: SCG, tmp_path: Path) -> None:
    """End-to-end smoke: `scg gaps mitre-recommendations` returns a
    non-empty table against the seeded overlay."""
    db_path = tmp_path / "scg.db"
    g_real = SCG(str(db_path))
    try:
        _seed_overlay(g_real)
    finally:
        g_real.close()

    # JSON format makes the assertion robust to table-formatting drift.
    proc = subprocess.run(
        [sys.executable, "-m", "scg.cli", "gaps", "mitre-recommendations",
         "--format", "json", "--db", str(db_path)],
        capture_output=True, text=True, env={"PYTHONSAFEPATH": "1", "PATH": ""},
    )
    assert proc.returncode == 0, proc.stderr
    assert "MITRE recommendation gaps" in proc.stdout
    assert "M1017" in proc.stdout
    assert "4 gap(s)" in proc.stdout


def test_cli_reports_clean_when_no_gaps(g: SCG, tmp_path: Path) -> None:
    """No threat_instance + no edges → no gaps to report."""
    db_path = tmp_path / "scg.db"
    g_real = SCG(str(db_path))
    try:
        g_real.upsert_app("app:empty", "Empty", "alice", "prod", "internal")
    finally:
        g_real.close()

    proc = subprocess.run(
        [sys.executable, "-m", "scg.cli", "gaps", "mitre-recommendations",
         "--db", str(db_path)],
        capture_output=True, text=True, env={"PYTHONSAFEPATH": "1", "PATH": ""},
    )
    assert proc.returncode == 0, proc.stderr
    assert "every MITRE-recommended mitigation has a matching control_instance" in proc.stdout
