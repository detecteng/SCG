"""
Four-state posture (paper §3.2-§3.4): the computed-status precedence, POWERS
requirement groups, the unknown state, and auditable engineer overrides.
"""

import pytest

from scg.graph import SCG


def _estate(g: SCG) -> str:
    """One app and one instance; tests add the defensive arms they need."""
    g.upsert_app("app:x", "X", "o", "prod", "internal")
    g.upsert_ttp("ttp:T1", "T1")
    ti = g.upsert_threat_instance("app:x", "ttp:T1")
    g.add_edge("HAS_TI", "app:x", ti)
    g.add_edge("DESCRIBES", "ttp:T1", ti)
    return ti


def _status(g: SCG, ti: str) -> str:
    return g.get_threat_instance(ti)["effective_status"]


def _detect(g: SCG, ti: str, det: str, powered_by: dict[str, int]) -> None:
    """Map `det` to `ti`, powered by {telemetry_id: requirement_group}."""
    g.upsert_detection(det, det, "rule", "o")
    for tel, grp in powered_by.items():
        if not g.get_telemetry(tel):
            g.upsert_telemetry(tel, tel, "sys", "o")
        g.add_edge("POWERS", tel, det, attrs={"requirement_group": grp})
    g.add_edge("DETECTED_BY", ti, det)


def _control(g: SCG, ti: str, ctrl: str, type: str) -> None:
    g.upsert_control(ctrl, ctrl, type, "o")
    ci = g.upsert_control_instance("app:x", ctrl, "o")
    g.add_edge("IMPLEMENTED_BY", ctrl, ci)
    g.add_edge("MITIGATED_BY", ti, ci)


# ---------------------------------------------------------------------------
# §3.2 precedence
# ---------------------------------------------------------------------------

def test_new_instance_is_gap(g: SCG) -> None:
    assert _status(g, _estate(g)) == "gap"


def test_preventive_control_alone_is_covered(g: SCG) -> None:
    ti = _estate(g)
    _control(g, ti, "ctrl:p", "preventive")
    assert _status(g, ti) == "covered"


def test_non_preventive_control_does_not_cover(g: SCG) -> None:
    ti = _estate(g)
    _control(g, ti, "ctrl:d", "detective")
    assert _status(g, ti) == "gap"


def test_control_type_change_recomputes(g: SCG) -> None:
    ti = _estate(g)
    _control(g, ti, "ctrl:c", "compensating")
    g.upsert_control("ctrl:c", "ctrl:c", "preventive", "o")
    assert _status(g, ti) == "covered"


def test_operable_detection_is_partial(g: SCG) -> None:
    ti = _estate(g)
    _detect(g, ti, "det:a", {"tel:a": 1})
    assert _status(g, ti) == "gap"          # mapped, but the app lacks tel:a
    g.add_edge("PRODUCES", "app:x", "tel:a")
    assert _status(g, ti) == "partial"
    g.remove_edge("PRODUCES", "app:x", "tel:a")
    assert _status(g, ti) == "gap"


def test_preventive_control_outranks_detection(g: SCG) -> None:
    ti = _estate(g)
    _detect(g, ti, "det:a", {"tel:a": 1})
    g.add_edge("PRODUCES", "app:x", "tel:a")
    _control(g, ti, "ctrl:p", "preventive")
    assert _status(g, ti) == "covered"


# ---------------------------------------------------------------------------
# §3.3 requirement groups (Figure 2)
# ---------------------------------------------------------------------------

@pytest.fixture
def fig2(g: SCG) -> tuple[SCG, str]:
    """Detection D: (process AND network) OR edr."""
    ti = _estate(g)
    _detect(g, ti, "det:d", {"tel:proc": 1, "tel:net": 1, "tel:edr": 2})
    return g, ti


def test_group_members_are_conjunctive(fig2: tuple[SCG, str]) -> None:
    g, ti = fig2
    g.add_edge("PRODUCES", "app:x", "tel:proc")
    assert _status(g, ti) == "gap"
    rows = g.false_coverage_check()
    assert {r["detection_id"] for r in rows} == {"det:d"}
    # the rows name what the app lacks, not what it already produces
    assert "tel:proc" not in {r["telemetry_id"] for r in rows}

    g.add_edge("PRODUCES", "app:x", "tel:net")
    assert _status(g, ti) == "partial"
    assert g.false_coverage_check() == []


def test_groups_are_alternatives(fig2: tuple[SCG, str]) -> None:
    g, ti = fig2
    g.add_edge("PRODUCES", "app:x", "tel:edr")
    assert _status(g, ti) == "partial"
    assert g.false_coverage_check() == []


def test_ungrouped_powers_edges_form_one_group(g: SCG) -> None:
    ti = _estate(g)
    g.upsert_detection("det:d", "d", "rule", "o")
    for tel in ("tel:a", "tel:b"):
        g.upsert_telemetry(tel, tel, "sys", "o")
        g.add_edge("POWERS", tel, "det:d")
    g.add_edge("DETECTED_BY", ti, "det:d")
    g.add_edge("PRODUCES", "app:x", "tel:a")
    assert _status(g, ti) == "gap"
    g.add_edge("PRODUCES", "app:x", "tel:b")
    assert _status(g, ti) == "partial"


def test_detection_without_powers_is_false_coverage(g: SCG) -> None:
    ti = _estate(g)
    g.upsert_detection("det:orphan", "orphan", "rule", "o")
    g.add_edge("DETECTED_BY", ti, "det:orphan")
    assert _status(g, ti) == "gap"
    rows = g.false_coverage_check()
    assert [(r["detection_id"], r["telemetry_id"]) for r in rows] == [("det:orphan", None)]


# ---------------------------------------------------------------------------
# §3.4 unknown
# ---------------------------------------------------------------------------

def _unconfirm(g: SCG, tel: str) -> None:
    g.upsert_telemetry(tel, tel, "sys", "o", sync_state="unconfirmed",
                       unconfirmed_reason="collector errored")


def test_unconfirmed_telemetry_yields_unknown_not_gap(g: SCG) -> None:
    ti = _estate(g)
    _detect(g, ti, "det:a", {"tel:a": 1})
    g.add_edge("PRODUCES", "app:x", "tel:a")
    assert _status(g, ti) == "partial"

    _unconfirm(g, "tel:a")
    assert _status(g, ti) == "unknown"
    assert g.false_coverage_check() == []   # could not check != proven absent

    g.upsert_telemetry("tel:a", "tel:a", "sys", "o")
    assert _status(g, ti) == "partial"


def test_preventive_control_stays_covered_when_telemetry_unconfirmed(g: SCG) -> None:
    ti = _estate(g)
    _detect(g, ti, "det:a", {"tel:a": 1})
    g.add_edge("PRODUCES", "app:x", "tel:a")
    _control(g, ti, "ctrl:p", "preventive")
    _unconfirm(g, "tel:a")
    assert _status(g, ti) == "covered"


def test_confirmed_absence_outranks_unknown_only_per_group(g: SCG) -> None:
    """A group that also lacks a confirmed input is a confirmed gap."""
    ti = _estate(g)
    _detect(g, ti, "det:a", {"tel:a": 1, "tel:b": 1})
    g.add_edge("PRODUCES", "app:x", "tel:a")
    _unconfirm(g, "tel:a")
    assert _status(g, ti) == "gap"          # tel:b is confirmed and not produced


def test_unconfirmed_but_not_produced_is_absent(g: SCG) -> None:
    """requirement_state: unknown needs the app to PRODUCE every member."""
    ti = _estate(g)
    _detect(g, ti, "det:a", {"tel:a": 1})
    _unconfirm(g, "tel:a")
    assert _status(g, ti) == "gap"
    rows = g.false_coverage_check()
    assert [(r["detection_id"], r["telemetry_id"]) for r in rows] == [("det:a", "tel:a")]


# ---------------------------------------------------------------------------
# §3.2 engineer override
# ---------------------------------------------------------------------------

def test_override_is_auditable_and_survives_recompute(g: SCG) -> None:
    ti = _estate(g)
    _control(g, ti, "ctrl:p", "preventive")
    g.set_status_override(ti, "partial", engineer="eng@corp.example",
                          reason="control does not cover the procedure")
    row = g.get_threat_instance(ti)
    assert (row["computed_status"], row["effective_status"]) == ("covered", "partial")
    assert row["override_by"] == "eng@corp.example"
    assert row["override_reason"] and row["override_at"]

    g.recompute_coverage()
    g.recompute_coverage(ti)
    assert _status(g, ti) == "partial"

    g.clear_status_override(ti)
    row = g.get_threat_instance(ti)
    assert row["effective_status"] == "covered"
    assert row["override_by"] is None


@pytest.mark.parametrize("status,engineer,reason", [
    ("bogus", "eng", "why"),
    ("partial", "", "why"),
    ("partial", "eng", "  "),
])
def test_override_requires_status_identity_and_reason(
    g: SCG, status: str, engineer: str, reason: str,
) -> None:
    ti = _estate(g)
    with pytest.raises(ValueError):
        g.set_status_override(ti, status, engineer=engineer, reason=reason)
    assert g.get_threat_instance(ti)["override_status"] is None


def test_override_on_missing_instance_raises(g: SCG) -> None:
    with pytest.raises(ValueError, match="no ThreatInstance"):
        g.set_status_override("nope", "gap", engineer="eng", reason="why")


def test_impact_analysis_keeps_overridden_status(seeded: SCG) -> None:
    """AWS:T1530 is overridden to partial; retiring its control changes the
    computed status but not the engineer's effective one."""
    res = seeded.impact_analysis("ctrl:s3-bpa")
    assert "app:aws:ttp:T1530:v1" not in {c["ti_id"] for c in res["coverage_changes"]}


# ---------------------------------------------------------------------------
# Seed estate matches §5
# ---------------------------------------------------------------------------

def test_seed_status_matches_worked_scenarios(seeded: SCG) -> None:
    aws = seeded.get_threat_instance("app:aws:ttp:T1530:v1")
    assert (aws["computed_status"], aws["effective_status"]) == ("covered", "partial")
    assert aws["override_by"] and aws["override_reason"]

    for ti in ("app:gcp:ttp:T1530:v1", "app:ep-cat-b:ttp:T1003.001:v1",
               "app:ep-cat-b:ttp:T1566.002:v1", "app:gcp:ttp:T1078.004:v1"):
        assert seeded.get_threat_instance(ti)["effective_status"] == "gap"
    for ti in ("app:ep-cat-a:ttp:T1566.002:v1", "app:entra:ttp:T1078.004:v1",
               "app:aws:ttp:T1078.004:v1"):
        assert seeded.get_threat_instance(ti)["effective_status"] == "covered"


def test_full_recompute_matches_edge_local_recompute(seeded: SCG) -> None:
    before = {t["id"]: t["effective_status"] for t in seeded.list_threat_instances()}
    seeded.recompute_coverage()
    after = {t["id"]: t["effective_status"] for t in seeded.list_threat_instances()}
    assert before == after
