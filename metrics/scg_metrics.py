#!/usr/bin/env python3
"""
Security Coverage Graph — empirical metrics harness.

Computes the figures behind the paper's three measurable theses on a given
SCG database (defaults to a fresh in-memory seed):

  T1  Aggregation gap   — technique-level (Navigator/DeTT&CT-style) coverage
                          vs instance-level coverage, and how much the
                          technique view conceals.
  T2  False coverage    — detections mapped to an instance but starved of
                          data because the at-risk app does not PRODUCE the
                          telemetry the detection is POWERED by; and the
                          coverage overstatement that results.
  T3  Unknown state     — single-collector-blind sensitivity: how many
                          instances should move to `unknown` (not silently
                          stay `covered`, nor flip to `gap`) if one telemetry
                          source's collector errors (sync_state=unconfirmed).
  T4  Prescriptive vs  — (app, technique, MITRE-recommended mitigation)
      observed            triples with no implemented control whose name
                          matches the mitigation (list_mitre_recommendation_gaps).
  T5  Impact simulation — read-only `impact_analysis` worked example: the
                          coverage change from decommissioning tel:ds-repl
                          (§5 Scenario 3).

All metrics are derived from graph structure only — no rule execution.
Run:  PYTHONSAFEPATH=1 PYTHONPATH=src python3 metrics/scg_metrics.py [--db PATH] [--json OUT]

With no --db, a fresh in-memory graph is seeded via scg.seed.load_seed, so
the numbers are fully reproducible from the canonical seed estate
(8 apps, 8 techniques, 13 ThreatInstances) the paper's Section 5 reports.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from scg.graph import SCG
from scg.seed import load_seed


# ----------------------------------------------------------------------
# Coverage primitives
#
# Two instance-level views are reported side by side:
#   effective — the SCG status materialized by the library (paper §3.2:
#               preventive control > operable detection > unknown > gap,
#               then any engineer override).
#   mapped    — the same precedence with every DETECTED_BY edge taken at face
#               value and no override: what a technique-mapping workflow
#               claims for each instance. The difference is what the SCG adds.
# ----------------------------------------------------------------------

def _build_indices(g: SCG) -> dict[str, Any]:
    """Pull the edges/nodes we need once and index them in memory."""
    produces: dict[str, set[str]] = {}          # app_id -> {telemetry_id}
    groups: dict[str, dict[Any, list[str]]] = {}  # det_id -> {group: [telemetry_id]}
    detected_by: dict[str, set[str]] = {}       # ti_id -> {detection_id}
    for e in g.list_edges():
        t, f, to = e["edge_type"], e["from_id"], e["to_id"]
        if t == "PRODUCES":
            produces.setdefault(f, set()).add(to)
        elif t == "POWERS":
            attrs = json.loads(e["attrs"]) if e["attrs"] else {}
            grp = attrs.get("requirement_group", 1)
            groups.setdefault(to, {}).setdefault(grp, []).append(f)
        elif t == "DETECTED_BY":
            detected_by.setdefault(f, set()).add(to)

    preventive, _ = g.execute_sql(
        "SELECT DISTINCT e.from_id AS ti_id FROM edge e "
        "JOIN control_instance ci ON ci.id = e.to_id "
        "JOIN control c ON c.id = ci.ctrl_id "
        "WHERE e.edge_type = 'MITIGATED_BY' AND c.type = 'preventive'"
    )
    return {
        "produces": produces,
        "groups": groups,
        "detected_by": detected_by,
        "preventive": {r["ti_id"] for r in preventive},
        "tel_state": {t["id"]: t["sync_state"] for t in g.list_telemetry()},
        "instances": g.list_threat_instances(),
    }


def _detective_state(idx: dict[str, Any], ti: dict[str, Any],
                     blind: frozenset[str] = frozenset()) -> str:
    """operable | unknown | absent — the detective arm alone (§3.2-§3.4).

    Operable: every telemetry in some POWERS requirement group is confirmed and
    produced by the app. Unknown: some group is fully produced but includes
    unconfirmed telemetry. `blind` treats those sources as unconfirmed (a
    failed collector) for the T3 sensitivity analysis.
    """
    produced = idx["produces"].get(ti["app_id"], set())
    candidate = False
    for det in idx["detected_by"].get(ti["id"], set()):
        for group in idx["groups"].get(det, {}).values():
            states = ["unconfirmed" if t in blind else idx["tel_state"].get(t)
                      for t in group]
            if all(t in produced and s == "confirmed" for t, s in zip(group, states)):
                return "operable"
            if all(t in produced for t in group) and "unconfirmed" in states:
                candidate = True
    return "unknown" if candidate else "absent"


def _mapped_status(idx: dict[str, Any], ti: dict[str, Any]) -> str:
    if ti["id"] in idx["preventive"]:
        return "covered"
    return "partial" if idx["detected_by"].get(ti["id"]) else "gap"


def _pct(k: int, n: int) -> float:
    return round(100 * k / n, 1) if n else 0.0


def _counts(statuses: list[str]) -> dict[str, int]:
    return {s: statuses.count(s) for s in ("covered", "partial", "gap", "unknown")}


# ----------------------------------------------------------------------
# T1 — aggregation gap
# ----------------------------------------------------------------------

def metric_t1_aggregation_gap(g: SCG, idx: dict[str, Any]) -> dict[str, Any]:
    instances = idx["instances"]
    n = len(instances)
    mapped_det = {ti["id"]: bool(idx["detected_by"].get(ti["id"])) for ti in instances}
    mapped = {ti["id"]: _mapped_status(idx, ti) for ti in instances}
    effective = {ti["id"]: ti["effective_status"] for ti in instances}
    detective = {ti["id"]: _detective_state(idx, ti) for ti in instances}

    by_ttp: dict[str, list[str]] = {}
    for ti in instances:
        by_ttp.setdefault(ti["ttp_id"], []).append(ti["id"])
    n_tech = len(by_ttp)

    # Technique cell (Navigator-style, optimistic any-asset rollup of mappings)
    tech_green = {ttp: any(mapped_det[i] for i in ids) for ttp, ids in by_ttp.items()}
    tech_covered = {ttp: any(mapped[i] == "covered" for i in ids) for ttp, ids in by_ttp.items()}
    ttp_of = {ti["id"]: ti["ttp_id"] for ti in instances}

    def heterogeneous(state: dict[str, Any]) -> int:
        return sum(1 for ids in by_ttp.values() if len({state[i] for i in ids}) > 1)

    concealed_mapped = sum(1 for i in mapped_det if not mapped_det[i] and tech_green[ttp_of[i]])
    # §3.2 aggregation_gap: detective state ABSENT under a green technique cell;
    # unknown instances are reported separately, never coerced into gaps.
    hidden = sum(1 for i in detective if detective[i] == "absent" and tech_green[ttp_of[i]])
    n_operable = sum(1 for v in detective.values() if v == "operable")
    return {
        "n_instances": n,
        "n_techniques": n_tech,
        "technique_view": {
            "detection_coverage_pct": _pct(sum(tech_green.values()), n_tech),
            "full_coverage_pct": _pct(sum(tech_covered.values()), n_tech),
        },
        "instance_view_mapped": {
            "detection_coverage_pct": _pct(sum(mapped_det.values()), n),
            "full_coverage_pct": _pct(list(mapped.values()).count("covered"), n),
            "status_counts": _counts(list(mapped.values())),
            "concealed_detection_gaps": concealed_mapped,
            "concealed_detection_gap_pct": _pct(concealed_mapped, n),
            "heterogeneous_techniques": heterogeneous(mapped_det),
            "heterogeneous_technique_pct": _pct(heterogeneous(mapped_det), n_tech),
        },
        "instance_view": {
            "operable_detection_pct": _pct(n_operable, n),
            "full_coverage_pct": _pct(list(effective.values()).count("covered"), n),
            "status_counts": _counts(list(effective.values())),
            "aggregation_gap": hidden,
            "aggregation_gap_pct": _pct(hidden, n),
            "detective_unknown": sum(1 for v in detective.values() if v == "unknown"),
            "heterogeneous_techniques": heterogeneous(detective),
            "heterogeneous_technique_pct": _pct(heterogeneous(detective), n_tech),
        },
    }


# ----------------------------------------------------------------------
# T2 — false coverage
# ----------------------------------------------------------------------

def metric_t2_false_coverage(g: SCG, idx: dict[str, Any]) -> dict[str, Any]:
    fc_rows = g.false_coverage_check()
    instances = idx["instances"]
    n = len(instances)

    n_detected_by = sum(len(v) for v in idx["detected_by"].values())
    det_bearing = [ti for ti in instances if idx["detected_by"].get(ti["id"])]
    mappings = sorted({(r["threat_instance_id"], r["detection_id"]) for r in fc_rows})
    fc_instances = {ti_id for ti_id, _ in mappings}

    # detection-bearing instances left with no operable detection at all
    lost_all = [ti["id"] for ti in det_bearing if _detective_state(idx, ti) == "absent"]

    degraded = []
    for ti in instances:
        naive = _mapped_status(idx, ti)
        if naive != ti["effective_status"]:
            degraded.append({
                "ti_id": ti["id"], "app": ti["app_name"], "ttp": ti["mitre_id"],
                "mapped_status": naive, "effective_status": ti["effective_status"],
                "override": ti["override_status"] is not None,
            })

    return {
        "false_coverage_mappings": len(mappings),
        "false_coverage_detail": [
            {"ti": r["threat_instance_id"], "detection": r["detection_name"],
             "telemetry": r["telemetry_name"], "app": r["app_name"]}
            for r in fc_rows
        ],
        "n_detected_by_edges": n_detected_by,
        "false_coverage_edge_pct": _pct(len(mappings), n_detected_by),
        "n_detection_bearing_instances": len(det_bearing),
        "instances_with_false_coverage": len(fc_instances),
        "instances_with_false_coverage_pct": _pct(len(fc_instances), len(det_bearing)),
        "instances_losing_all_detection": lost_all,
        "instances_losing_all_detection_pct": _pct(len(lost_all), len(det_bearing)),
        "status_degradations": degraded,
        "overstated_instances_pct": _pct(len(degraded), n),
    }


# ----------------------------------------------------------------------
# T3 — three-valued (single-collector-blind sensitivity)
# ----------------------------------------------------------------------

def metric_t3_unknown_sensitivity(g: SCG, idx: dict[str, Any]) -> dict[str, Any]:
    instances = idx["instances"]
    base = {ti["id"] for ti in instances if _detective_state(idx, ti) == "operable"}
    per_source = {}
    sensitive_union: set[str] = set()
    for tel_id in idx["tel_state"]:
        blind = frozenset({tel_id})
        # operably detected instances whose detective evidence becomes unknown
        # when this one collector fails
        moved = sorted(ti["id"] for ti in instances
                       if ti["id"] in base and _detective_state(idx, ti, blind) != "operable")
        if moved:
            per_source[tel_id] = moved
            sensitive_union.update(moved)

    redundant = sorted(base - sensitive_union)
    return {
        "n_operably_detected_instances": len(base),
        "per_source_instances_to_unknown": per_source,
        "n_single_source_fragile_instances": len(sensitive_union),
        "single_source_fragile": sorted(sensitive_union),
        "n_telemetry_redundant_instances": len(redundant),
        "telemetry_redundant": redundant,
        "note": ("Each fragile instance's operable detection hangs on ONE telemetry "
                 "source; if its collector fails, its detective evidence is `unknown`, "
                 "not proof of a gap."),
    }


# ----------------------------------------------------------------------
# T4 — prescriptive vs observed (recommendation gap)
# ----------------------------------------------------------------------

def metric_t4_recommendation_gap(g: SCG) -> dict[str, Any]:
    rows = g.list_mitre_recommendation_gaps()
    return {
        "n_recommendation_gaps": len(rows),
        "recommendation_gaps": [
            {"app_id": r["app_id"], "ttp": r["ttp_mitre_id"],
             "missing_mitigation": f'{r["mitigation_mitre_id"]} {r["mitigation_name"]}'}
            for r in rows
        ],
    }


# ----------------------------------------------------------------------
# T5 — impact simulation (read-only deletion)
# ----------------------------------------------------------------------

def metric_t5_impact(g: SCG, target: str = "tel:ds-repl") -> dict[str, Any]:
    res = g.impact_analysis(target)
    return {
        "simulated_node": target,
        "node_label": res["node_label"],
        "coverage_changes": res["coverage_changes"],
        "n_coverage_changes": len(res["coverage_changes"]),
    }


def compute_all(g: SCG) -> dict[str, Any]:
    idx = _build_indices(g)
    return {
        "graph_summary": g.graph_summary(),
        "T1_aggregation_gap": metric_t1_aggregation_gap(g, idx),
        "T2_false_coverage": metric_t2_false_coverage(g, idx),
        "T3_unknown_sensitivity": metric_t3_unknown_sensitivity(g, idx),
        "T4_recommendation_gap": metric_t4_recommendation_gap(g),
        "T5_impact_simulation": metric_t5_impact(g),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=None,
                    help="Path to an existing SCG db. Omit for a fresh seeded :memory: graph.")
    ap.add_argument("--json", default=None, help="Write full results JSON to this path.")
    args = ap.parse_args()

    if args.db:
        g = SCG(args.db)
    else:
        g = SCG(":memory:")
        load_seed(g)

    try:
        results = compute_all(g)
    finally:
        g.close()

    print(json.dumps(results, indent=2))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n[written] {args.json}")


if __name__ == "__main__":
    main()
