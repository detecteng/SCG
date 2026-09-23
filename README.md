# The Security Coverage Graph

Code and seed data for **The Security Coverage Graph: Instance-Grounded,
Operability-Aware Modeling of Defensive Posture** ([paper/scg.pdf](paper/scg.pdf)).

The SCG models coverage at the (asset, technique) `ThreatInstance` level, binds
each instance to the asset's actual telemetry, deployed detections and
implemented controls, and computes false coverage as a graph anti-join. The
implementation is a zero-dependency Python package (`scg`) over SQLite.

Each instance materializes a four-state status (§3.2–§3.4), recomputed
edge-locally on every write:

```
computed_status   preventive ControlInstance                    -> covered
                  else operable detection                       -> partial
                  else detection only unconfirmed telemetry
                       could satisfy                            -> unknown
                  else                                          -> gap
effective_status  engineer override (status, identity, reason,
                  timestamp) if set, else computed_status
```

A detection is operable when every telemetry in one of its POWERS requirement
groups (`attrs.requirement_group`, default 1) is confirmed and produced by the
instance's app. A group the app fully produces but that includes unconfirmed
telemetry makes the detection unknown rather than false coverage.

```
src/scg/        graph library, schema, seed estate, CLI
metrics/        scg_metrics.py (§5), scaling_bench.py (§6.3),
                pre_fix_false_coverage.py (§6.2), plus their JSON outputs
tests/          77 tests, including the sublinear-scaling regression tests (§6.3)
paper/          scg.pdf and LaTeX source
```

## Reproduce

Requires Python ≥ 3.11.

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                                    # 77 tests
.venv/bin/python metrics/scg_metrics.py --json metrics/results.json
.venv/bin/python metrics/scaling_bench.py --json metrics/scaling_results.json
.venv/bin/python metrics/pre_fix_false_coverage.py --json metrics/pre_fix_false_coverage.json
```

`scg_metrics.py` seeds a fresh in-memory graph from `scg.seed.load_seed`, so
§5 figures are deterministic. Pass `--db PATH` to run the same harness on a
real `scg.db`.

## Paper figures → output

Keys are in `metrics/results.json`.

| Paper | Figure | Key |
|---|---|---|
| §5 estate | 8 apps, 8 techniques, 13 instances, 12 DETECTED_BY edges | `graph_summary` |
| Table 4 (T2) | 3 false-coverage mappings, 25% of DETECTED_BY, 27.3% of detection-bearing instances | `T2_false_coverage` |
| Scenario 1 | AWS · T1530 computes covered, overridden to partial; GCP · T1530 gap | `T2_false_coverage.status_degradations` |
| Scenario 1 (T4) | 17 (app, technique, missing-mitigation) triples | `T4_recommendation_gap` |
| Scenario 2 (T1) | technique view 100% detected / 75% fully covered | `T1_aggregation_gap.technique_view` |
| Scenario 2 (T1) | 61.5% / 46.2%, 6 covered / 3 partial / 4 gap, 38.5% aggregation gap, 37.5% heterogeneous | `T1_aggregation_gap.instance_view` |
| Scenario 2 (T3) | 7 of 8 operably detected instances single-source fragile | `T3_unknown_sensitivity` |
| Scenario 3 (T5) | decommissioning `tel:ds-repl`: AD · T1003.006 partial → gap | `T5_impact_simulation` |

`T1_aggregation_gap.instance_view_mapped` additionally reports what a
technique-mapping workflow would claim, counting every DETECTED_BY edge at face
value with no override (84.6% / 53.8%, 7 / 4 / 2).

Table 5 / Figure 4 come from `scaling_bench.py` (synthetic graphs, 10³–2×10⁵
instances, ~10⁶ edges, in-memory SQLite). Absolute milliseconds are
machine-specific; the result is the shape across N: `impact`, `delete` and
`fc_scoped` stay flat while `fc_full` is linear.

`pre_fix_false_coverage.py` reproduces the §6.2 quadratic join by dropping the
two composite edge indexes the fix added and timing the whole-estate
`false_coverage_check()` (the paper's 16.7 s at 10⁴ instances).

## CLI

```sh
.venv/bin/scg seed --db scg.db
.venv/bin/scg gaps false-coverage --db scg.db
.venv/bin/scg gaps mitre-recommendations --db scg.db
```

## License

[PolyForm Noncommercial 1.0.0](LICENSE.md). Commercial use requires a separate
license: licensing@detecteng.ai.

Required Notice: Copyright 2026 detecteng.ai (licensing@detecteng.ai)
