#!/usr/bin/env python3
"""
Security Coverage Graph — scaling benchmark.

Measures whether the coverage queries scale with the *neighborhood* they touch
(the model's claim) or with *total graph size* (the failure mode). Builds
synthetic graphs at several sizes and times, on each:

  Flat-if-correct (should be ~constant across sizes):
    impact_analysis        — read-only deletion sim on a fixed 1-node neighborhood
    delete_isolated        — delete one detection with a single dependent TI
    false_coverage_scoped  — false_coverage_check(app_id=...) for one app

  Linear-by-nature (grow with size — full-estate operations, shown for contrast):
    false_coverage_full    — false_coverage_check() over the whole estate
    gaps_full              — list_detection_gaps() over the whole estate
    naive_edge_load        — list_edges() with no filter == what the OLD
                             impact_analysis did first (O(|E|)); the cost the
                             neighborhood rewrite now avoids
    full_recompute         — recompute_coverage() over every TI == what the OLD
                             delete_node did on every delete

The contrast between a flat row and its linear counterpart (impact_analysis vs
naive_edge_load; delete_isolated vs full_recompute; false_coverage_scoped vs
false_coverage_full) is the scaling result.

Graphs are built with bulk INSERTs (one transaction per table) so large sizes
are fast; ~10% of instances are given false coverage (a detection powered by
telemetry the app does not produce) for realism.

Run:  PYTHONSAFEPATH=1 python3 scaling_bench.py [--sizes 1000,10000,50000,100000,200000] [--json OUT]
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Any, Callable

from scg.graph import SCG

DISPOSABLE = 30  # isolated detections used as delete-timing samples


def build_graph(n: int) -> SCG:
    """N background instances (app_i×ttp_i, each with its own detection +
    telemetry), one fixed 'hot' neighborhood, and DISPOSABLE isolated
    detections for delete timing. ~10% of background instances are false
    coverage (PRODUCES edge omitted)."""
    g = SCG(":memory:")
    c = g._conn

    apps: list[tuple] = [("app:hot", "Hot", "o", "prod", "internet")]
    ttps: list[tuple] = [("ttp:hot", "Hot")]
    dets: list[tuple] = [("det:hot", "HotDet", "rule", "o", 0.8)]
    tels: list[tuple] = []
    tis: list[tuple] = [("app:hot:ttp:hot:v1", "app:hot", "ttp:hot", "v1")]
    edges: list[tuple] = [
        ("DETECTED_BY", "app:hot:ttp:hot:v1", "det:hot"),
        ("HAS_TI", "app:hot", "app:hot:ttp:hot:v1"),
        ("DESCRIBES", "ttp:hot", "app:hot:ttp:hot:v1"),
    ]

    for i in range(n):
        a, t, d, tel = f"app:{i}", f"ttp:{i}", f"det:{i}", f"tel:{i}"
        ti = f"{a}:{t}:v1"
        apps.append((a, f"A{i}", "o", "prod", "internet"))
        ttps.append((t, f"T{i}"))
        dets.append((d, f"D{i}", "rule", "o", 0.6))
        tels.append((tel, f"Tel{i}", "sys", "o"))
        tis.append((ti, a, t, "v1"))
        edges.append(("DETECTED_BY", ti, d))
        edges.append(("POWERS", tel, d))
        edges.append(("HAS_TI", a, ti))
        edges.append(("DESCRIBES", t, ti))
        if i % 10 != 0:                      # ~90% real coverage…
            edges.append(("PRODUCES", a, tel))
        # …every 10th instance is false coverage: no PRODUCES edge.

    for j in range(DISPOSABLE):
        a, t, d = f"app:disp{j}", f"ttp:disp{j}", f"det:disp{j}"
        ti = f"{a}:{t}:v1"
        apps.append((a, f"AD{j}", "o", "prod", "internet"))
        ttps.append((t, f"TD{j}"))
        dets.append((d, f"DD{j}", "rule", "o", 0.5))
        tis.append((ti, a, t, "v1"))
        edges.append(("DETECTED_BY", ti, d))

    c.executemany("INSERT INTO app(id,name,owner,env,exposure) VALUES(?,?,?,?,?)", apps)
    c.executemany("INSERT INTO ttp(id,name) VALUES(?,?)", ttps)
    c.executemany("INSERT INTO detection(id,name,type,owner,confidence) VALUES(?,?,?,?,?)", dets)
    c.executemany("INSERT INTO telemetry(id,name,source_system,owner) VALUES(?,?,?,?)", tels)
    c.executemany("INSERT INTO threat_instance(id,app_id,ttp_id,version_id) VALUES(?,?,?,?)", tis)
    c.executemany("INSERT INTO edge(edge_type,from_id,to_id) VALUES(?,?,?)", edges)
    c.commit()
    g.recompute_coverage()  # one-time materialization of has_detection/has_control
    g.analyze()             # post-bulk-load stats, as a real connector sync would
    return g


def _median_ms(fn: Callable[[], Any], reps: int) -> float:
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return samples[len(samples) // 2]


def bench_size(n: int) -> dict[str, Any]:
    g = build_graph(n)
    try:
        summary = g.graph_summary()
        n_edges = sum(summary["edges"].values())

        g.impact_analysis("det:hot")  # warm
        impact = _median_ms(lambda: g.impact_analysis("det:hot"), reps=50)

        # delete timing: each disposable detection is a fresh single-shot sample
        del_samples = []
        for j in range(DISPOSABLE):
            t0 = time.perf_counter()
            g.delete_node(f"det:disp{j}")
            del_samples.append((time.perf_counter() - t0) * 1000)
        del_samples.sort()
        delete_isolated = del_samples[len(del_samples) // 2]

        fc_scoped = _median_ms(lambda: g.false_coverage_check(app_id="app:0"), reps=50)
        fc_full = _median_ms(g.false_coverage_check, reps=5)
        gaps_full = _median_ms(g.list_detection_gaps, reps=5)
        naive_edge_load = _median_ms(g.list_edges, reps=5)          # old impact_analysis cost
        full_recompute = _median_ms(g.recompute_coverage, reps=3)   # old delete_node cost

        return {
            "n_instances": summary["threat_instance"],
            "n_nodes": sum(summary[k] for k in
                           ("app", "ttp", "threat_instance", "detection",
                            "control", "control_instance", "telemetry")),
            "n_edges": n_edges,
            "flat": {
                "impact_analysis_ms": round(impact, 4),
                "delete_isolated_ms": round(delete_isolated, 4),
                "false_coverage_scoped_ms": round(fc_scoped, 4),
            },
            "linear": {
                "false_coverage_full_ms": round(fc_full, 4),
                "gaps_full_ms": round(gaps_full, 4),
                "naive_edge_load_ms": round(naive_edge_load, 4),
                "full_recompute_ms": round(full_recompute, 4),
            },
        }
    finally:
        g.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sizes", default="1000,10000,50000,100000,200000",
                    help="Comma-separated background instance counts.")
    ap.add_argument("--json", default=None, help="Write full results JSON here.")
    args = ap.parse_args()

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    results = {"sizes": sizes, "rows": []}
    for n in sizes:
        row = bench_size(n)
        results["rows"].append(row)
        f = row["flat"]; l = row["linear"]
        print(f"[{row['n_instances']:>7} TIs / {row['n_edges']:>8} edges]  "
              f"impact={f['impact_analysis_ms']:.3f}  "
              f"delete={f['delete_isolated_ms']:.3f}  "
              f"fc_scoped={f['false_coverage_scoped_ms']:.3f}  ||  "
              f"fc_full={l['false_coverage_full_ms']:.2f}  "
              f"edge_load={l['naive_edge_load_ms']:.2f}  "
              f"recompute={l['full_recompute_ms']:.2f}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n[written] {args.json}")


if __name__ == "__main__":
    main()
