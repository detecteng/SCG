#!/usr/bin/env python3
"""Pre-fix baseline for false_coverage_check — the paper's quadratic-join claim.

The O(n^2) fix (Section 6.2) changed no query SQL: it added the composite
indexes idx_edge_from_type / idx_edge_to_type and an ANALYZE step. This script
reproduces that pre-fix planner state for the current false_coverage_check()
(the requirement-group anti-join of §3.3): it builds the same synthetic graph
as scaling_bench.py, drops those two indexes, skips ANALYZE, and times the
whole-estate query, reporting the median of 3 runs per size. Absolute times
are machine-specific; the quadratic growth is the result.

Run from the repo root:
    PYTHONSAFEPATH=1 PYTHONPATH=src python3 metrics/pre_fix_false_coverage.py \
        --json metrics/pre_fix_false_coverage.json
"""

from __future__ import annotations

import argparse
import json
import time

from scg.graph import SCG

FIX_INDEXES = ("idx_edge_from_type", "idx_edge_to_type")


def build(n: int) -> SCG:
    """Same shape as scaling_bench.build_graph: n independent instances,
    ~10% false coverage (PRODUCES edge omitted)."""
    g = SCG(":memory:")
    c = g._conn
    apps, ttps, dets, tels, tis, edges = [], [], [], [], [], []
    for i in range(n):
        a, t, d, tel = f"app:{i}", f"ttp:{i}", f"det:{i}", f"tel:{i}"
        ti = f"{a}:{t}:v1"
        apps.append((a, f"A{i}", "o", "prod", "internet"))
        ttps.append((t, f"T{i}"))
        dets.append((d, f"D{i}", "rule", "o", 0.6))
        tels.append((tel, f"Tel{i}", "sys", "o"))
        tis.append((ti, a, t, "v1"))
        edges += [("DETECTED_BY", ti, d), ("POWERS", tel, d),
                  ("HAS_TI", a, ti), ("DESCRIBES", t, ti)]
        if i % 10 != 0:
            edges.append(("PRODUCES", a, tel))
    c.executemany("INSERT INTO app(id,name,owner,env,exposure) VALUES(?,?,?,?,?)", apps)
    c.executemany("INSERT INTO ttp(id,name) VALUES(?,?)", ttps)
    c.executemany("INSERT INTO detection(id,name,type,owner,confidence) VALUES(?,?,?,?,?)", dets)
    c.executemany("INSERT INTO telemetry(id,name,source_system,owner) VALUES(?,?,?,?)", tels)
    c.executemany("INSERT INTO threat_instance(id,app_id,ttp_id,version_id) VALUES(?,?,?,?)", tis)
    c.executemany("INSERT INTO edge(edge_type,from_id,to_id) VALUES(?,?,?)", edges)
    for idx in FIX_INDEXES:
        c.execute(f"DROP INDEX {idx}")
    c.commit()
    g.recompute_coverage()
    return g


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sizes", default="1000,5000,10000,20000")
    ap.add_argument("--json", default=None, help="Write results JSON here.")
    args = ap.parse_args()

    out = {"dropped_indexes": list(FIX_INDEXES), "rows": []}
    for n in (int(x) for x in args.sizes.split(",") if x.strip()):
        g = build(n)
        try:
            samples = []
            for _ in range(3):
                t0 = time.perf_counter()
                g.false_coverage_check()
                samples.append(time.perf_counter() - t0)
        finally:
            g._conn.close()  # skip SCG.close(): its PRAGMA optimize is part of the fix
        samples.sort()
        out["rows"].append(
            {"n_instances": n, "false_coverage_full_s": round(samples[1], 3)}
        )
        print(f"{n:>6} TIs: {samples[1]:.3f}s")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\n[written] {args.json}")


if __name__ == "__main__":
    main()
