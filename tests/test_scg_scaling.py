"""
Scaling guards for the coverage analytics.

These pin the *asymptotic shape* established when the query implementations were
made index-backed: `impact_analysis` and `delete_node` on a fixed-size
neighborhood must stay roughly constant as unrelated graph bulk grows, i.e. they
must NOT scale with total graph size. The thresholds are deliberately loose (CI
timing is noisy) — they exist to catch a regression back to a full-table
SCAN / full recompute, not to assert a precise millisecond budget.
"""

import time

import pytest

from scg.graph import SCG


def _build(n_unrelated: int) -> SCG:
    """A fixed 1-detection hot neighborhood plus n_unrelated independent TIs."""
    g = SCG(":memory:")
    g.upsert_app("app:hot", "Hot", "o", "prod", "internet")
    g.upsert_ttp("ttp:H", "H")
    g.upsert_detection("det:hot", "HotDet", "rule", "o", confidence=0.8)
    ti = g.upsert_threat_instance("app:hot", "ttp:H")
    g.add_edge("DETECTED_BY", ti, "det:hot")
    for i in range(n_unrelated):
        g.upsert_app(f"app:{i}", f"A{i}", "o", "prod", "internet")
        g.upsert_ttp(f"ttp:{i}", f"T{i}")
        g.upsert_detection(f"det:{i}", f"D{i}", "rule", "o", confidence=0.5)
        t = g.upsert_threat_instance(f"app:{i}", f"ttp:{i}")
        g.add_edge("DETECTED_BY", t, f"det:{i}")
    return g


def _median_ms(fn, reps: int) -> float:
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return samples[len(samples) // 2]


def test_impact_analysis_does_not_scale_with_graph_size() -> None:
    small = _build(200)
    large = _build(20_000)
    try:
        small.impact_analysis("det:hot")  # warm
        large.impact_analysis("det:hot")
        t_small = _median_ms(lambda: small.impact_analysis("det:hot"), reps=25)
        t_large = _median_ms(lambda: large.impact_analysis("det:hot"), reps=25)
        # 100x the graph must not cost anywhere near 100x. A reverted O(|E|)
        # scan would blow past this; the index-backed path stays ~flat.
        assert t_large < t_small * 10 + 5, (t_small, t_large)
    finally:
        small.close()
        large.close()


def test_delete_isolated_node_does_not_scale_with_graph_size() -> None:
    small = _build(200)
    large = _build(20_000)
    try:
        t_small = _median_ms(lambda: small.delete_node("det:hot"), reps=1)
        t_large = _median_ms(lambda: large.delete_node("det:hot"), reps=1)
        # delete + scoped recompute of one isolated detection: a reverted full
        # recompute_coverage() / unindexed cascade would scale with graph size.
        assert t_large < t_small * 10 + 5, (t_small, t_large)
    finally:
        small.close()
        large.close()
