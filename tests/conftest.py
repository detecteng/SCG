"""
Pytest fixtures for SCG tests.

All tests get a fresh in-memory SCG instance — no file I/O, no teardown needed.
"""

import pytest
from scg.graph import SCG


@pytest.fixture
def g() -> SCG:
    """Fresh in-memory SCG instance per test."""
    return SCG(":memory:")


@pytest.fixture
def seeded(g: SCG) -> SCG:
    """SCG instance pre-loaded with the canonical seed dataset."""
    from scg.seed import load_seed
    load_seed(g)
    return g
