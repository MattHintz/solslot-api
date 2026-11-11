"""Retained legacy consensus coverage only; never imported by application code.

The active publisher is paused. These older SpendSim scenarios still verify
its historical downstream puzzles, signatures and lineage. Their local fixture
first verifies the real pause, then isolates only that policy entry guard.
Unmodified test_governance_sponsorship_containment covers the active entry path.
"""
import pytest
from solslot_api import governance_publisher

@pytest.fixture
def historical_reserve_native_only(monkeypatch):
    with pytest.raises(ValueError, match="reserve-sponsored votes are paused"):
        governance_publisher.require_reserve_sponsored_publication()
    monkeypatch.setattr(governance_publisher, "require_reserve_sponsored_publication", lambda: None)
