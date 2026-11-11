"""New reserve sponsorship stops before chain reads, consent or funding."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from solslot_api.governance_endpoints import submit_publication
from solslot_api import governance_endpoints
from solslot_api.governance_publisher import build_governance_publication
from solslot_api.governance_sponsorship import (
    RESERVE_SPONSORSHIP_PAUSED,
    require_reserve_sponsored_publication,
    reserve_sponsored_publication_status,
)


class Untouched:
    def __getattr__(self, name):
        raise AssertionError(f"Publication pause accessed {name}")


def test_pause_is_explicit_and_has_no_runtime_reenable_switch():
    status = reserve_sponsored_publication_status()
    assert status["enabled"] is False
    assert status["enforcement"] == "coordinator_containment"
    assert "Saved proposals" in status["message"]
    status["enabled"] = True
    assert reserve_sponsored_publication_status()["enabled"] is False
    with pytest.raises(ValueError, match="reserve-sponsored votes are paused"):
        require_reserve_sponsored_publication()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["SGT_GRANT", "SGT_SALE", "FUNDED_REDEMPTION"])
@pytest.mark.parametrize("slot", [1, 2])
async def test_publication_builder_cannot_read_or_mutate_when_paused(kind, slot):
    with pytest.raises(ValueError, match="reserve-sponsored votes are paused"):
        await build_governance_publication(
            record=SimpleNamespace(kind=kind, state="READY"), coadmin_slot=slot,
            request=Untouched(), settings=Untouched(), genesis_store=Untouched(),
            queue_store=Untouched(), actor="test-only", renew_expired=True,
            publication_chain_time=1_900_000_000,
        )


@pytest.mark.asyncio
async def test_submit_returns_actionable_conflict_before_node_quote_or_dispatch(monkeypatch):
    # Treasury validation is independently covered; no signed production
    # artifact is used in this focused entry-point test.
    monkeypatch.setattr(governance_endpoints, "_treasury", lambda _: None)
    with pytest.raises(HTTPException) as caught:
        await submit_publication(
            proposal_id="test-only", body=Untouched(), request=Untouched(),
            settings=SimpleNamespace(sgt_allocations_enabled=True),
            genesis_store=Untouched(), queue_store=Untouched(),
            actor=SimpleNamespace(authority_slot=0),
        )
    assert caught.value.status_code == 409
    assert caught.value.detail == RESERVE_SPONSORSHIP_PAUSED
