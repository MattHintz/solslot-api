"""Contain reserve-sponsored publication until bounded bootstrap is reviewed.

This is coordinator containment, not an on-chain revocation. The deployed
reserve puzzle remains reusable by valid authority spends. A beta release
must enforce the final bootstrap policy in its committed contracts.
"""

RESERVE_SPONSORSHIP_PAUSED = (
    "New reserve-sponsored votes are paused for governance review. "
    "Saved proposals and transaction receipts are retained. "
    "Your wallet does not need another signature for this pause."
)


def reserve_sponsored_publication_status() -> dict:
    return {
        "enabled": False,
        "code": "RESERVE_SPONSORSHIP_PAUSED",
        "message": RESERVE_SPONSORSHIP_PAUSED,
        "scope": "new_reserve_sponsored_publications",
        "enforcement": "coordinator_containment",
    }


def require_reserve_sponsored_publication() -> None:
    # No request field, administrator role or environment flag reopens this
    # path. Reopening requires a separately reviewed source release.
    raise ValueError(RESERVE_SPONSORSHIP_PAUSED)
