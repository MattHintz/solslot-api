"""Alpha operational metrics endpoint.

Exposes a JSON metrics snapshot at ``/alpha/metrics`` for dashboard
scraping and alerting.  No PII is included; all values are aggregate
counts, gauges, and timestamps.

The endpoint requires the admin JWT so metrics are not publicly
enumerable during the alpha.
"""
from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends

from .admin_auth import AdminClaims, require_admin_jwt
from .config import Settings, get_settings

router = APIRouter(prefix="/alpha", tags=["alpha-ops"])


def _presale_metrics(settings: Settings) -> dict:
    """Read current persisted presale/voucher totals, or report unavailable."""
    try:
        from .presale_endpoints import get_presale_store

        return {"available": True, **get_presale_store(settings).aggregate_counts()}
    except Exception:
        return {"available": False}


def _telemetry_metrics(settings: Settings) -> dict:
    """Distinguish a successful zero count from unavailable storage."""
    try:
        from .alpha_observability import get_alpha_observability_store

        return {"available": True, **get_alpha_observability_store(settings).aggregate_counts()}
    except Exception:
        return {"available": False}


@router.get("/metrics")
def alpha_metrics(
    settings: Annotated[Settings, Depends(get_settings)],
    _admin: Annotated[AdminClaims, Depends(require_admin_jwt)],
) -> dict:
    """Return an aggregate operational metrics snapshot.

    Intended for dashboard scraping; no PII or secrets are included.
    """
    return {
        "timestamp": int(time.time()),
        "network": settings.network,
        "flags": {
            "alpha_writes_enabled": settings.alpha_writes_enabled,
            "minting_enabled": settings.minting_enabled,
            "payment_omnichain_enabled": settings.payment_omnichain_enabled,
        },
        "presale": _presale_metrics(settings),
        "telemetry": _telemetry_metrics(settings),
    }
