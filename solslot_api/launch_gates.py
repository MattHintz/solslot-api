"""Dynamic signed operation windows beneath immutable environment ceilings."""

from __future__ import annotations

from fastapi import HTTPException, status

from .config import Settings
from .genesis_store import GenesisConflict, GenesisStore
from .launch_rehearsal import require_completed_rehearsal


def require_operation_gate(settings: Settings, gate_name: str) -> None:
    """Require an effective RC21 gate when guided launch control is active.

    Older test fixtures and recovery deployments that do not enable the RC21
    launch controller retain their existing environment-only behavior. RC21
    staging and production enable it explicitly, making absent/expired gates
    fail closed.
    """

    if not settings.launch_control_enabled:
        return
    try:
        store = GenesisStore(settings.genesis_db_path)
        active = store.active()
        if active is None:
            history = store.list_ceremonies(limit=1)
            active = history[0] if history else None
        if active is None:
            raise GenesisConflict("no signed alpha launch exists")
        if gate_name != "ceremonyBroadcast" and active["state"] != "locked":
            raise GenesisConflict("the signed alpha launch is not complete")
        gate = store.authorized_gate(settings, str(active["ceremony_id"]), gate_name)
        if not gate or gate["state"] != "open":
            raise GenesisConflict(f"the signed {gate_name} window is closed")
        if gate_name in {"presale", "purchases"}:
            require_completed_rehearsal(
                settings,
                store,
                str(active["ceremony_id"]),
            )
    except (GenesisConflict, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


__all__ = ["require_operation_gate"]
