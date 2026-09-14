"""New voucher sales policy; historical settlement is deliberately separate."""
from __future__ import annotations

from fastapi import HTTPException

# This release has not completed current XCH/V5 issuance and outcome verification.
# Enabling a later release also requires independently enforced validator approval
# of the admin rail policy. A settings value or an admin window cannot bypass this.
XCH_VOUCHER_RELEASE_READY = False
XCH_VOUCHER_GATE = "xchVouchers"
XCH_VOUCHER_UNAVAILABLE = (
    "XCH voucher purchases are off. Use an approved stablecoin or Stripe. "
    "Existing vouchers can still be refunded or reconciled."
)


def xch_voucher_control(settings) -> dict:
    eligible = bool(XCH_VOUCHER_RELEASE_READY and settings.presale_xch_enabled
                    and settings.presale_enabled and settings.alpha_writes_enabled
                    and settings.collection_minting_enabled and settings.launch_control_enabled
                    and settings.network == "testnet11")
    return {"defaultEnabled": False, "releaseReady": XCH_VOUCHER_RELEASE_READY,
            "serverEnabled": bool(settings.presale_xch_enabled), "canOpen": eligible,
            "reason": None if eligible else XCH_VOUCHER_UNAVAILABLE}


def require_xch_voucher_sales(settings) -> None:
    if not xch_voucher_control(settings)["canOpen"]:
        raise HTTPException(status_code=503, detail=XCH_VOUCHER_UNAVAILABLE)
    from .launch_gates import require_operation_gate
    require_operation_gate(settings, "presale")
    require_operation_gate(settings, XCH_VOUCHER_GATE)


def require_xch_voucher_issuance_release() -> None:
    if not XCH_VOUCHER_RELEASE_READY:
        raise ValueError(XCH_VOUCHER_UNAVAILABLE)
