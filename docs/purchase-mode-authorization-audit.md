# Purchase mode authorization follow-up

Assessment date: 2026-09-13. Original finding 45 remains open.

The historical protocol V3 and V4 mint offer delegates sign PurchaseArtifactV2.
Their solution chooses DIRECT or VOUCHER, but that choice and the voucher coin
and transition message are absent from the signed artifact. DIRECT emits the
quote deadline; the native XCH voucher branch substitutes a coin announcement.
Changing those solution fields leaves the validator artifact messages unchanged.
Offline inner-puzzle execution reproduces this failed authorization invariant;
it is not a complete consensus-accepted or public-chain transaction outcome.

Paid vouchers intentionally may redeem after their original purchase quote
expires. `test_live_xch_voucher_redeems_expired_quote_into_exact_governed_deed`
in protocol `tests/test_voucher_presale_v2_driver.py` preserves that behavior.
Adding unconditional quote expiry would break legitimate paid redemption.

This is distinct from retired legacy backend purchasing. Current
`voucher_issuance_worker.py` and `validator_service.py` still reference
`build_universal_primary_offer_v4`. `VoucherTransitionClaim.signature_messages`
includes the original artifact hash for the deed authorization. A retirement of
old SQL routes does not change these protocol commitments. Current native
inventory purchase instead uses V2 available inventory and the V5 delegate,
whose PurchaseArtifactV3 binds the purchase kind. V5 also already defines native
XCH and Base PRESALE voucher branches; replacement need not be one-to-one with
the older drivers.

Repair must first evaluate the existing V5 PRESALE branch and current artifact
model as the replacement. A new puzzle version is needed only if those existing
methods cannot enforce the complete invariant. Preserve exact historical puzzle
bytes and release manifests, and coordinate every mint/delivery builder, validator
signature producer/verifier and activation selector. The replacement
must authorize the mode and exact paid-voucher transition, preserve paid-voucher
redemption after quote expiry, and reject stale unpaid purchase authorization.
Existing coins and historical signatures cannot be repaired by changing a
Python helper or an old frozen puzzle file. Inventory/deployment selection and
any migration require their own exact-source evidence before activation.

Next repair acceptance: direct before/after quote boundary; retained direct
signature rejected for voucher mode; changed voucher/transition rejected without
new authorization; authorized paid voucher delivered to its committed vault;
V2/V5 controls preserved; reviewed module identity enforced by API and validators;
old commitments preserved and unsupported contexts held. Base/omnichain receipt
activation stays in the separately ordered omnichain work.
