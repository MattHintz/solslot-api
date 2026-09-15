# Base reservation lifecycle — source preparation

Status: source implementation and offline verification; customer payment remains
unavailable. This is not alpha deployment approval, a completed launch audit, or
public-chain outcome evidence. Test assets have no monetary value or property rights.

## Authority and original identity

`baseReservationLifecycle` is an optional, authenticated
`solslot.base-reservation-lifecycle.v1` capability. It binds the exact environment,
Testnet11/Base Sepolia route, deployment, all nine source revisions, validator
ledger version 15, protocol puzzles, original admission limits, deadlines and
review evidence. `customerPaymentEnabled` must be false. An arbitrary true flag
cannot activate payment. Omnichain contract repair and reviewed activation remain
separate gates; API protection is not authorization enforced by the escrow contract.

A new V2 hold binds this current capability without a circular artifact hash. The
server saves the original payer, local/global payment IDs, purchase and reservation
before requesting private signatures. All retries recover that identity. The
customer endpoint checks session ownership, immutable intent identity, deployment,
token and the shared reservation traffic budget. The browser validates the saved
identity and current payer/network and refuses payment before token approval.

Existing V1 holds and their first verified deposit are never replaced. Their
projections must be explicitly reviewed in `holdOrigins`, with exact ceremony,
source SHA, puzzle hash, launcher and validator-roster comparisons. Prior lifecycle
receipts require a bounded, explicitly reviewed digest in `priorLifecycles`, plus
matching sources and execution coordinates. That digest is an explicit review
trust boundary; it does not reload a complete historical artifact. Only capability
changes **within the same source release and exact genesis deployment** may use
these paths. Neither projection list proves a missing on-chain transition.

Authority V3 curries the genesis source manifest into its on-chain puzzle and
preserves that commitment in every supported successor. Rebuilding a genesis plan
with new sources under an old ceremony confirmation changes real authority custody
outputs. It is rejected. A source-changing, same-deployment upgrade is unsupported
by the current artifact architecture; it requires separately reviewed separation
of genesis/runtime source identities or a genuinely fresh deployment. A fresh
alpha deployment may start without historical origins. Do not claim that the
same-source tests prove migration from an activated older source release.

Historical V3 payments without a hold remain recoverable under old ungated
artifacts. Under the new capability they require an explicit, bounded
`historicalDirectPaymentSha256` entry for the canonical purchase, global ID and
immutable source transaction/block/log. This is checked only after the existing
full independent voucher verifier. It creates no hold and grants no extension
permission. Existing payment/input replay locks remain authoritative.

## Renewal and outcomes

Base source observation and extension use separate claim schemas and BLS domains;
they never masquerade as Stripe payment intents/events. Private signers verify the
original mature EVM deposit, current eligible state, canonical Chia reservation and
series, current time and bounded increasing expiry. Exact signed and funded bytes
are retained before dispatch. The existing append-only extension journal resolves
the renewed reservation without rewriting original inventory evidence.

Terminal proof separately requires original EVM deposit identity, a mature canonical
settlement receipt, exact PaymentSettled event and corresponding ERC20 transfer to
the original payer (refund) or reviewed payout recipient (delivery). Failed results
without refunds, expiry, provider outages and partial evidence never release funded
inventory. Unfunded return requires a mature expired quote and an empty original
purchase mapping on Base, plus the actual mature Chia timeout and available output.
Delivery requires the exact signed atomic Chia bundle and SmartDeed destination.

Terminal quorum and chain observation close admission and append permanent private
tombstones. The original hold/signature/payment anchor survives. Old callbacks and
paid signatures cannot reopen that purchase. A returned deed can be reserved by a
new purchase; schema-15 generation rows preserve schema-14 originals.

The shared worker has independent renewal and terminal lanes. Private RPC capacity
is bounded, including after cancellation; recovery does not consume renewal slots.
Source observation and terminal recovery stay available when dispatch is paused.
The owner recovery endpoint resolves retained settlement and transaction evidence;
it does not accept browser-selected proofs or fall back to generic expiry for a
protected Base hold. The public prepare route still requires backend purchase gates.

## Verification boundaries

The tests exercise real serialization, secp256k1 artifact signatures, BLS, CLVM,
SQLite, transaction construction, original/renewed delivery outcomes, refund and
emergency-return proof, lost responses, retries, alias routing, ownership/admission,
capability upgrades, migration preservation and bounded cancellation. Authority,
identity registry, provider transports, chain records and fee inputs are synthetic.
The continuous transaction fixture begins from a confirmed inventory snapshot and
uses an already issued/launched series; it is not complete live campaign continuity.

Stripe behavior, historical direct recovery, legacy redemption/reads and retired
legacy/KOS write gates remain covered by their existing suites. XCH vouchers remain
release-unavailable; the admin control cannot independently bypass that release gate.
Native iOS/emulator wallet journeys, public-chain signed outcomes, independent launch
review, remaining findings, fresh ceremony/health/rollback evidence and promotion to
`solslot.com` are still separate requirements. Omnichain source is unchanged here.
