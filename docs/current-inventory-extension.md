# Current Stripe presale inventory extensions

This source adds a service-only V5 reservation extension. Activation requires a
new reviewed, signed `inventoryExtension` capability; historical artifacts do
not enable it. Alpha uses test assets without monetary value or property rights.
This service change does not establish customer payment or launch readiness.

## Authority and execution

`POST /protocol/native-purchases/inventory/extend` authenticates the existing
server token. `purchaseId`, `paymentIntentId`, `paymentEventId`,
`paymentStartedAt`, and `paymentMethod` identify the original processing/success
event. The service selects the current input and expiry. `observeOnly: true`
permits confirmation recovery while purchase/mint write gates are paused; it
never funds, signs, or submits a transaction. Results describe a retained payment
hold and extension state, not current holdings or completed payment settlement.

A separate private `/v1/inventory-extension/sign` route independently retrieves
its node, Stripe account, current PaymentIntent and charge, and the start event.
The initial card event must prove success; ACH may be processing. It verifies
exact amount, method, purchase metadata, Testnet11, the DID-bound reserved
singleton, canonical series terms, and the active deployment. Processing hold
evidence cannot authorize paid delivery. Partial refunds and disputes retain
inventory, while full refunds/cancellation refuse new extension authorization.
Delivery retains its separate existing final-payment verification.

The private route and network verifier use async I/O on the owning event-loop
thread. Running this CLVM reconstruction in FastAPI's synchronous thread pool
reproduced a Rust LazyNode thread-affinity panic in the actual HTTP-route test.

A series witness can be canonically spent by a subsequent series transition:
its immutable terms still identify this hold. Changing phase is not permission
to release pending-payment inventory. Each validator retains its own verified
start claim for later renewals and always rereads the current account, intent,
and charge. This is necessary because Stripe guarantees event retrieval for
only 30 days. See [Stripe's event retrieval documentation](https://docs.stripe.com/api/events/retrieve).
No client-supplied historical event replaces a validator's retained start claim.

Extensions execute before the current expiry, within its last 24 hours, adding
exactly the protocol's maximum eleven-day increment. The journal pins the claim
before quorum, quorum output before funding, and full funded bytes before push.
Retries cannot replace a claim, signature set, funded bundle, or fee coin. A
fresh independent quorum rechecks the same claim before any dispatch/replay.
The signer ledger atomically excludes native, Stripe, and voucher terminal
signatures for the same input. A pending extension blocks ordinary delivery.

Three canonical confirmations of the exact source and fee spends plus the
atomic successor advance an additive receipt history. A lost acknowledgment or
an expired local clock cannot override that observation. The delivery loader
uses the confirmed successor and actual parent lineage. Original reservation
fields and artifacts remain unchanged. Historical never-confirmed expiry
snapshots accept only an empty missing extension-history field.

ACH holds require review after ten days, without inventory reuse or automatic
payment retries. Failed attempts retain their exact operation and an explicit
review status. Once an extension attempt is retained, local timeout dispatch
and timeout-based inventory release cannot remove the payment hold. The private
initial-reservation signer also refuses a different buyer for a SmartDeed with
a retained extension hold, even if a permissionless timeout created a new
available coin. Authoritative terminal reconciliation must clear that hold
through a separately reviewed method; no clearing method is exposed here. Confirmed
history is bounded to 128 extensions; exhaustion requires review and keeps the
hold. Terminal-payment/refund recovery must be separately completed before
this capability is activated.

## Capability and migration

The capability binds `staging-alpha` or `production-alpha`, Testnet11, ceremony
ID, all nine exact source SHAs, inventory V2, adapter v1, validator ledger v11,
frozen available/reserved module hashes, timing bounds, the approved RC24 hold
policy, exact test Stripe account, a derived release identity, and a nonzero
review-evidence digest. Runtime and private signer loaders reject malformed
present capabilities. Historical inventory-recovery capability v10 is preserved;
the additive ledger migration does not rewrite signed evidence.

API storage gains a durable extension journal and separate confirmed-history
column. Validator storage advances from schema 10 to 11, retaining all existing
signature locks. Back up both stores before a separately approved deployment.
After extension signatures exist, never restore an older ledger or discard
journal rows to make a retry work. Pause writes and use a reviewed forward
repair. Source-only publication can be reverted before deployment without a
runtime migration.

## Evidence and remaining integration

`tests/test_inventory_extensions.py` executes real local BLS and CLVM, private
HTTP quorum, SQLite restart/conflict behavior, canonical-outcome reconstruction,
and the existing paid-voucher delivery loader. Chain, provider, authority,
fee transport and paid-delivery quorum are explicit fixtures. These tests do
not prove customer-signed Testnet transactions or the complete checkout flow.
The existing initial-reservation route has separate source coverage.

Before activation, align the customer Stripe metadata and presale payment
producer with the verifier contract, durably register the payment-start event,
wire monitored automatic renewal, and implement terminal payment/refund recovery
without inventory reassignment. The current checkout producer's `purchase_id`
and `protocol_artifact_hash` do not satisfy the validator's canonical
`protocol_purchase_id` and `purchase_artifact_hash` commitments. This change
does not relax the validator to accommodate that mismatch. Complete the actual
initial reservation → payment start → extensions → paid delivery/refund journey
with independent terminal verification, then separately authorized customer
Testnet outcomes. Mainnet beta, legacy SQL/KOS purchase writers, and omnichain
are not enabled by this capability.
