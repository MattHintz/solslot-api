# Private payment inventory holds

This is source support for the presale payment lifecycle. It does not enable
presale checkout, start a payment, renew a reservation, submit a timeout, or
reconcile the coordinator's available-inventory cursor. Those integrations and
customer transaction outcomes must be verified before activation. Alpha uses
Testnet11 assets with no monetary value or real property rights.

## Authority and ordering

A payment must not be confirmed until the exact deed and an unconfirmed Stripe
PaymentIntent have a durable private two-of-three hold. The intended integration
order is: create an unconfirmed intent without exposing its client secret;
retain its exact identifier; journal the hold request; collect and retain the
private quorum acknowledgment; then confirm that same intent. A missing response
must never cause a different PaymentIntent or deed to replace an uncertain one.

`POST /v1/inventory-payment-hold/sign` is a private signer route protected by the
existing validator mTLS boundary. Its strict claim binds the signed deployment,
network, all nine source revisions, adapter and ledger versions, current V3
Stripe presale purchase, original reserved coin/puzzle/expiry, and payment ID and
method. Each signer independently reads the current Stripe account and intent,
and the mature canonical reserved singleton. New holds require an unconfirmed,
unfunded intent and live local and canonical chain clocks. The ledger rechecks
the deadline and latest signed reservation before committing.

The acknowledgment is BLS over a separate off-chain domain and the canonical
claim hash. It is not a payment receipt, spend signature, settlement authority,
or confirmation that checkout completed. Existing exact acknowledgments can be
recovered after confirmation uncertainty and expiration; they are not authority
to retry payment. Card action states and ACH processing remain held. The
coordinator must distinguish arm recovery from permission to confirm.

The ledger rejects a second active purchase for the deed, another intent for the
purchase, and reuse of a previously held payment/input. Reservation, extension,
settlement, voucher issuance and voucher transition checks share its atomic
writer boundary. A hold cannot be attached retroactively after another paid
operation was signed. Competing writers cannot each win by reading stale state.

## Terminal release

`POST /v1/inventory-payment-hold/release` observes independent evidence; it never
cancels or refunds a payment or submits a chain transaction. It requires both:

- The exact intent is canceled without received funds, or its successful charge
  is fully refunded through a complete, nonduplicated set of succeeded refunds.
  Account, test mode, purchase, currency, amounts and method must match. Pending,
  failed, partial, disputed, or unavailable evidence retains the hold.
- The same purchase's current reserved singleton has been spent through the exact
  protocol timeout and returned the exact available singleton, with three chain
  confirmations. The first acknowledgment requires that output to be unspent.

The release can follow confirmed extensions; the original purchase and payment
remain unchanged. A private release tombstone survives forever. The original
claim cannot be rearmed, rebound, or used for another extension or paid operation.
An exact release acknowledgment can be recovered after its available successor
is spent. Only the private exclusion is cleared: coordinator release/cursor
updates require their own durable quorum journal and canonical recovery proof.
Timeout, age, a worker lease, or absence of a webhook never suffices alone.

## Capability, migration and operations

`inventoryPaymentHolds` is a separate optional signed-artifact capability using
`solslot.inventory-payment-holds.v1`, adapter 1, validator ledger 12, Testnet11,
Stripe test mode and the approved `rc24-processing-through-terminal-v1` policy.
Its release identity binds the existing inventory-extension release identity,
exact source SHAs, deployment and environment; independent review evidence is
required. A missing capability cannot authorize either new private route. A
malformed present capability rejects artifact loading. Historical extension
capabilities and unrelated operations keep their existing contracts.

Ledger v12 adds payment holds without rewriting old signatures or tombstones.
Back up the private ledgers before any separately approved rollout. Older code
must not open a v12 ledger or silently discard its holds. A source revert before
activation is ordinary; rollback after any hold is armed requires a reviewed
recovery procedure retaining every acknowledgment and exclusion.

Still required: customer checkout create/retain/arm/confirm integration; durable
start-event capture; monitored renewal and ten-day ACH review without retries;
late confirmation and requires-action recovery; cancellation/refund execution;
current-coin timeout submission; coordinator release quorum/cursor reconciliation;
provider outage/restart tests; independent launch review and signed Testnet
outcomes. Existing presale gates must remain closed until those are complete.
