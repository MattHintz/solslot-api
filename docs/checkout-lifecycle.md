# Automatic checkout lifecycle (source capability, disabled by default)

`SOLSLOT_CHECKOUT_LIFECYCLE_WORKER_ENABLED` opts in to two durable lanes in the
existing environment-specific payment purchase database. Startup requires an exact
reviewed `checkoutLifecycle` signed-artifact capability binding the environment,
testnet11, deployment, all nine source SHAs, hold/extension releases, adapter version,
Stripe test account, 60-second lease, 45-second advancement deadline and ten-day ACH
review policy. A missing or mismatched capability fails startup. Publishing source
does not create this evidence or enable a deployment. Continue to use the supported
single coordinator process for faucet-backed writes.

The backend's `SOLSLOT_CHECKOUT_LIFECYCLE_HANDOFF_ENABLED` flag forwards retained
payment-start candidates after the local callback commit. The service-only
`POST /protocol/native-purchases/inventory/payment-hold/observe-payment` acknowledges
queue retention, explicitly not payment verification. Failed or stale callback
retries forward the same payment without another confirmation or provider intent.
No customer payment or personal data is added to a public status response.

The renewal lane first obtains independent two-of-three provider observation
signatures. Their domain cannot authorize a chain spend. An invalid event does not
pin an extension; the first verified event/start is immutable. Existing extension
claims and exact funded executions remain immutable and recover through their
existing independent validator checks. Observation runs while fresh purchases are
paused; renewal dispatch still requires authoritative write gates and preflight.
Ten-day ACH age or an expired reservation produces review, never automatic reuse.

The terminal lane independently observes either the actual REDEEMED current-voucher
SmartDeed output or the canonical timeout plus private canceled/unfunded/full-refund
quorum. It does not cancel/refund a payment or broadcast a timeout. Partial-arm abort
is observed only after a mature timeout, so early polling cannot interrupt arming.
Only the existing atomic terminal closure frees identity admission capacity.

One job per purchase/lane, separate global lane leases, bounded keyset backfill and
durable retry times survive restart and prevent callback retries from growing work
or resetting backoff. Cancellation preserves existing execution bytes and releases
only the owning lease. The service-only `GET .../inventory/payment-hold/lifecycle-health`
reports exact bound lane receipts; healthy requires both lanes within 90 seconds and
an eligible status. An enabled process alone is not health evidence.

Verification uses actual BLS/private HTTP and CLVM transaction builders with synthetic
provider/RPC authority. These are not live customer signatures or chain outcomes.
The existing voucher worker's broader pending scans still require separate bounded
scheduling. Previously pinned invalid extension records need evidence-led review;
never delete journals, private tombstones or held inventory to clear capacity.

Source rollback is a reviewed revert. If a future approved deployment has activated
the capability, stop dispatch first and preserve its durable observations/jobs and
all original transaction/terminal journals; do not downgrade or erase evidence.
