# Enrollment bridge coin eligibility

Enrollment selection and isolated credential validators share one policy over
the verified signed release artifact: the exact policy hash, one-mojo amount,
allowed parent, allowed coin ID, and the coin ID derived from those fields must
agree. Discovery also requires a confirmed, unspent coin. Duplicate discovery
records do not create extra inventory. Empty inventory returns 503; inventory
already reserved by other vaults returns 409. The API does not create coins in
response to public enrollment requests.

Valid existing reservations survive missing discovery records or discovery
outages and retain their durable single-use coin binding. The API rechecks the
signed policy before returning a pending enrollment for use, accepting its proof,
preparing a stamp, or using either sponsored relay path. Validators independently
apply the same eligibility policy before their existing live-coin checks.

Historical ineligible reservations return a repair-needed 409 without replacing
the record or freeing its indexed coin. A missing local receipt or relay attempt
does not prove no external EVM authorization exists: a wallet may already have
signed a ForwardRequest. Existing rows also do not bind their original artifact
or record when authorization was exposed. Safe historical reconciliation remains
unresolved. Do not use generic update_enrollment to change a bridge coin: it does
not update the indexed bridge_coin_id, and replacement requires stronger atomic
authorization and lifecycle evidence.

The current administrator top-up path creates varying positive amounts without
adding signed parent/coin evidence. These coins already fail validator policy.
This patch does not weaken validators to accept them. Replenishment needs a
separately reviewed, consistent authorization/evidence design before it can
support customer enrollment.

Scope AUTH-BRIDGE-2: the new-reservation prevention patch does not complete
historical recovery or replenishment readiness. AUTH-RESERVE-1 (abandoned valid
reservations exhausting inventory) remains separate. Tests use simulated nodes,
synthetic public coin records and local SQLite; no live proof or chain outcome
is established. No customer omnichain source or deployment is changed.

## Pending enrollment admission

Allocation now enforces `SOLSLOT_ZKPASSPORT_ENROLLMENT_MAX_PENDING_PER_OWNER` (default 3, configurable 1–20) inside the same SQLite transaction that binds the coin. It counts every existing `reserved` row for the normalized owner, survives process restarts, and leaves exact retries available. Exceeding the bound returns 429 with instructions to finish an existing verification. Proof-confirmed progress stops consuming this pending allowance, but its coin remains permanently bound.

This mitigates one owner's accumulation across vaults; it does not prevent multiple owners exhausting the pool and does not close AUTH-RESERVE-1. Historical rows, failed or ambiguous relays, signatures created outside the API and replay records are retained. No age-based release or reassignment is implemented. Complete recovery requires a versioned authorization deadline that the external protocol can enforce, and a safe treatment of existing authorizations without that deadline.
