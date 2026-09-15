# Base prepayment protection v1

This is a preparation capability, not a complete Base checkout lifecycle. The
signed `baseInventoryHold` capability must contain
`paymentConfirmationEnabled: false`. Its acknowledgment cannot authorize an
escrow deposit, voucher issuance, delivery, reservation extension, or inventory
reuse. No customer payment UI should be enabled from this capability.

`POST /protocol/native-purchases/inventory/base-payment-hold/arm` is service-only.
A new claim requires purchase write gates, the current admitted vault owner,
the exact confirmed unpaid initial reservation, and a separately reviewed Base
capability. Existing exact holds can recover acknowledgment while new writes
are paused. Read retained evidence through the existing inventory status route.
The response always reports `confirmationAllowed: false`,
`paymentRetryAllowed: false`, `inventoryReusable: false`, and
`lifecycleReady: false`.

The claim binds the original purchase, Base Sepolia USDC, spoke, chain selector,
depositor, local/global payment ID, reserved Chia coin/puzzle, original deadline,
Testnet11, environment, deployment and nine exact component SHAs. Stripe pi_/evt_
fields are not accepted. A distinct signature domain cannot authorize a spend.

Each private validator independently checks the Base codec identity, RPC chain,
escrow route and current empty purchase mapping, then mature unspent canonical
Chia lineage and time. The coordinator retains ARMING before private requests;
the private ledger records an immutable exclusion before returning a signature.
Lost replies recover the original signatures even after the deadline. A deposit
racing the empty-mapping observation leaves inventory held, not reusable.

New Base and Stripe holds share coordinator admission and arming capacity;
abort/return capacity is separately reserved. Private fresh proofs have two
nonqueued slots across EVM and Chia work. EVM calls have bounded timeouts and a
separate two-thread limit; cancellation does not recycle an occupied RPC slot.
No SQLite transaction spans provider I/O.

A held deposit must match the original payer and payment coordinates before RPC
work and again under the coordinator writer lock. Full independent voucher
verification can retain the first exact deposit in the private ledger before
key access. Only increasing confirmations may vary on retry; retained evidence
is never replaced. V1 then refuses paid signing because the lifecycle is still
unavailable. Historical payments without this capability keep their original
verification and recovery path; no retroactive hold is invented.

Validator schema 14 adds `base_inventory_holds`; the coordinator adds
`payment_base_inventory_holds`. Original tables/receipts are preserved. Do not
remove these tables, reset their rows, downgrade an activated ledger, or use a
quote timeout to clear a hold. There is deliberately no v1 release/reset method.
Source rollback before deployment is a reviewed revert; a future deployed
rollback must remain schema-14-compatible and preserve all exclusions.

The next adapter must implement independently anchored extension through the
campaign, exact-byte resume, and terminal proof distinguishing payment disposition
from canonical inventory return. It must verify all failure paths before a
separately reviewed capability can permit customer payment. The browser still
needs to retain its local payment identity and consume that complete handshake.
The current escrow accepts deposits directly and does not enforce this API hold;
contract/customer-bridge repair remains a separate, later task. Offline tests
here prove neither public-chain transactions nor native iOS/Android journeys.
