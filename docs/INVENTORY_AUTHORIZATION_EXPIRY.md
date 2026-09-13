# Inventory authorization expiry — local candidate

Never-confirmed inventory V2 reservations can be retired only after the signed consensus deadline is behind a mature canonical Testnet block and every original available coin is still unspent. A local timer or absent mempool record does not release a reservation. Three-confirmation evidence assumes the configured primary node is honest and the observed chain remains canonical; it is not irreversible finality.

The service-only `POST /protocol/native-purchases/inventory/reconcile-expiry` accepts only `purchaseId`. It requires the server token, mint/write ceilings, the existing purchases window, a configured primary node, and an authenticated artifact with matching `inventoryActivation` and `inventoryRecovery`. The observer validates actual V2 CLVM and retained BLS signatures, then compares the entire purchase and item snapshot in a single SQLite transaction. It records `AUTHORIZATION_EXPIRED`, preserving all original bundles, signatures, receipts and fee records. No timeout spend, payment refund or synthetic successor is created. Only genuine confirmed timeout releases advance `latest_released_inventory`.

A new purchase needs a new quote and purchase identity. Each private validator independently reconstructs its old signed claim and checks its own node before replacing the active coin lock. This also handles a partial quorum issued before API bundle persistence. Ledger schema 10 retains the v9 table unchanged and keeps all later signatures, purchase uniqueness, retirement evidence, and the exact replacement binding. Retired claims cannot replay; races have one winner. Normal first authorization and exact active retries retain their existing behavior.

## Reviewed activation required

Set `SOLSLOT_VALIDATOR_DEPLOYMENT_ENVIRONMENT` to the exact `staging-alpha` or `production-alpha` environment on each validator. This setting alone does not enable recovery. The complete committee-signed artifact must contain `inventoryRecovery` with schema `solslot.inventory-recovery.v1`, network `testnet11`, the same environment and ceremony deployment, inventory version 2, adapter version 1, validator ledger version 10, minimum confirmations 3, the exact V2 available-module hash, exact `sourceShas`, and a nonzero reviewed-evidence SHA-256. `historicalArtifactHashes` is an explicit reviewed allowlist (at most 32 distinct hashes) for old signatures from an earlier artifact; omission does not silently authorize history. Existing signed artifacts and puzzle bytes are unchanged.

V1, unknown puzzle versions, malformed history, changed rosters, missing activation, another deployment, unavailable or changing chain evidence, partially spent batches and confirmed reservations retain their locks. A recorded external payment requires settlement/refund reconciliation. Expired bundles cannot be dispatched by the shared reservation submit helper. Customer recovery UI orchestration and live deployment evidence remain launch work; this endpoint is not a public client API.

## Operations and rollback

Back up ledgers before any approved migration. Never delete old signatures or restore a pre-signature database while those signatures may remain usable. An old binary rejects ledger version 10; operational rollback must retain the migrated evidence and stop signing pending a reviewed compatible rollback. Discarding this isolated local candidate is safe because its tests use synthetic keys/state and have never broadcast.

No production activation, customer transaction outcome, signed deployment, or enrollment recovery is attested by this document. Enrollment signatures need a new permit enforced on both EVM and Chia; old consumed coins are not reusable. Beta remains separately gated.
