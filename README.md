# Solslot API

Solslot API is the testnet protocol coordinator for vault registration,
chain-bound administrator authentication, mint proposals, protocol artifacts,
and anonymous zkPassport credential stamping.

The V2 cutover is intentionally breaking:

- Python imports use `solslot_api.*` and `solslot_puzzles.*` only.
- Runtime configuration uses `SOLSLOT_*` only.
- Protocol writes default to disabled.
- A valid, signed Solslot V2 ceremony artifact is required before vault,
  mint, offer, or credential writes can be enabled.
- Retired launchers, browser state, databases, bridge policies, contracts, and
  signatures are never migrated.

## Trust Boundaries

- Chia singleton state is authoritative for protocol coordinates and vault
  credentials.
- The API's SQLite-WAL indexes are recovery and anti-replay state, not a
  substitute for Chia confirmation.
- Admin JWTs are issued only to EIP-712 members in a records file whose
  launcher and hash match the current admin-authority singleton.
- The bootstrap operator token is limited to the run-once ceremony surface.
- The official guided Testnet11 launch review class is a protected server
  setting. A browser cannot downgrade it from `independent-release-review`.
- zkPassport validator signing is internal. There is no public signing route.
- Offer artifacts require a current, server-confirmed Chia credential receipt.

## Protocol Payment Configuration

The coordinator is authoritative for protocol pricing and fulfillment terms.
Clients select a published deed and rail; they do not submit a price, launcher,
share allocation, or delivery address.

- `SOLSLOT_PAYMENT_ORACLE_ROUNDS_PATH` points to strict canonical XCH/CAT
  rounds. Native prices are accepted only with a live 2-of-3 BLS authorization
  from `SOLSLOT_PAYMENT_ORACLE_OPERATOR_PUBKEYS`.
- `SOLSLOT_PAYMENT_ORACLE_ALLOWED_CAT_ASSET_IDS` is the explicit native CAT
  allowlist.
- `SOLSLOT_SGT_WUSDC_B_ASSET_ID` names the one wUSDC.b CAT accepted by the SGT
  allocation desk. It must also appear in the oracle CAT allowlist. The admin
  UI never accepts an arbitrary CAT asset ID.
- `SOLSLOT_PAYMENT_EVM_USDC_TOKENS` must contain exactly one binding when the
  omnichain rail is enabled. Alpha binds Base Sepolia chain `84532` to Circle
  USDC `0x036CbD53842c5426634e7929541eC2318f3dCF7e` and accepts no USDT.
- `SOLSLOT_PAYMENT_OMNICHAIN_ENABLED` remains false until the separately
  deployed CCIP/Warp rail is approved. Enabling it also requires
  `SOLSLOT_PAYMENT_OMNICHAIN_PREFLIGHT_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_ACTIVATION_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_GOVERNANCE_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_SAMUEL_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_WARP_PORTAL_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_OWNERSHIP_INTENT_EVIDENCE_PATH`,
  `SOLSLOT_PAYMENT_OMNICHAIN_SOURCE_SHA`, and
  `SOLSLOT_PAYMENT_OMNICHAIN_GATEWAY_PROFILE`; the API verifies the evidence
  hashes, source SHA, chain, token, gateway profile, runtime-code descriptors,
  and a post-handoff governance-ownership attestation before it quotes or
  finalizes an EVM buy. RC19 requires schema-v2 owner-required governance:
  slot 0 owns a 1-of-1 Owner Identity Safe, slots 1 and 2 own a 1-of-2 Coadmin
  Safe, and those child Safes own a 2-of-2 root Safe. The API rejects the old
  flat 2-of-3 Safe, pre-RC19 rail schemas, guardian key reuse, incorrect Safe
  thresholds, missing seven-day recovery acceptance, and any payout or
  timelock role not bound to the root Safe.
- The one-shot ownership handoff desk is separately gated by
  `SOLSLOT_PAYMENT_OMNICHAIN_OWNERSHIP_ACTIVATION_ENABLED`. It requires the
  reviewed Safe-operation path and exact artifact hash. Administrators sign
  the actual nested Safe messages in the portal; the API stores no EVM private
  key and accepts a broadcast receipt only when the Root Safe destination and
  calldata match the reconstructed sealed transaction.
- `SOLSLOT_PAYMENT_PURCHASE_DB_PATH` is the coordinator-owned SQLite-WAL
  purchase and replay ledger.
- `SOLSLOT_PROTOCOL_ARTIFACT_API_TOKEN` protects server-to-server purchase
  construction and finalization. It is mandatory and must contain at least 32
  characters in staging and production.
- `SOLSLOT_PURCHASE_OPERATIONS_SERVICE_URL` and
  `SOLSLOT_PURCHASE_OPERATIONS_TOKEN` connect the administrator Sales desk to
  the durable backend ledger. Configure both or neither. The URL must use TLS,
  except that `http://127.0.0.1` is accepted for same-host deployment. Use the
  same generated token in the backend and never expose it to either Angular
  build.
- External SmartDeed and governed SGT delivery is controlled by
  `SOLSLOT_STRIPE_SETTLEMENT_ENABLED` and
  `SOLSLOT_STRIPE_DELIVERY_WORKER_ENABLED`. Settlement requires independent
  provider verification through `SOLSLOT_STRIPE_RESTRICTED_KEY_FILE`. Install
  a distinct Account/Event/PaymentIntent/Charges read-only key for the
  coordinator as a non-symlink file inaccessible to group and other users;
  Charges read access is required because the service may request
  `GET /v1/charges/{id}`. Never reuse a validator key or the Telonium
  fulfillment secret. The guided rehearsal refuses to arm without this file.
  The worker also requires protocol fee funding, mint writes, and a signed
  `purchases` operation window; a
  partial configuration fails closed. Store its SQLite-WAL ledger outside the
  release directory with `SOLSLOT_STRIPE_DELIVERY_DB_PATH`. Interval and lease
  settings are bounded by `SOLSLOT_STRIPE_DELIVERY_INTERVAL_SECONDS` and
  `SOLSLOT_STRIPE_DELIVERY_LEASE_SECONDS`. The worker persists each exact
  receipt-funding and delivery bundle before submission, then finalizes only
  after the expected asset and coordination output coins confirm atomically.
  `SOLSLOT_PAYMENT_KOS_EXECUTOR_URL`, request-key file, and matching BLS public
  key are mandatory. Key of Solomon is the sole submit/retry boundary and
  receives no Stripe or Base credential; hosted remote links require mTLS.
  Stripe voucher redemption and refund use the same exact KoS boundary when
  `SOLSLOT_VOUCHER_ISSUANCE_WORKER_ENABLED=true`: the API persists the funded
  bundle before dispatch, serializes terminal spends per voucher-series
  singleton, reserves its sealed fee coin, and retries only those exact bytes
  after a restart.
  The same durable worker handles reviewed Base Sepolia USDC when
  `SOLSLOT_PAYMENT_OMNICHAIN_ENABLED=true`; Base remains pending until Samuel
  relays the one-use Chia result and the API independently verifies the final
  escrow payout. Each isolated validator must receive the reviewed return
  puzzle as `SOLSLOT_VALIDATOR_BASE_RETURN_PUZZLE_HASH`, alongside its existing
  Base RPC, spoke, and official USDC settings. The hash must match the Samuel
  `send_bridge_message` curry in the signed omnichain evidence.

Native XCH and CAT purchases are completed as standard atomic Chia offer files.
The sealed USD target raise and deed share determine the exact integer USD
minor-unit price; the H-system oracle round converts that price to XCH mojos or
CAT base units. A quantity order binds every selected governed SmartDeed output
or the exact SGT CAT amount to the canonical vault in one atomic settlement.
Native offers do not pass through Samuel, Key of Solomon, or the EVM escrow.
EVM and Stripe use escrow-backed fulfillment, but must bind the same purchase
ID, artifact hash, deed launcher, vault launcher, destination, quantity, and
expiry.

## Local Verification

Create an isolated environment and pin the exact protocol checkout:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install pip==26.2.1 wheel==0.47.0
export PIP_BUILD_CONSTRAINT="$(realpath ../solslot-protocol/build-constraints.lock)"
.venv/bin/python -m pip install -c constraints.lock zstd==1.5.7.3
.venv/bin/python -m pip install -c constraints.lock -e ../solslot-protocol -e '.[dev]'
PYTHON=.venv/bin/python bash scripts/check_dependency_audit.sh
.venv/bin/python -m compileall -q solslot_api
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_namespace.py --paths .
```

The audit has no advisory ignores. Pytest 9.0.3 fixes the temporary-directory advisory.
The exact upstream Chia archive makes pytest optional while preserving the
published 0.20.3 Python/puzzle bytes; its source and build-backend pins are
verified by the protocol dependency provenance checks.
`zstd==1.5.7.3` is installed explicitly because Chia 2.7.x requires that
yanked wheel; remove the preinstall once Chia accepts a non-yanked `zstd`
release.

Start the API only with a fresh V2 state directory:

```bash
SOLSLOT_RUNTIME_ENVIRONMENT=development \
SOLSLOT_API_DOCS_ENABLED=true \
SOLSLOT_CORS_ORIGINS=http://localhost:4200 \
SOLSLOT_ALPHA_WRITES_ENABLED=false \
SOLSLOT_MINTING_ENABLED=false \
.venv/bin/uvicorn solslot_api.app:app --host 127.0.0.1 --port 5001
```

The release workflow verifies the OpenAPI schema in-process before deployment.
Staging and production disable `/docs`, `/redoc`, and `/openapi.json`; public
URLs remain under `/protocol-api` at the reverse proxy.

Production must use the systemd command and proxy limits in
[the staging deployment contract](docs/STAGING_BACKEND_DEPLOY.md). Never use
`--reload`, never bind the application to `0.0.0.0`, and never expose the
uvicorn port directly.

## Operator Documents

- [Security model](SECURITY.md)
- [Admin authority](ADMIN_README.md)
- [Clean genesis ceremony](GENESIS_README.md)
- [KoS MINT execute signer](docs/KOS_MINT_EXECUTE_SIGNER.md)
- [Staging deployment](docs/STAGING_BACKEND_DEPLOY.md)
- [zkPassport to Chia stamp](docs/ZKPASSPORT_CHIA_VAULT_ATTESTATION.md)

Minting remains disabled until the independent audit, namespace gate,
ceremony preflight, and live EVM/BLS smoke evidence all pass.
