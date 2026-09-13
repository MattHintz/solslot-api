# Solslot V2 Security Gate

## Launch State

Alpha is locked while the clean V2 ceremony is prepared. Mainnet protocol
functionality is disabled. No SmartDeed may be minted and no offer may be
created until every gate in this document is green.

## Required Invariants

### Namespace and release identity

- Release sources, paths, archives, OpenAPI output, process commands, and
  compiled assets pass `scripts/check_namespace.py`.
- Every API release records exact API and protocol commits in `release.json`.
- The protocol dependency is an exact 40-character commit, never a branch.
- The Chia ceremony draft envelope uses `schemaVersion: 2`. The signed launch
  artifact and bootstrap lock use source/artifact schema v4 and
  `protocolVersion: "solslot-v2-rc23"`. The independently versioned RC19
  Omnichain evidence uses governance v2, preflight/deployment/activation v3,
  and ownership-intent v2.

### Protocol coordinates

- Trust-critical writes load a structurally valid V2 deployment manifest.
- Zero, missing, malformed, or retired coordinates fail closed.
- Pool V3, SmartDeed V2, SGT, governance, bridge policy, and vault registry
  coordinates must all come from the signed ceremony bundle.
- Request parameters cannot replace canonical pool, governance, treasury,
  registry, or bridge coordinates.

### Public cryptographic metadata

- `/protocol` exposes only typed coordinates and commitments that are already
  independently observable on-chain and are required for client verification.
- The public snapshot never returns the raw deployment manifest, faucet
  address, faucet balance, private ceremony evidence, or administrator records.
- `/admin/auth/authority_v2` may expose launcher and commitment hashes needed
  before login. Those hashes are public singleton state, are informational
  only, and never grant authority; administrator addresses and Merkle paths are
  loaded from hash-verified records and are not returned by that route.
- The `authority_v2` route and artifact field names are preserved Chia schema
  identifiers. They do not replace the Authority V3 governance evidence and
  independent-review receipt required by the official Testnet11 launch.
- Public metadata is not an authorization source. Every mutation revalidates
  current chain state, owner proof, canonical coordinates, and replay guards.

### Administrator authority

- Deployed interactive admin authority comes only from the signed public
  release artifact, revalidated against the current authority singleton and
  genesis roster. Missing or invalid evidence fails closed.
- `SOLSLOT_ADMIN_RECORDS_PATH` is retired in deployed environments and causes
  startup rejection. Its parser is retained only in the explicit `test`
  environment for historical unit tests; it cannot authorize staging or
  production access.
- A removed member loses access on the next request even if its JWT has not
  expired.
- Ceremony bearer credentials cannot authorize post-genesis mutations.
- The bootstrap lock manifest is written last and cannot be reopened.
- EVM operations use `slot0 AND (slot1 OR slot2)` on chain: a slot-0 Owner
  Identity Safe and 1-of-2 Coadmin Safe jointly own a 2-of-2 root Safe. A flat
  2-of-3 Safe is unsupported because slots 1 and 2 could otherwise bypass the
  permanent owner requirement.
- The root Safe alone controls the 24-hour timelock and receives protocol
  payouts. Slot-0 recovery requires the separate secp256k1 guardian, both
  coadmins, replacement acceptance, and seven days; its deployment evidence
  also binds a separate BLS guardian commitment.

### zkPassport and vault credentials

- Every enrollment mutation requires a fresh EVM or BLS vault-owner challenge.
- The EVM event must come from the pinned emitter and must match the reserved
  Chia bridge coin, vault launcher, policy, scope, nullifier, and proof time.
- Validator signatures are produced only inside the verified enrollment state
  machine; there is no public signer endpoint.
- Nullifiers, bridge coins, EVM events, relay nonces, and enrollment actions are
  single-use in a persistent SQLite-WAL ledger.
- Staging and production refuse to start in protocol-write mode unless the
  configured validator policy is exactly two-of-three. Official Testnet11
  strict preflight requires the exact ordered three-member roster from the
  coordinated manifest and three healthy mTLS responses before bundle
  preparation; runtime authorization remains two-of-three.
- The UI may report verified only when Coinset confirms the current unspent
  vault successor whose puzzle hash contains the receipt's identity root.
- Browser storage is never an authorization source.

### Relay and faucet economics

- Relay limits persist across processes and restarts and are keyed by source
  IP, owner, vault, nullifier, and bridge coin.
- One relay is allowed per enrollment; request digests and forwarder nonces are
  locked before submission. The outer nonce is allocated across both owner
  modes and all coordinator workers. Exact signed EVM bytes, their locally
  derived transaction hash, owner, network, deployment and release context
  commit to SQLite before any provider submission.
- A provider timeout or mismatched response hash leaves the original relay
  outcome unknown. Authenticated recovery checks its canonical receipt first
  and may resend only the retained bytes within the original retry window.
  Receipt lookup remains available after the window ends or writes are gated.
  Historical reservations without signed bytes require explicit reconciliation;
  they are never backfilled, renewed or recycled. Any unresolved historical
  relay blocks new outer-nonce allocation across owners until reconciliation.
- When writes are paused, an existing relay owner can reauthenticate into a
  receipt-only session. That scope is rejected by ordinary vault mutation
  routes and by exact-transaction dispatch, even after writes are reenabled.
- EVM confirmation binds the transaction hash, chain, canonical block and every
  event coordinate. Pending, removed or reverted events cannot mark a vault
  verified. Browser refresh checks the server's retained relay before requesting
  a new proof or wallet authorization.
- Global gas budgets and the relay circuit breaker fail closed.
- Public enrollment requests cannot spend the faucet or create bridge coins.
- Bridge-pool replenishment requires current chain-bound admin authority.
- The exact fee-funded genesis bundle, bundle ID, and fee coin are persisted
  atomically before provider submission. A partial or ambiguous push preserves
  that reservation for reconciliation; it does not authorize constructing a
  replacement.
- Genesis replay requires a fresh owner-plus-one signed
  `ceremonyBroadcast` gate and may submit only the exact preserved bundle. Its
  reserved fee coin remains unavailable to every other protocol action.

### Server and proxy boundary

- Uvicorn binds only `127.0.0.1`; the reverse proxy is the only public
  listener and the firewall denies direct access to the application port.
- Staging and production reject insecure bootstrap cookies, development CORS,
  public API documentation, disabled HSTS, or disabled security headers during
  startup.
- The app enforces a bounded body size and request duration. Uvicorn also caps
  concurrency, backlog, and keep-alive duration; the proxy independently caps
  bodies, reads, connections, and request rates.
- Forwarded headers are trusted only from the loopback proxy. The process never
  runs with file watching or a public-interface bind.

### Offers and minting

- Mint writes require both `SOLSLOT_ALPHA_WRITES_ENABLED=true` and
  `SOLSLOT_MINTING_ENABLED=true` plus the signed V2 ceremony coordinates.
- Offer files are Solslot V2, bind canonical coordinates, and include a current
  server-confirmed Chia credential receipt.
- Empty, stale, mismatched, or unconfirmed identity roots are rejected by the
  API, portal builder, and protocol spend.
- Alpha inventory contains only canonical testnet SmartDeeds created by the
  complete admin and committee flow.

## Acceptance Evidence

The launch packet must contain clean Protocol, EVM, Omnichain, API, legacy
backend, Key of Solomon, Samuel, customer-web, and admin-portal test reports;
namespace scans of release archives; exploit regressions; reproducible puzzle
and contract hashes; secret-rotation evidence; the signed ceremony bundle; and
EVM plus BLS zkPassport-to-Chia smoke receipts.

No Critical, High, Medium, or Low security finding is accepted for Alpha.
Partial or ambiguous genesis submission is reconciled from the durable exact
bundle; a replacement bundle must never be built or submitted.
