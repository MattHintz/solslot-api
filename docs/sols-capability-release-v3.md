# Customer capability release evidence, version 3

Runtime bridge/liquidity activation now requires schema 3 evidence. Schema 2 remains readable for offline historical review but cannot enable runtime execution. All feature flags still default to false, and the bridge and Tibet execution gates remain closed pending independent review and chain trials.

Deployment inputs:

- Existing checksum-pinned bridge or liquidity evidence path and SHA-256.
- `SOLSLOT_SOLS_CAPABILITY_DEPLOYMENT_ID`: distinct identifier for the exact isolated deployment.
- `SOLSLOT_SOLS_CAPABILITY_RELEASE_TAG` and `SOLSLOT_SOLS_CAPABILITY_SOURCE_SHA`: exact reviewed release identity and API source revision.
- `SOLSLOT_RUNTIME_ENVIRONMENT` and `SOLSLOT_NETWORK`: expected environment/network; evidence cannot choose these.
- `SOLSLOT_SOLS_CAPABILITY_OPERATIONS_PATH`: durable SQLite receipt store, isolated by deployment and included in runtime backups.
- `SOLSLOT_SOLS_CAPABILITY_EVM_RPC_URL`: dedicated HTTPS RPC for read-only customer bridge observation. No purchase-rail RPC or evidence is selected implicitly.

In addition to version 2 fields, version 3 requires `environment`, `deploymentId`, and `evidenceScope` equal to the exact capability. `network` must equal the configured network. `testOnly` must be true on Testnet11 and false on Mainnet. Adapter descriptors must repeat the environment, network, deployment ID, release tag and source SHA; `adapterVersion` must equal the installed version 1. Ethereum/Base Mainnet IDs (1, 8453) and Sepolia/Base Sepolia IDs (11155111, 84532) cannot cross the network boundary. Each governed record has exactly one adapter descriptor.

`implementation.chainTrialsPassed` must be true and `implementation.chainTrialEvidenceRoot` must identify the reviewed real-chain test packet. These are signed release evidence assertions, not independently re-derived chain trials during startup. Fixture passes alone are insufficient. The deployment operator must obtain independent review of the trial packet before generating these values.

Warp descriptors additionally require `confirmation` containing observer version 1, the exact Chia locker/unlocker/bridging/locked-asset puzzle hashes, Warp source-chain bytes3 values, minimum Chia/EVM confirmations, and the immutable WrappedCAT `mojoToTokenRatio` and `tipBps`. These values must be independently re-derived from the reviewed deployment; the runtime-code hashes bind the EVM contracts. The EVM-to-Chia observer verifies the authenticated EVM signer, finalized receipt/code/message, confirmed Chia unlocker spend and exact CAT payout. Chia-to-EVM parsing can match public locker/mint evidence, but the source locker carries no authenticated vault-funding association. That direction returns `SOURCE_ASSOCIATION_UNVERIFIED`, never reserves the source nonce or establishes owner-associated completion, and remains gated pending reviewed funding proof. A submitted reference is never treated as confirmation.

The observer consumes discovery references: an EVM transaction hash, a Chia bridging coin ID for the Chia source, or a Chia unlocker coin ID for the Chia destination. It is an on-demand observer, not a background indexer. The current release still needs an independently reviewed discovery/indexing workflow and deployed chain trials before the code-owned bridge activation guard can change.

Private API additions, all authorized to the vault session:

- `GET /sols/vaults/{vault}/capability-operations`: deployment-scoped saved receipts.
- `POST .../{operationHash}/authorize`: verify current execution gates, approved vault/owner, active record/root, release/deployment and unsubmitted status for a freshly prepared action.
- `POST .../{operationHash}/references`: save source/destination transaction references; cannot set finality.
- `POST .../{operationHash}/observe`: re-fetch both-chain proof and persist status; no transaction submission.

Receipt statuses include prepared, awaiting source, source association unverified, source confirmed, destination confirmed and recovery required. Saved receipts are observation-only in the browser, including PREPARED receipts with no transaction hints; another action requires fresh preparation. The official Warp handoff is an authorized button rather than a reusable saved external execution link. Replay keys bind the deployment, portal, direction and source nonce. Observation history is appended separately; later observations may downgrade current completion when evidence becomes inconsistent. Recovery remains accessible while write feature flags are disabled, provided the original reviewed deployment evidence and RPC remain available.

Operational prerequisites still outstanding: real customer WrappedCAT/registry and Chia counterpart deployments; reviewed Testnet11 governance records and observer pins; dedicated provider access; full bridge and liquidity chain trials; audited discovery/indexing; reviewed Chia-to-EVM funding-to-vault association; native Chia offer/spend verification and Tibet wallet submission; SGT governed-sale/payment/native-offer local verification. Do not enable a feature to bypass any prerequisite.
