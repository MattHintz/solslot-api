# Base mainnet operations preparation

This source change adds an explicit `solslot.enrollment-activation.v2` profile:
identity verification and operational EIP-712 signing use Base mainnet (8453),
while Chia vaults and assets remain on Testnet11. It does not activate a release.

Historical v1 activation keeps operations on Base Sepolia (84532), even when its
identity verifier is on Base mainnet. Historical artifacts with no activation
retain their existing signing domains. Changing JSON chain IDs is not migration:
the activation, source manifest, genesis plan and signatures must agree.

The protected launch template, API, remote permit issuer, protocol artifact
validator and both browser clients recognize v2. The API additionally binds
Authority V3 governance evidence, recovery intents, Safe approvals and transaction
requests to the authenticated artifact network and checks the live RPC chain.
Both the artifact chain and deployment evidence must match; a wallet cannot
select a different authority network.

Mainnet recovery restore drills use payload schema 2 and EIP-712 domain version
2 on chain 8453. Their BLS digest also includes the new version and chain. The
historical schema-1 payload and digest remain unchanged. Offline browser review
rebuilds both digests and the payload checksum from public synthetic fixtures.
No recovery secrets are sent to the API.

For v2, the intended configuration is `SOLSLOT_NETWORK=testnet11`,
`SOLSLOT_EIP712_CHAIN_ID=8453` and `SOLSLOT_ZKPASSPORT_EVM_CHAIN_ID=8453`, with complete
issuer metadata and Base-mainnet RPCs. Configuration alone grants no authority.
The signed activation, exact release sources, matching contract deployments and
existing review/write gates remain mandatory.

## Outstanding before activation

Payment puzzles, settlement evidence, ownership activation and the Samuel Warp
route still require a distinct Base-mainnet/Testnet11 migration. Historical
Base-Sepolia payment constants have not been rewritten. The payment asset must
be selected explicitly before constructing deployable payment contracts or new
consensus modules. This branch is not a complete mainnet payment release.

A real passport/mobile proof, deployed identity contracts, all three enrolled
administrator daily wallets and tested recovery kits, exact source/deployment
review, and cross-chain confirmation remain separate launch prerequisites.
Administrator enrollment itself does not require a pre-existing SGT vault or SGT
stake. This preparation signs no deployment transactions and enables no writes.
