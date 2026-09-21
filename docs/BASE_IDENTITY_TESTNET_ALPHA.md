# Base identity verification with Testnet11 assets

This document describes the historical v1 profile. The explicit v2 operations
profile is documented in [Base mainnet operations preparation](BASE_MAINNET_OPERATIONS.md).

This candidate separates identity verification from operational signatures and settlement. It does not activate a deployment or change the reviewed RC27.41 evidence.

| Purpose | Selected network |
| --- | --- |
| zkPassport root, Solslot identity adapter, forwarder and permit emitter | Base mainnet, 8453 |
| Chia vaults, SGT, SmartDeeds and genesis | Testnet11 |
| Ceremony and administrator EIP-712 signing domain | Base Sepolia, 84532 |
| Payment, Safe recovery and omnichain components | Existing testnet configuration |

The signed `enrollmentActivation.evmChainId` is the identity chain. The artifact and genesis plan `evmChainId` remain the operational signing chain. The activation context hash, curried bridge policy, permit signature and source release commitment change when the identity network changes. Existing permits, signatures and bridge coins cannot be migrated by editing JSON or environment settings.

## Required configuration

For a new reviewed Base identity deployment, configure `SOLSLOT_ZKPASSPORT_EVM_CHAIN_ID=8453` and an HTTPS Base mainnet RPC. Keep `SOLSLOT_NETWORK=testnet11` and `SOLSLOT_EIP712_CHAIN_ID=84532`. Supply complete, matching enrollment issuer metadata, source evidence, reviewed deployment evidence and the new signed activation. All three isolated validators require the same selected identity chain and their own authenticated activation and RPC checks. Payment and recovery RPC settings remain separate.

The posture validator permits this combination only with complete issuer metadata. Runtime, ceremony, issuer, deployment, validator and artifact checks independently compare the exact selected chain. A generic network switch is not sufficient.

## Proof and privacy policy

The application uses the existing vault-specific domain/scope, age >=18, developer mode off, and the compatible zkPassport 0.20.0 proof layout. Canonical committed inputs must be exactly `0x0100021200`: AGE, length two, minimum 18, no maximum. The browser, API and contract reject extra disclosed fields and other queries. SDK 0.16.0 is kept pinned and its automatic dashboard proof storage is explicitly disabled. Browser success alone never grants an identity stamp.

No passport image, name, birth date or document number is requested by this flow. Solslot retains verification status, scoped identifiers, authorization and receipt metadata. A broadcast Base transaction publishes pseudonymous wallet/vault-linked commitments and its proof; these are not anonymous records and cannot be deleted from the chain. The scoped identifier is specific to a vault/document and is not a universal one-person/one-account guarantee.

The issuer permit and owner-signed exact calldata bind the chain, emitter, owner, current vault and one-use bridge input. There is no separate SDK bind query in this version. Its admission policy rejects all additional query types, including bind, to match the current age-only request. Any future query requires matching browser/API/contract changes and privacy review.

## Deployment and activation

Use the EVM repository's explicit `network=base`, `chainId=8453` selected plan. Never rewrite historical Base Sepolia plans. Deployment requires real Base ETH for network fees, a configured version-pinned issuer and complete public constructor values. Estimates made with placeholders are not executable approval plans.

The upstream root can change its version mappings, and its registries/verifiers are administered upstream. Pinning the root runtime and accepted layout does not make that dependency immutable. Observe the root, selected helper/subverifier, verification-key mapping, registries and pause state before deployment and activation; retain canonical block/hash observations from independent providers.

After deployment, reconstruct the exact activation and bridge policy, verify canonical creation receipts and runtime bindings, record approval of the new identity source/deployment, and install the authenticated artifacts consistently. The existing review and write gates remain enforced. Complete a real supported-document browser/mobile proof with developer mode off before opening enrollment. Unit tests and helper calls cannot establish NFC/mobile or real-proof acceptance.

Base enrollment keeps the existing twelve-block canonical receipt rule; it is a confirmation threshold, not a claim of Ethereum L1 finality. The one-use permit expiry is unchanged. No payment handoff, SGT issuance or genesis is implied by deploying identity contracts.
