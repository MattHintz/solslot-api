"""Independently reconstruct the private current-generation batch before external settlement."""

from dataclasses import dataclass, replace
import asyncio

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol,
)
from solslot_puzzles.payment_artifacts_v3 import purchase_batch_from_json
from .vault_card_native import VaultCardNative
from .validator_quorum import _private_validator_client, configured_validator_pubkeys


def check(ok, msg):
    if not ok:
        raise ValueError(msg)


async def confirmed(native, anchor, provider):
    check(
        provider is not None and native.settings.network == "testnet11",
        "Current native card validation unavailable",
    )
    evidence = await native.from_primary(anchor, provider)
    check(
        not evidence.inventory.evidence.registry.state.pause_mask & 8,
        "Current generation purchases are paused",
    )
    stage, height = await native.stage(evidence, provider)
    check(
        stage == "CONFIRMED" and height and height > 0,
        "Original card reservations are not both confirmed",
    )
    return evidence


async def group(worker, operation):
    from .native_purchases import NativePurchaseContext, NativePurchaseGroup
    from .vault_stripe_protection import bound, paid
    from .generation_index import load_generation_read_anchor

    native = VaultCardNative.configured(worker.settings)
    evidence = await confirmed(
        native, load_generation_read_anchor(worker.settings), worker.provider
    )
    row = paid(worker, operation)
    check(
        bound(evidence.order) == row["binding"],
        "Current native vault or order differs from the paid record",
    )
    stored = worker._stored_record(operation.purchase_id)
    batch = purchase_batch_from_json(stored.purchase_artifact)
    o = evidence.order
    receipt = stored.offer_artifact["vaultCredentialReceipt"]
    check(
        stored.purchase_artifact == o.batch
        and receipt["ownerKey"] == o.owner_key
        and receipt["chiaVaultCoinId"] == o.vault_coin_id
        and receipt["identityAttestRoot"] == o.credential_root
        and receipt["policyVersion"] == o.policy_version
        and receipt["bridgePolicyHash"] == o.bridge_policy_hash
        and stored.offer_artifact["generationAnchorHash"] == o.generation_anchor_hash,
        "Protected card credential changed",
    )
    contexts = []
    for item, transition in zip(evidence.items, evidence.transitions, strict=True):
        t = item.terms
        contexts.append(
            NativePurchaseContext(
                stored=stored,
                purchase=transition.reservation.artifact,
                terms=t,
                deed_coin=transition.reserved_coin,
                deed_struct=Program.to(
                    (
                        SINGLETON_MOD_HASH,
                        (t.deed_launcher_id, t.deed_launcher_puzzle_hash),
                    )
                ),
                deed_lineage=lineage_proof_for_coinsol(transition.spend),
                genesis_artifact={"artifactHash": o.genesis_artifact_hash},
                credential_receipt=receipt,
                credential_owner_auth_type=o.owner_auth_type,
                credential_owner_key=bytes.fromhex(o.owner_key[2:]),
                reservation=transition.reservation,
            )
        )
    return NativePurchaseGroup(stored=stored, contexts=tuple(contexts), batch=batch)


@dataclass(frozen=True)
class CurrentCardSignerProof:
    evidence: object
    release: str
    receipt_record: dict | None = None

    async def bind_receipt(self, claim, provider):
        from chia_rs.sized_bytes import bytes32
        from .generation_coin_evidence import read_confirmed_coin
        from .vault_card_pending_read import card_coin_pending

        self.require_claim(claim)
        cid = bytes32.from_hexstr(claim.receipt_coin_id)
        raw = await provider.get_coin_record_by_name_primary(claim.receipt_coin_id)
        row = read_confirmed_coin(raw, cid)
        check(
            not row.spent_height
            and not await card_coin_pending(provider.primary, self.evidence.order, claim.receipt_coin_id),
            "Current card receipt is spent, pending, or unavailable",
        )
        return replace(self, receipt_record=raw)

    def require_claim(self, claim):
        o = self.evidence.order
        check(
            self.release == o.release_id
            and claim.network == o.network
            and claim.genesis_artifact_hash == o.genesis_artifact_hash
            and claim.purchase_artifact == o.batch
            and claim.stripe_evidence
            and not claim.base_evidence
            and claim.credential_vault_coin_id == o.vault_coin_id
            and claim.credential_identity_root == o.credential_root
            and claim.credential_policy_version == o.policy_version
            and claim.credential_bridge_policy_hash == o.bridge_policy_hash
            and claim.credential_owner_auth_type == o.owner_auth_type
            and claim.credential_owner_key == o.owner_key,
            "Card claim differs from independently reconstructed mint and current wallet",
        )
        rows = claim.delivery_items()
        check(
            len(rows) == len(self.evidence.transitions) == 2,
            "Incomplete native settlement set",
        )
        for row, item, transition in zip(
            rows, self.evidence.items, self.evidence.transitions, strict=True
        ):
            t = item.terms
            c = transition.reserved_coin
            check(
                (
                    row.deed_launcher_id,
                    row.deed_coin_id,
                    row.deed_puzzle_hash,
                    row.smart_deed_inner_hash,
                    row.reservation_expires_at,
                )
                == (
                    "0x" + t.deed_launcher_id.hex(),
                    "0x" + c.name().hex(),
                    "0x" + c.puzzle_hash.hex(),
                    "0x" + t.smart_deed_inner_hash.hex(),
                    o.expires_at,
                ),
                "Protected SmartDeed settlement coordinates differ",
            )


async def validator_proof(settings, provider):
    from .generation_index import load_generation_read_anchor

    native = VaultCardNative.configured(settings)
    check(
        settings.vault_card_settlement_enabled
        and not settings.stripe_settlement_enabled
        and settings.network == "testnet11",
        "Private card signer is disabled",
    )
    evidence = await confirmed(native, load_generation_read_anchor(settings), provider)
    order = evidence.order
    artifact = current_card_artifact(settings, order)
    check(
        all(
            tuple("0x" + bytes(k).hex() for k in item.terms.validator_pubkeys)
            == tuple(artifact["validatorSet"]["pubkeys"])
            and "0x" + item.terms.protocol_treasury_puzzle_hash.hex()
            == order.technology_fee_puzzle_hash
            and "0x" + item.terms.protocol_puzhash.hex()
            == order.primary_proceeds_puzzle_hash
            for item in evidence.items
        ),
        "Native mint authority differs from signed validator release",
    )
    return CurrentCardSignerProof(evidence, native.release_id)


async def validator_coverage(settings, order):
    keys = configured_validator_pubkeys(settings)
    urls = settings.zkpassport_validator_urls
    check(
        len(urls) == 3 and len(set(urls)) == 3 and len(set(keys)) == 3,
        "Independent card validators missing",
    )
    async with _private_validator_client(settings) as client:

        async def one(i):
            try:
                r = await client.get(
                    urls[i].rstrip("/") + "/v1/generation/vault-card/ready", timeout=15
                )
                r.raise_for_status()
                d = r.json()
                return d == {
                    "releaseId": order.release_id,
                    "purchaseId": order.purchase_id,
                    "batchHash": order.batch_hash,
                    "reservedCoinIds": list(order.reserved_coin_ids),
                    "network": order.network,
                    "signerIndex": i,
                    "validatorPubkey": "0x" + keys[i].hex(),
                }
            except Exception:
                return False

        outcomes = await asyncio.gather(*(one(i) for i in range(3)))
    check(
        sum(outcomes) >= 2, "Two independent validators have not proved this card order"
    )


def check_release(app, order):
    native = app.state.vault_card_checkout.native
    native.check_profile()
    scope = native.scope
    check(
        native.release_id == order.release_id
        and (
            scope.network,
            scope.mode,
            scope.accountId,
            scope.generationId,
            scope.collectionId,
            scope.vaultLauncherId,
            scope.deedLauncherIds,
            scope.originalCoinIds,
            scope.expiresAt,
            scope.generationAnchorHash,
        )
        == (
            order.network,
            order.mode,
            order.account_id,
            order.generation_id,
            order.collection_id,
            order.vault_launcher_id,
            tuple(order.deed_launcher_ids),
            tuple(order.original_coin_ids),
            order.expires_at,
            order.generation_anchor_hash,
        ),
        "Approved runtime release differs from card allocation",
    )
    return scope


def current_card_artifact(settings, order):
    from .generation_index import load_generation_read_anchor
    from .generation_preparation import read_generation_preparation

    anchor = load_generation_read_anchor(settings)
    prep = read_generation_preparation(settings)
    check(
        order.generation_anchor_hash == settings.generation_chain_anchor_hash
        and order.network == settings.network == "testnet11"
        and order.generation_id == prep.generation_id
        and "0x" + anchor.issuance.generation.hex() == order.generation_id,
        "Current generation release differs",
    )
    roster = getattr(settings, "roster_pubkeys", None)
    if roster is None:
        roster = [
            "0x" + bytes(key).hex() for key in configured_validator_pubkeys(settings)
        ]
    check(len(roster) == 3 and len(set(roster)) == 3, "Current roster is missing")
    return dict(
        network=settings.network,
        artifactHash=order.generation_anchor_hash,
        sourceShas=prep.source_commits,
        launcherIds={},
        validatorSet={"pubkeys": roster, "threshold": 2},
        puzzleHashes={
            "protocolTreasuryPuzzleHash": order.technology_fee_puzzle_hash,
            "primaryProceedsPuzzleHash": order.primary_proceeds_puzzle_hash,
        },
    )


def card_return_binding(order, artifact, environment):
    order.check()
    check(
        artifact["artifactHash"] == order.generation_anchor_hash
        and artifact["network"] == order.network
        and artifact["puzzleHashes"]["protocolTreasuryPuzzleHash"]
        == order.technology_fee_puzzle_hash
        and artifact["puzzleHashes"]["primaryProceedsPuzzleHash"]
        == order.primary_proceeds_puzzle_hash,
        "Retained native return release differs",
    )
    return dict(
        network=order.network,
        artifactHash=order.generation_anchor_hash,
        sourceShas=artifact["sourceShas"],
        adapterVersion=1,
        protocolTreasuryPuzzleHash=order.technology_fee_puzzle_hash,
        cardPrimaryProceedsPuzzleHash=order.primary_proceeds_puzzle_hash,
        cardReleaseId=order.release_id,
        validatorPubkeys=artifact["validatorSet"]["pubkeys"],
        environment=environment,
    )
