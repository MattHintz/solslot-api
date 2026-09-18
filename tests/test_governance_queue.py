from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_api.governance_endpoints import (
    ClaimExternalSGTPurchase,
    CompleteAllocationVoteRequest,
    CreateGovernanceProposal,
    PrepareAllocationVoteRequest,
    _proposal_chain_state,
    _external_sgt_purchase,
    _public,
    _recipient_vault,
    _wusdc_b_asset_id,
    claim_external_sgt_purchase_artifact,
    complete_allocation_vote,
    get_public_sgt_sale,
    list_public_sgt_sales,
    prepare_allocation_vote,
)
from solslot_api.governance_execution import (
    AllocationChainState,
    AllocationVoteBuild,
    trace_allocation_proposal,
)
from solslot_api.governance_sale_offer import reconstruct_governed_sale_offer
from solslot_api.governance_publisher import _action, _publication_delegated_puzzle
from solslot_api.governance_queue import (
    GovernanceQueueConflict,
    GovernanceQueueStore,
)
from solslot_api.protocol_submission import ProtocolBundleSubmitter
from solslot_api.protocol_artifacts import _artifact_rejection_reasons
from solslot_api.vault_eligibility import ApprovedVault
from solslot_puzzles.eip712_helpers import normalize_eip712_member_signature
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseDeliveryKind,
    build_sgt_purchase_artifact_v3,
    purchase_artifact_v3_to_json,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import (
    TRK_EXECUTE,
    TRK_PROPOSE,
    TRK_VOTE,
    bill_sgt_sale,
    proposal_hash_from_bill,
    sgt_free_inner_puzzle,
    sgt_locked_inner_mod,
)
from solslot_puzzles.sgt_reserve_driver import (
    SGTAllocationRail,
    SGTSaleTermsV1,
    sgt_cat_puzzle,
    sgt_reserve_inner_puzzle,
    sgt_sale_inner_puzzle,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


def _create(store: GovernanceQueueStore, seed: int):
    return store.create(
        kind="SGT_SALE",
        title=f"Allocation {seed}",
        bill={"saleId": f"0x{seed:064x}", "sgtAmount": "1000"},
        bill_clvm_hex=f"0x{seed:02x}",
        proposal_hash=f"0x{seed:064x}",
        actor="0xowner",
        now=1_800_000_000 + seed,
    )


def test_sgt_allocation_accepts_only_a_current_approved_vault(monkeypatch) -> None:
    launcher = "0x" + "11" * 32
    p2 = "0x" + "22" * 32
    identity = "0x" + "33" * 32
    approved = SimpleNamespace(
        launcher_id=launcher,
        p2_puzzle_hash=p2,
        current_coin_id="0x" + "44" * 32,
        identity_attest_root=identity,
        confirmed_block_index=123,
        enrollment=SimpleNamespace(),
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints.require_current_approved_vault",
        lambda _settings, value: approved if value == launcher else None,
    )
    body = CreateGovernanceProposal.model_validate(
        {
            "kind": "SGT_SALE",
            "title": "Vault-bound committee allocation",
            "sgtAmount": "10000",
            "recipientVaultLauncherId": launcher,
            "saleId": "0x" + "55" * 32,
            "paymentRail": "XCH",
            "paymentAmount": "1000000",
            "expiresAt": 1_900_000_000,
        }
    )
    resolved, recipient = _recipient_vault(body, SimpleNamespace())
    assert resolved is approved
    assert recipient == bytes32.from_hexstr(p2)

    with pytest.raises(Exception, match="Extra inputs are not permitted"):
        CreateGovernanceProposal.model_validate(
            {
                "kind": "SGT_GRANT",
                "title": "Unsafe free-wallet allocation",
                "sgtAmount": "1",
                "recipientVaultLauncherId": launcher,
                "recipientAddress": "txch1unsafe",
                "grantId": "0x" + "66" * 32,
                "reasonHash": "0x" + "77" * 32,
            }
        )


def test_external_sgt_sale_windows_cover_stripe_ach_but_keep_base_quotes_short(
    monkeypatch,
) -> None:
    now = 1_800_000_000
    launcher = "0x" + "11" * 32
    approved = SimpleNamespace(
        launcher_id=launcher,
        p2_puzzle_hash="0x" + "22" * 32,
        identity_attest_root="0x" + "33" * 32,
    )
    settings = SimpleNamespace(
        network="testnet11",
        payment_evm_usdc_tokens={"84532": "0x" + "44" * 20},
    )
    monkeypatch.setattr("solslot_api.governance_endpoints.time.time", lambda: now)
    monkeypatch.setattr(
        "solslot_api.governance_endpoints._sgt_tail_hash",
        lambda _settings: bytes32(b"\x55" * 32),
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints._protocol_treasury",
        lambda _settings: bytes32(b"\x66" * 32),
    )

    def body(rail: str, expires_at: int) -> CreateGovernanceProposal:
        return CreateGovernanceProposal.model_validate(
            {
                "kind": "SGT_SALE",
                "title": "Governed committee allocation",
                "sgtAmount": "10000",
                "recipientVaultLauncherId": launcher,
                "saleId": "0x" + "77" * 32,
                "paymentRail": rail,
                "baseUsdAmountMinor": "100000",
                "expiresAt": expires_at,
            }
        )

    with pytest.raises(ValueError, match="at least 11 days"):
        _external_sgt_purchase(body("STRIPE", now + 10 * 24 * 60 * 60), approved, settings)
    stripe = _external_sgt_purchase(
        body("STRIPE", now + 11 * 24 * 60 * 60), approved, settings
    )
    assert stripe.quote_expires_at == now + 11 * 24 * 60 * 60

    base = _external_sgt_purchase(body("BASE_USDC", now + 20 * 60), approved, settings)
    assert base.quote_expires_at == now + 20 * 60
    with pytest.raises(ValueError, match="cannot exceed 30 minutes"):
        _external_sgt_purchase(body("BASE_USDC", now + 31 * 60), approved, settings)


def test_vault_vote_routes_are_registered_without_replacing_committee_relay() -> None:
    from solslot_api.app import app

    paths = app.openapi()["paths"]
    base = "/governance/proposals/{proposal_id}/vaults/{vault_launcher_id}/votes"
    assert f"{base}/prepare" in paths
    assert f"{base}/complete" in paths
    assert "/admin/committee/vote" in paths


@pytest.mark.asyncio
async def test_external_sgt_purchase_uses_shared_verified_offer_envelope(
    monkeypatch,
    tmp_path,
) -> None:
    now = 1_800_000_000
    sale_id = bytes32(b"\x31" * 32)
    sgt_tail = bytes32(b"\x32" * 32)
    launcher = bytes32(b"\x33" * 32)
    identity_root = bytes32(b"\x34" * 32)
    treasury = bytes32(b"\x35" * 32)
    sale_coin = Coin(bytes32(b"\x36" * 32), bytes32(b"\x37" * 32), uint64(500))
    purchase = build_sgt_purchase_artifact_v3(
        network="testnet11",
        sgt_asset_id=sgt_tail,
        sale_id=sale_id,
        sgt_amount=500,
        base_usd_amount_minor=100_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=treasury,
        zkpassport_root=identity_root,
        rail=PaymentRail.STRIPE,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=2,
        vault_launcher_id=launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(launcher),
        authorization_nonce=bytes32(b"\x38" * 32),
        authorization_expires_at=now + 600,
        quote_expires_at=now + 600,
    )
    purchase_json = purchase_artifact_v3_to_json(purchase)
    proposal_hash = "0x" + "39" * 32
    record = SimpleNamespace(
        id="sgt-sale-1",
        kind="SGT_SALE",
        state="EXECUTED",
        proposal_hash=proposal_hash,
        bill={
            "paymentRail": "STRIPE",
            "purchaseArtifact": purchase_json,
            "purchaseArtifactHash": "0x" + purchase.artifact_hash.hex(),
        },
    )
    receipt = {
        "vaultLauncherId": "0x" + launcher.hex(),
        "network": "testnet11",
        "policyVersion": 2,
        "identityAttestRoot": "0x" + identity_root.hex(),
        "attestationLeafHash": "0x" + identity_root.hex(),
        "attestationProof": {"bitpath": 0, "siblings": []},
        "bridgePolicyHash": "0x" + "40" * 32,
        "bridgeParentId": "0x" + "41" * 32,
        "bridgeAmount": 1,
        "bridgeCoinId": "0x" + "42" * 32,
        "evmTxHash": "0x" + "43" * 32,
        "chiaVaultCoinId": "0x" + "44" * 32,
        "confirmedBlockIndex": 123,
        "enrolledAt": now - 60,
    }
    approved = ApprovedVault(
        launcher_id="0x" + launcher.hex(),
        p2_puzzle_hash="0x" + puzzle_hash_for_p2_vault(launcher).hex(),
        current_coin_id="0x" + "44" * 32,
        identity_attest_root="0x" + identity_root.hex(),
        confirmed_block_index=123,
        enrollment=SimpleNamespace(
            receipt=SimpleNamespace(model_dump=lambda: receipt)
        ),
    )
    terms = SimpleNamespace(
        expires_at=now + 600,
        payment_rail=SGTAllocationRail.STRIPE,
        purchase_artifact_hash=purchase.artifact_hash,
        payment_amount=purchase.rail_amount,
        sgt_amount=purchase.delivery_amount,
        sale_id=purchase.delivery_context_hash,
        recipient_vault_launcher_id=purchase.vault_launcher_id,
    )
    chain = SimpleNamespace(sale_coin=sale_coin, terms=terms, spent_height=None)
    signed_artifact = {
        "artifactHash": "0x" + "45" * 32,
        "launcherIds": {
            "pool": "0x" + "46" * 32,
            "protocolConfig": "0x" + "47" * 32,
            "vaultVersionRegistry": "0x" + "48" * 32,
        },
    }
    settings = SimpleNamespace(
        network="testnet11",
        payment_purchase_db_path=str(tmp_path / "payments.db"),
    )
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(coinset=SimpleNamespace()))
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints.require_sgt_allocation_drafts",
        lambda _settings: None,
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints._require_server_to_server_token",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints.require_current_approved_vault",
        lambda *_args, **_kwargs: approved,
    )

    async def reconstruct(**_kwargs):
        return chain

    monkeypatch.setattr(
        "solslot_api.governance_endpoints.reconstruct_governed_sale_coin",
        reconstruct,
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints.load_signed_public_artifact",
        lambda _settings: signed_artifact,
    )

    response = await claim_external_sgt_purchase_artifact(
        record.id,
        ClaimExternalSGTPurchase.model_validate(
            {
                "purchaseIntentId": "pi_sgt_sale_1",
                "rail": "stripe",
                "vaultLauncherId": approved.launcher_id,
                "currentVaultCoinId": approved.current_coin_id,
                "identityAttestRoot": approved.identity_attest_root,
            }
        ),
        request,
        settings,
        SimpleNamespace(get=lambda _proposal_id: record),
        "Bearer internal",
    )
    envelope = response["artifact"]
    assert envelope["protocol"]["deliveryKind"] == "sgt"
    assert envelope["protocol"]["deliveryAmount"] == "500"
    assert envelope["protocol"]["quantity"] == 500
    assert envelope["protocol"]["collectionId"] == "0x" + "00" * 32
    assert envelope["paymentTerms"]["gross_usd_amount_minor"] == "101000"
    assert _artifact_rejection_reasons(
        envelope,
        response["artifact_hash"],
        now=now,
    ) == []


@pytest.mark.asyncio
async def test_external_sgt_sale_is_public_without_a_fake_chia_offer(
    monkeypatch,
) -> None:
    now = int(time.time())
    sale_coin = Coin(bytes32(b"\x51" * 32), bytes32(b"\x52" * 32), uint64(750))
    record = SimpleNamespace(
        id="sgt-sale-external",
        kind="SGT_SALE",
        state="EXECUTED",
        title="Approved Stripe allocation",
        proposal_hash="0x" + "53" * 32,
        bill={
            "paymentRail": "STRIPE",
            "sgtAmount": "750",
            "recipientVaultLauncherId": "0x" + "54" * 32,
        },
        sale_offer_id=None,
        sale_coin_id="0x" + sale_coin.name().hex(),
        sale_offer_status="AVAILABLE",
        sale_offer_published_at=now,
        sale_offer_confirmed_height=456,
        sale_offer_spent_height=None,
    )
    settings = SimpleNamespace()
    store = SimpleNamespace(
        list=lambda public=True: [record],
        get=lambda _proposal_id: record,
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints.require_sgt_allocation_drafts",
        lambda _settings: None,
    )
    listed = list_public_sgt_sales(settings, store)
    assert listed["count"] == 1
    assert listed["sales"][0]["offer"] is None
    assert listed["sales"][0]["externalPayment"]["rail"] == "stripe"

    async def reconstruct(**_kwargs):
        return SimpleNamespace(
            sale_coin=sale_coin,
            terms=SimpleNamespace(expires_at=now + 600),
            confirmed_height=456,
            spent_height=None,
        )

    monkeypatch.setattr(
        "solslot_api.governance_endpoints.reconstruct_governed_sale_coin",
        reconstruct,
    )
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(coinset=SimpleNamespace()))
    )
    detail = await get_public_sgt_sale(record.id, request, settings, store)
    assert detail["offer"] is None
    assert detail["externalPayment"]["status"] == "AVAILABLE"
    assert detail["externalPayment"]["saleCoinId"] == (
        "0x" + sale_coin.name().hex()
    )


class _VoteSubmitter(ProtocolBundleSubmitter):
    def __init__(self) -> None:
        self.submitted = None

    async def submit(self, bundle):
        self.submitted = bundle
        return {
            "status": "MEMPOOL",
            "spendBundleId": "0x" + "91" * 32,
            "feeMojos": "77",
            "feeTargetSeconds": 300,
            "submissionProvider": "primary",
            "mempoolObservedAt": "2026-08-01T18:00:00Z",
        }


@pytest.mark.asyncio
async def test_vault_vote_prepare_and_complete_reuse_exact_server_build(
    monkeypatch,
    tmp_path,
) -> None:
    launcher = bytes32(b"\x41" * 32)
    proposal_hash = bytes32(b"\x42" * 32)
    operation_hash = bytes32(b"\x43" * 32)
    vault_coin_id = bytes32(b"\x44" * 32)
    sgt_coin_id = bytes32(b"\x45" * 32)
    approved = ApprovedVault(
        launcher_id="0x" + launcher.hex(),
        p2_puzzle_hash="0x" + "46" * 32,
        current_coin_id="0x" + vault_coin_id.hex(),
        identity_attest_root="0x" + "47" * 32,
        confirmed_block_index=10,
        enrollment=SimpleNamespace(),
    )
    chain = AllocationChainState(
        state="VOTING",
        vote_tally=100_000,
        voting_deadline=1_900_000_000,
    )
    build = AllocationVoteBuild(
        chain=chain,
        bundle=SpendBundle([], G2Element()),
        operation_hash=operation_hash,
        proposal_hash=proposal_hash,
        vault_launcher_id=launcher,
        vault_coin_id=vault_coin_id,
        vault_auth_type="chia_bls",
        vault_typed_data=None,
        sgt_coin_id=sgt_coin_id,
        sgt_amount=25_000,
        available_sgt_amounts=(25_000,),
        locked_inner_puzzle_hash=bytes32(b"\x48" * 32),
        approved_vault=approved,
    )
    store = GovernanceQueueStore(str(tmp_path / "vote.db"))
    record = store.create(
        kind="SGT_GRANT",
        title="Vault-bound vote",
        bill={"sgtAmount": "25000"},
        bill_clvm_hex="0x80",
        proposal_hash="0x" + proposal_hash.hex(),
        actor="0xowner",
    )
    record = store.transition(
        proposal_id=record.id,
        expected_revision=record.revision,
        target="READY",
        actor="0xreviewer",
    )
    record = store.transition(
        proposal_id=record.id,
        expected_revision=record.revision,
        target="ACTIVE",
        actor="0xowner",
        activation_bundle_id="0x" + "49" * 32,
        proposal_coin_id="0x" + "4a" * 32,
    )
    submitter = _VoteSubmitter()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(coinset=SimpleNamespace(), protocol_submitter=submitter)
        )
    )

    monkeypatch.setattr(
        "solslot_api.governance_endpoints.require_alpha_writes", lambda _settings: None
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints.require_sgt_allocation_drafts",
        lambda _settings: None,
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints.verify_vault_session",
        lambda *_args: SimpleNamespace(vault_launcher_id=approved.launcher_id),
    )

    calls = []

    async def fake_build(**kwargs):
        calls.append(kwargs)
        return build

    async def inputs_clear(*_args):
        return None

    monkeypatch.setattr(
        "solslot_api.governance_endpoints.build_allocation_vote", fake_build
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints._require_inputs_clear", inputs_clear
    )
    monkeypatch.setattr(
        "solslot_api.governance_endpoints._verify_aggregate_signature",
        lambda *_args: None,
    )
    settings = SimpleNamespace(network="testnet11")

    prepared = await prepare_allocation_vote(
        record.id,
        approved.launcher_id,
        PrepareAllocationVoteRequest(voteAmount="25000"),
        request,
        settings,
        store,
    )
    assert prepared["operationHash"] == "0x" + operation_hash.hex()
    assert prepared["vaultAuthType"] == "chia_bls"
    assert prepared["availableSgtAmounts"] == ["25000"]

    completed = await complete_allocation_vote(
        record.id,
        approved.launcher_id,
        CompleteAllocationVoteRequest(
            voteAmount="25000",
            operationHash="0x" + operation_hash.hex(),
            aggregatedSignature="0x" + bytes(G2Element()).hex(),
        ),
        request,
        settings,
        store,
    )
    assert completed["status"] == "MEMPOOL"
    assert completed["feeMojos"] == "77"
    assert submitter.submitted is not None
    assert len(calls) == 2


def test_wusdc_b_sale_uses_only_the_server_configured_allowlisted_cat(monkeypatch) -> None:
    asset_id = "0x" + "88" * 32
    monkeypatch.setattr(
        "solslot_api.governance_endpoints.load_signed_public_artifact",
        lambda _settings: {
            "genesisPlan": {"trustedAssets": {"wusdcBAssetId": asset_id}}
        },
    )
    settings = SimpleNamespace(
        sgt_wusdc_b_asset_id=asset_id,
        payment_oracle_allowed_cat_asset_ids=[asset_id],
    )
    assert _wusdc_b_asset_id(settings) == bytes32.from_hexstr(asset_id)

    body = CreateGovernanceProposal.model_validate(
        {
            "kind": "SGT_SALE",
            "title": "Stablecoin committee allocation",
            "sgtAmount": "10000",
            "recipientVaultLauncherId": "0x" + "11" * 32,
            "saleId": "0x" + "55" * 32,
            "paymentRail": "WUSDC_B",
            "paymentAmount": "125050",
            "expiresAt": 1_900_000_000,
        }
    )
    assert body.payment_rail == "WUSDC_B"

    with pytest.raises(Exception, match="Extra inputs are not permitted"):
        CreateGovernanceProposal.model_validate(
            {
                **body.model_dump(by_alias=True),
                "paymentAssetId": "0x" + "99" * 32,
            }
        )

    with pytest.raises(HTTPException, match="not in the signed-oracle CAT allowlist"):
        _wusdc_b_asset_id(
            SimpleNamespace(
                sgt_wusdc_b_asset_id=asset_id,
                payment_oracle_allowed_cat_asset_ids=["0x" + "99" * 32],
            )
        )


def test_queue_allows_many_drafts_but_only_one_chain_backed_active(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    first = _create(store, 1)
    second = _create(store, 2)
    first = store.transition(
        proposal_id=first.id,
        expected_revision=first.revision,
        target="READY",
        actor="0xreviewer",
    )
    second = store.transition(
        proposal_id=second.id,
        expected_revision=second.revision,
        target="READY",
        actor="0xreviewer",
    )

    with pytest.raises(GovernanceQueueConflict, match="submitted bundle"):
        store.transition(
            proposal_id=first.id,
            expected_revision=first.revision,
            target="ACTIVE",
            actor="0xowner",
        )

    first = store.transition(
        proposal_id=first.id,
        expected_revision=first.revision,
        target="ACTIVE",
        actor="0xowner",
        activation_bundle_id="0x" + "11" * 32,
        proposal_coin_id="0x" + "12" * 32,
    )
    assert first.activation_bundle_id == "0x" + "11" * 32
    assert first.proposal_coin_id == "0x" + "12" * 32

    with pytest.raises(GovernanceQueueConflict, match="already active"):
        store.transition(
            proposal_id=second.id,
            expected_revision=second.revision,
            target="ACTIVE",
            actor="0xowner",
            activation_bundle_id="0x" + "21" * 32,
            proposal_coin_id="0x" + "22" * 32,
        )


def test_completion_requires_chain_evidence_and_releases_next_queue_item(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    first = _create(store, 3)
    second = _create(store, 4)
    for value in (first, second):
        store.transition(
            proposal_id=value.id,
            expected_revision=value.revision,
            target="READY",
            actor="0xreviewer",
        )
    first = store.get(first.id)
    first = store.transition(
        proposal_id=first.id,
        expected_revision=first.revision,
        target="ACTIVE",
        actor="0xowner",
        activation_bundle_id="0x" + "31" * 32,
        proposal_coin_id="0x" + "32" * 32,
    )

    with pytest.raises(GovernanceQueueConflict, match="completion bundle"):
        store.transition(
            proposal_id=first.id,
            expected_revision=first.revision,
            target="EXECUTED",
            actor="0xowner",
        )
    first = store.transition(
        proposal_id=first.id,
        expected_revision=first.revision,
        target="EXECUTED",
        actor="0xowner",
        completion_bundle_id="0x" + "33" * 32,
    )
    assert first.completion_bundle_id == "0x" + "33" * 32

    second = store.get(second.id)
    second = store.transition(
        proposal_id=second.id,
        expected_revision=second.revision,
        target="ACTIVE",
        actor="0xowner",
        activation_bundle_id="0x" + "41" * 32,
        proposal_coin_id="0x" + "42" * 32,
    )
    assert second.state == "ACTIVE"


def test_execution_submission_is_durable_and_idempotent(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    value = _create(store, 12)
    value = store.transition(
        proposal_id=value.id,
        expected_revision=value.revision,
        target="READY",
        actor="0xreviewer",
    )
    value = store.transition(
        proposal_id=value.id,
        expected_revision=value.revision,
        target="ACTIVE",
        actor="0xowner",
        activation_bundle_id="0x" + "51" * 32,
        proposal_coin_id="0x" + "52" * 32,
    )
    outputs = ("0x" + "53" * 32, "0x" + "54" * 32)
    submitted = store.record_execution_submission(
        proposal_id=value.id,
        expected_revision=value.revision,
        execution_bundle_id="0x" + "55" * 32,
        expected_output_coin_ids=outputs,
        actor="0xexecutor",
        now=1_800_000_500,
    )
    assert submitted.execution_bundle_id == "0x" + "55" * 32
    assert submitted.expected_output_coin_ids == outputs
    assert submitted.execution_submitted_at == 1_800_000_500
    assert store.record_execution_submission(
        proposal_id=value.id,
        expected_revision=value.revision,
        execution_bundle_id="0x" + "55" * 32,
        expected_output_coin_ids=outputs,
        actor="0xexecutor",
    ) == submitted


def test_sale_offer_evidence_is_immutable_and_status_is_revisioned(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    value = _create(store, 13)
    value = store.transition(
        proposal_id=value.id,
        expected_revision=value.revision,
        target="READY",
        actor="0xreviewer",
    )
    value = store.transition(
        proposal_id=value.id,
        expected_revision=value.revision,
        target="ACTIVE",
        actor="0xowner",
        activation_bundle_id="0x" + "61" * 32,
        proposal_coin_id="0x" + "62" * 32,
    )
    available = store.record_sale_offer_snapshot(
        proposal_id=value.id,
        offer_id="0x" + "63" * 32,
        offer_bech32="offer1governed",
        sale_coin_id="0x" + "64" * 32,
        status="AVAILABLE",
        confirmed_height=100,
        spent_height=None,
        actor="chain-reconciler",
        now=1_800_000_600,
    )
    assert available.sale_offer_status == "AVAILABLE"
    assert _public(available)["saleOffer"]["offerFile"] == "offer1governed"
    assert "offerFile" not in _public(
        available, include_private_actor=False
    )["saleOffer"]
    assert store.record_sale_offer_snapshot(
        proposal_id=value.id,
        offer_id="0x" + "63" * 32,
        offer_bech32="offer1governed",
        sale_coin_id="0x" + "64" * 32,
        status="AVAILABLE",
        confirmed_height=100,
        spent_height=None,
        actor="chain-reconciler",
    ) == available
    taken = store.record_sale_offer_snapshot(
        proposal_id=value.id,
        offer_id="0x" + "63" * 32,
        offer_bech32="offer1governed",
        sale_coin_id="0x" + "64" * 32,
        status="TAKEN",
        confirmed_height=100,
        spent_height=120,
        actor="chain-reconciler",
    )
    assert taken.sale_offer_status == "TAKEN"
    assert taken.revision == available.revision + 1
    with pytest.raises(GovernanceQueueConflict, match="different immutable"):
        store.record_sale_offer_snapshot(
            proposal_id=value.id,
            offer_id="0x" + "65" * 32,
            offer_bech32="offer1changed",
            sale_coin_id="0x" + "64" * 32,
            status="TAKEN",
            confirmed_height=100,
            spent_height=120,
            actor="chain-reconciler",
        )


def test_stale_revision_and_duplicate_bill_fail_closed(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    value = _create(store, 5)
    with pytest.raises(GovernanceQueueConflict, match="already queued"):
        _create(store, 5)
    value = store.transition(
        proposal_id=value.id,
        expected_revision=value.revision,
        target="READY",
        actor="0xreviewer",
    )
    with pytest.raises(GovernanceQueueConflict, match="stale revision"):
        store.transition(
            proposal_id=value.id,
            expected_revision=1,
            target="CANCELED",
            actor="0xowner",
        )


def test_creator_cannot_self_review(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    value = _create(store, 9)
    with pytest.raises(GovernanceQueueConflict, match="different administrator"):
        store.transition(
            proposal_id=value.id,
            expected_revision=value.revision,
            target="READY",
            actor="0xOWNER",
        )


def test_public_queue_excludes_private_drafts_and_canceled_items(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    draft = _create(store, 6)
    ready = _create(store, 7)
    canceled = _create(store, 8)
    ready = store.transition(
        proposal_id=ready.id,
        expected_revision=ready.revision,
        target="READY",
        actor="0xreviewer",
    )
    store.transition(
        proposal_id=canceled.id,
        expected_revision=canceled.revision,
        target="CANCELED",
        actor="0xowner",
    )

    public_ids = {item.id for item in store.list(public=True)}
    assert ready.id in public_ids
    assert draft.id not in public_ids
    assert canceled.id not in public_ids


def test_public_view_redacts_private_admin_actor(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    value = _create(store, 10)
    assert _public(value)["createdBy"] == "0xowner"
    assert "createdBy" not in _public(value, include_private_actor=False)


def test_publication_approver_and_exact_signatures_are_immutable(tmp_path) -> None:
    store = GovernanceQueueStore(str(tmp_path / "governance.db"))
    value = _create(store, 11)
    value = store.transition(
        proposal_id=value.id,
        expected_revision=value.revision,
        target="READY",
        actor="0xreviewer",
    )
    prepared = store.bind_publication_coadmin(
        proposal_id=value.id,
        coadmin_slot=2,
        voting_deadline=1_800_086_500,
        actor="0xowner",
        now=1_800_000_100,
    )
    assert prepared.publication_coadmin_slot == 2
    assert prepared.publication_voting_deadline == 1_800_086_500
    with pytest.raises(GovernanceQueueConflict, match="already fixed"):
        store.bind_publication_coadmin(
            proposal_id=value.id,
            coadmin_slot=1,
            voting_deadline=1_800_086_500,
            actor="0xowner",
            now=1_800_000_101,
        )

    signature = store.add_signature(
        proposal_id=value.id,
        action_id="0x" + "41" * 32,
        signer_slot=0,
        signer_public_key="0x" + "02" + "42" * 32,
        message_hash="0x" + "43" * 32,
        signature="0x" + "44" * 64,
        actor="0xowner",
    )
    assert signature.signer_slot == 0
    assert store.add_signature(
        proposal_id=value.id,
        action_id=signature.action_id,
        signer_slot=0,
        signer_public_key=signature.signer_public_key,
        message_hash=signature.message_hash,
        signature=signature.signature,
        actor="0xowner",
    ) == signature
    with pytest.raises(GovernanceQueueConflict, match="different signature"):
        store.add_signature(
            proposal_id=value.id,
            action_id=signature.action_id,
            signer_slot=0,
            signer_public_key=signature.signer_public_key,
            message_hash=signature.message_hash,
            signature="0x" + "45" * 64,
            actor="0xowner",
        )


def test_publication_action_binds_coin_delegated_puzzle_and_proposal() -> None:
    private_key = keys.PrivateKey(b"\x31" * 32)
    identity = SimpleNamespace(
        daily_compressed_pubkey=private_key.public_key.to_compressed_bytes()
    )
    action = _action(
        slot=0,
        identity=identity,
        coin_id=bytes32(b"\x41" * 32),
        delegated_puzzle_hash=bytes32(b"\x42" * 32),
        proposal_hash=bytes32(b"\x43" * 32),
        voting_deadline=1_900_000_000,
    )
    signature = private_key.sign_msg_hash(
        bytes.fromhex(action.message_hash[2:])
    ).to_bytes()
    assert normalize_eip712_member_signature(
        signature=signature,
        digest=bytes.fromhex(action.message_hash[2:]),
        compressed_pubkey=identity.daily_compressed_pubkey,
    ) == signature[:64]
    altered = _action(
        slot=0,
        identity=identity,
        coin_id=bytes32(b"\x41" * 32),
        delegated_puzzle_hash=bytes32(b"\x44" * 32),
        proposal_hash=bytes32(b"\x45" * 32),
        voting_deadline=1_900_000_001,
    )
    assert altered.action_id != action.action_id
    assert altered.message_hash != action.message_hash


def test_publication_deadline_changes_signed_delegated_puzzle() -> None:
    proposal_hash = bytes32(b"\x46" * 32)
    first = _publication_delegated_puzzle(proposal_hash, 1_900_000_000)
    second = _publication_delegated_puzzle(proposal_hash, 1_900_000_001)

    assert first.get_tree_hash() != second.get_tree_hash()


def _coin_record(coin: Coin, *, confirmed: int, spent: int) -> dict:
    return {
        "coin": {
            "parent_coin_info": "0x" + coin.parent_coin_info.hex(),
            "puzzle_hash": "0x" + coin.puzzle_hash.hex(),
            "amount": int(coin.amount),
        },
        "confirmed_block_index": confirmed,
        "spent_block_index": spent,
    }


def _tracker_solution(dispatcher: int, params=None) -> dict:
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
    from solslot_puzzles.protocol_deployment import singleton_struct
    from solslot_puzzles.sgt_driver import proposal_tracker_inner_puzzle, TEST_KOS_MINT_EXECUTE_PUBKEY
    if params is None:
        params = []
    solution = Program.to(
        [[], 1, [bytes32(b"\x51" * 32), bytes32(b"\x52" * 32), 1, dispatcher, params]]
    )
    seed = bytes32(b"\x51" * 32)
    inner = proposal_tracker_inner_puzzle(singleton_struct(seed), seed, seed, seed, seed, seed,
        singleton_struct(seed), 5000, 300, 1_000_000, 10_000, TEST_KOS_MINT_EXECUTE_PUBKEY)
    return {"solution": "0x" + bytes(solution).hex(),
        "puzzle_reveal": "0x" + bytes(puzzle_for_singleton(seed, inner)).hex()}


class _TrackerProvider:
    def __init__(self, *, terminal: bool) -> None:
        self.initial = Coin(bytes32(b"\x61" * 32), bytes32(b"\x62" * 32), uint64(1))
        self.child = Coin(self.initial.name(), bytes32(b"\x63" * 32), uint64(1))
        self.terminal = terminal

    async def get_coin_record_by_name(self, coin_id: str):
        if coin_id == "0x" + self.initial.name().hex():
            return _coin_record(self.initial, confirmed=10, spent=11)
        if coin_id == "0x" + self.child.name().hex():
            return _coin_record(
                self.child,
                confirmed=12,
                spent=13 if self.terminal else 0,
            )
        return None

    async def get_puzzle_and_solution(self, coin_id: str, _height: int):
        if coin_id == "0x" + self.initial.name().hex():
            return _tracker_solution(TRK_VOTE)
        if coin_id == "0x" + self.child.name().hex() and self.terminal:
            return _tracker_solution(TRK_EXECUTE)
        return None

    async def get_coin_records_by_parent_ids(self, parent_ids, *, include_spent: bool):
        assert parent_ids == ["0x" + self.initial.name().hex()]
        assert include_spent is True
        return [
            _coin_record(
                self.child,
                confirmed=12,
                spent=13 if self.terminal else 0,
            )
        ]


@pytest.mark.asyncio
async def test_reconciler_follows_votes_to_the_live_tracker_coin() -> None:
    provider = _TrackerProvider(terminal=False)
    state = await _proposal_chain_state(
        provider,
        "0x" + provider.initial.name().hex(),
    )
    assert state == {
        "state": "VOTING",
        "confirmedHeight": 12,
        "currentCoinId": "0x" + provider.child.name().hex(),
    }


@pytest.mark.asyncio
async def test_reconciler_follows_votes_to_terminal_execution() -> None:
    provider = _TrackerProvider(terminal=True)
    state = await _proposal_chain_state(
        provider,
        "0x" + provider.initial.name().hex(),
    )
    assert state == {
        "state": "EXECUTED",
        "confirmedHeight": 13,
        "currentCoinId": "0x" + provider.child.name().hex(),
    }


class _ExecutionTrackerProvider:
    def __init__(self, bill: Program) -> None:
        self.bill = bill
        self.proposal_hash = bytes32(bill.get_tree_hash())
        self.parent = Coin(bytes32(b"\x70" * 32), bytes32(b"\x71" * 32), uint64(1))
        self.initial = Coin(self.parent.name(), bytes32(b"\x72" * 32), uint64(1))
        self.child = Coin(self.initial.name(), bytes32(b"\x73" * 32), uint64(1))

    async def get_coin_record_by_name(self, coin_id: str):
        if coin_id == "0x" + self.parent.name().hex():
            return _coin_record(self.parent, confirmed=8, spent=9)
        if coin_id == "0x" + self.initial.name().hex():
            return _coin_record(self.initial, confirmed=10, spent=11)
        if coin_id == "0x" + self.child.name().hex():
            return _coin_record(self.child, confirmed=12, spent=0)
        return None

    async def get_puzzle_and_solution(self, coin_id: str, _height: int):
        if coin_id == "0x" + self.parent.name().hex():
            return _tracker_solution(
                TRK_PROPOSE,
                [
                    self.proposal_hash,
                    self.bill,
                    bytes32(b"\x74" * 32),
                    400_000,
                    1_800_000_100,
                ],
            )
        if coin_id == "0x" + self.initial.name().hex():
            return _tracker_solution(
                TRK_VOTE,
                [bytes32(b"\x75" * 32), 100_000],
            )
        return None

    async def get_coin_records_by_parent_ids(self, parent_ids, *, include_spent: bool):
        assert parent_ids == ["0x" + self.initial.name().hex()]
        assert include_spent is True
        return [_coin_record(self.child, confirmed=12, spent=0)]


@pytest.mark.asyncio
async def test_execution_trace_reconstructs_quorum_after_multiple_votes() -> None:
    bill = Program.to([b"G", bytes32(b"\x76" * 32), 10_000])
    provider = _ExecutionTrackerProvider(bill)
    state = await trace_allocation_proposal(
        provider=provider,
        proposal_coin_id="0x" + provider.initial.name().hex(),
        proposal_hash=provider.proposal_hash,
        bill=bill,
        quorum_bps=5_000,
        total_supply=1_000_000,
        now=1_800_000_101,
    )
    assert state.state == "AWAITING_EXECUTE"
    assert state.current_coin == provider.child
    assert state.first_vote_amount == 400_000
    assert state.vote_tally == 500_000
    assert state.voting_deadline == 1_800_000_100


@pytest.mark.asyncio
async def test_execution_trace_rejects_a_different_queued_bill() -> None:
    bill = Program.to([b"G", bytes32(b"\x77" * 32), 10_000])
    provider = _ExecutionTrackerProvider(bill)
    with pytest.raises(ValueError, match="bill does not match"):
        await trace_allocation_proposal(
            provider=provider,
            proposal_coin_id="0x" + provider.initial.name().hex(),
            proposal_hash=provider.proposal_hash,
            bill=Program.to([b"G", bytes32(b"\x78" * 32), 10_000]),
            quorum_bps=5_000,
            total_supply=1_000_000,
            now=1_800_000_101,
        )


class _SaleOfferProvider:
    def __init__(self, allocation_coin: Coin, sale_coin: Coin, recipient_coin: Coin) -> None:
        self.allocation_coin = allocation_coin
        self.sale_coin = sale_coin
        self.recipient_coin = recipient_coin
        self.taken = False

    async def get_coin_record_by_name(self, coin_id: str):
        if coin_id == "0x" + self.allocation_coin.name().hex():
            return _coin_record(self.allocation_coin, confirmed=100, spent=100)
        if coin_id == "0x" + self.sale_coin.name().hex():
            return _coin_record(
                self.sale_coin,
                confirmed=100,
                spent=120 if self.taken else 0,
            )
        return None

    async def get_coin_records_by_parent_ids(self, parent_ids, *, include_spent: bool):
        assert parent_ids == ["0x" + self.sale_coin.name().hex()]
        assert include_spent is True
        return (
            [_coin_record(self.recipient_coin, confirmed=120, spent=0)]
            if self.taken
            else []
        )

    async def get_mempool_items_by_coin_name(self, coin_id: str):
        assert coin_id == "0x" + self.sale_coin.name().hex()
        return {}


@pytest.mark.asyncio
async def test_sale_offer_is_reconstructed_from_exact_confirmed_lineage(
    monkeypatch,
    tmp_path,
) -> None:
    tracker_launcher = bytes32(b"\x81" * 32)
    admin_launcher = bytes32(b"\x82" * 32)
    sgt_tail = bytes32(b"\x83" * 32)
    wusdc_b = bytes32(b"\x80" * 32)
    treasury = bytes32(b"\x84" * 32)
    recipient_launcher = bytes32(b"\x85" * 32)
    tracker_struct = singleton_struct(tracker_launcher)
    reserve_inner = sgt_reserve_inner_puzzle(
        proposal_tracker_struct=tracker_struct,
        admin_authority_struct=singleton_struct(admin_launcher),
        sgt_tail_hash=sgt_tail,
        wusdc_b_asset_id=wusdc_b,
        company_treasury_puzzle_hash=treasury,
    )
    reserve_owner = bytes32(reserve_inner.get_tree_hash())
    bill = bill_sgt_sale(
        sale_id=bytes32(b"\x86" * 32),
        sgt_amount=25_000,
        recipient_vault_launcher_id=recipient_launcher,
        payment_rail=int(SGTAllocationRail.XCH),
        payment_asset_id=bytes32.zeros,
        payment_amount=9_500_000,
        company_treasury_puzzle_hash=treasury,
        expires_at=1_900_000_000,
        reserve_owner_inner_puzzle_hash=reserve_owner,
    )
    terms = SGTSaleTermsV1(
        sale_id=bytes32(b"\x86" * 32),
        proposal_hash=proposal_hash_from_bill(bill),
        sgt_amount=25_000,
        recipient_vault_launcher_id=recipient_launcher,
        payment_rail=SGTAllocationRail.XCH,
        payment_asset_id=bytes32.zeros,
        payment_amount=9_500_000,
        company_treasury_puzzle_hash=treasury,
        expires_at=1_900_000_000,
        reserve_owner_inner_puzzle_hash=reserve_owner,
    )
    reserve_free = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        tracker_struct,
        reserve_owner,
    )
    allocation_coin = Coin(
        bytes32(b"\x87" * 32),
        bytes32(construct_cat_puzzle(CAT_MOD, sgt_tail, reserve_free).get_tree_hash()),
        uint64(25_000),
    )
    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=reserve_owner,
        sgt_tail_hash=sgt_tail,
        terms=terms,
    )
    sale_coin = Coin(
        allocation_coin.name(),
        bytes32(
            sgt_cat_puzzle(
                proposal_tracker_struct=tracker_struct,
                sgt_tail_hash=sgt_tail,
                owner_inner_puzzle=sale_inner,
            ).get_tree_hash()
        ),
        uint64(25_000),
    )
    recipient_free = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        tracker_struct,
        puzzle_hash_for_p2_vault(recipient_launcher),
    )
    recipient_coin = Coin(
        sale_coin.name(),
        bytes32(construct_cat_puzzle(CAT_MOD, sgt_tail, recipient_free).get_tree_hash()),
        uint64(25_000),
    )
    artifact = {
        "sgtTailHash": "0x" + sgt_tail.hex(),
        "genesisPlan": {
            "launcherIds": {
                "governance": "0x" + tracker_launcher.hex(),
                "adminAuthority": "0x" + admin_launcher.hex(),
            },
            "puzzleHashes": {"sgtReserveInner": "0x" + reserve_owner.hex()},
            "trustedAssets": {"wusdcBAssetId": "0x" + wusdc_b.hex()},
            "trustedDestinations": {
                "companySgtSaleTreasuryPuzzleHash": "0x" + treasury.hex()
            },
        },
    }

    async def evidence(_settings):
        return artifact, {}, None

    monkeypatch.setattr(
        "solslot_api.governance_sale_offer._verified_evidence_context",
        evidence,
    )
    store = GovernanceQueueStore(str(tmp_path / "sale-governance.db"))
    value = store.create(
        kind="SGT_SALE",
        title="Exact governed sale",
        bill={},
        bill_clvm_hex="0x" + bytes(bill).hex(),
        proposal_hash="0x" + proposal_hash_from_bill(bill).hex(),
        actor="0xowner",
    )
    value = store.transition(
        proposal_id=value.id,
        expected_revision=value.revision,
        target="READY",
        actor="0xreviewer",
    )
    value = store.transition(
        proposal_id=value.id,
        expected_revision=value.revision,
        target="ACTIVE",
        actor="0xowner",
        activation_bundle_id="0x" + "88" * 32,
        proposal_coin_id="0x" + "89" * 32,
    )
    value = store.record_execution_submission(
        proposal_id=value.id,
        expected_revision=value.revision,
        execution_bundle_id="0x" + "8a" * 32,
        expected_output_coin_ids=("0x" + sale_coin.name().hex(),),
        actor="0xowner",
    )
    provider = _SaleOfferProvider(allocation_coin, sale_coin, recipient_coin)
    available = await reconstruct_governed_sale_offer(
        record=value,
        provider=provider,
        settings=SimpleNamespace(),
        now=1_800_000_000,
    )
    assert available.status == "AVAILABLE"
    assert available.sale_coin_id == "0x" + sale_coin.name().hex()
    assert available.offer_bech32.startswith("offer1")

    provider.taken = True
    taken = await reconstruct_governed_sale_offer(
        record=value,
        provider=provider,
        settings=SimpleNamespace(),
        now=1_800_000_000,
    )
    assert taken.status == "TAKEN"
    assert taken.offer_id == available.offer_id
    assert taken.offer_bech32 == available.offer_bech32

    provider.recipient_coin = Coin(
        sale_coin.name(), bytes32(b"\x8b" * 32), uint64(25_000)
    )
    with pytest.raises(ValueError, match="no canonical settlement output"):
        await reconstruct_governed_sale_offer(
            record=value,
            provider=provider,
            settings=SimpleNamespace(),
            now=1_800_000_000,
        )
