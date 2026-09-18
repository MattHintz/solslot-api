"""Customer redemption review, exact fee funding, and durable dispatch."""
from dataclasses import replace
from time import time

from chia.wallet.trading.offer import Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import Coin, G2Element, SpendBundle

from solslot_puzzles.funded_redemption_v1 import aggregate_direct_redemption, prepare_unsigned_direct_redemption
from solslot_puzzles.vault_v2_driver import eip712_typed_data_for_redemption_accept

from .chia_snapshot import PrimaryReadSnapshot
from .credential_auth import require_vault_record, verify_vault_session
from .protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError
from .redemption_review_store import RedemptionReviewStore
from .sols_swap_execution import execution_confirmation_height
from .sols_swap_funding import (digest, funding_identity, hx, normalize_vault, reserve_funding,
                               require_hold, submit_reserved_funding)
from .sols_swaps import _coin_spend_json, _funding_binding
from .vault_eligibility import require_current_approved_vault
from .wallet_offer_worker import run_offer_job


def review_store(request, settings):
    store = getattr(request.app.state, "redemption_review_store", None)
    if not isinstance(store, RedemptionReviewStore):
        store = RedemptionReviewStore(settings.admin_db_path)
        request.app.state.redemption_review_store = store
    submitter = getattr(request.app.state, "protocol_submitter", None)
    if isinstance(submitter, ProtocolBundleSubmitter):
        submitter.add_fee_coin_reservation_source(store.reserved_input_coin_ids)
        submitter.faucet.add_coin_reservation_source(store.reserved_input_coin_ids)
    return store


def allocation_view(context):
    p, a = context.plan, context.allocation
    return {"collectionId": hx(p.collection_id), "settlementId": hx(p.settlement_id),
        "deedLauncherId": hx(a.deed_launcher_id), "deedCommitment": hx(a.deed_commitment),
        "sharePpm": a.share_ppm, "paymentAssetId": hx(p.payment_asset_id),
        "paymentAmount": str(a.payment_amount), "totalPaymentAmount": str(p.total_payment_amount),
        "allocationRoot": hx(p.allocations_root), "allocationIndex": p.allocations.index(a)}


def terms_for(context, evidence):
    from solslot_puzzles.vault_driver import puzzle_for_p2_vault
    from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
    inner = puzzle_for_p2_vault(context.vault_record.launcher_id)
    recipient = construct_cat_puzzle(CAT_MOD, context.plan.payment_asset_id, inner).get_tree_hash()
    payouts = [coin for coin in evidence.outputs if coin.puzzle_hash == recipient and
               coin.amount == context.allocation.payment_amount]
    if len(payouts) != 1:
        raise ValueError("Exact redemption payout to the selected vault is missing")
    return {"vaultLauncherId": hx(context.vault_record.launcher_id), **allocation_view(context),
        "candidateHash": hx(evidence.candidate_hash), "fundingCoinId": hx(context.leaf_coin.name()),
        "expectedPaymentCoinId": hx(payouts[0].name()), "destinationPuzzleHash": hx(inner.get_tree_hash())}


def authority(request, settings, queue, context, terms):
    if (require_vault_record(hx(context.vault_record.launcher_id)) != context.vault_record
            or require_current_approved_vault(settings, hx(context.vault_record.launcher_id)) != context.approved_vault
            or queue.get(context.record.id) != context.record):
        raise ValueError("Redemption vault or governed allocation changed during review")
    return {**_funding_binding(request, settings, context), "action": "FUNDED_REDEMPTION",
            "allocationHash": digest(terms)}


async def prepare_review(vault, settlement, deed, request, settings, queue):
    from .funded_redemptions import _find_redemption, _redemption_context
    submitter = request.app.state.protocol_submitter
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise ProtocolSubmissionError("Protocol funding is unavailable before owner review")
    store = review_store(request, settings)
    async with PrimaryReadSnapshot(request.app.state.coinset, settings.network) as snapshot:
        record, allocation = _find_redemption(queue, settlement, deed)
        context = await _redemption_context(record=record, allocation=allocation, vault_launcher_id=vault,
            request=request, settings=settings, build_acceptance=True)
        evidence = prepare_unsigned_direct_redemption(maker_offer=context.maker_offer, acceptance=context.acceptance)
        terms = terms_for(context, evidence)
        operation = hx(evidence.operation_hash)
        expires = store.prepare(operation, terms, int(time()) + 300)
        authorize = lambda: authority(request, settings, queue, context, terms)
        binding = authorize()
        snapshot.recheck(authorize, binding)
        funding = await reserve_funding(submitter, store, evidence, binding, operation, expires, authorize)
        persistent = list(zip(evidence.roles[:3], [spend.coin for spend in evidence.coin_spends[:3]]))
        persistent.append(("fee", Coin.from_json_dict({"parent_coin_info": funding["fundingCoinSpend"]["coin"]["parentCoinInfo"],
            "puzzle_hash": funding["fundingCoinSpend"]["coin"]["puzzleHash"], "amount": int(funding["fundingCoinSpend"]["coin"]["amount"])})))
        observation = await snapshot.finish(persistent, {**binding, "operationHash": operation,
            "quoteExpiresAt": expires, "protocolCandidateHash": hx(evidence.candidate_hash),
            "fundingReservationHash": funding["reservationHash"]})
    is_bls = context.vault_record.auth_type == 1
    return {"schemaVersion": 2, "action": "FUNDED_REDEMPTION", **terms, "operationHash": operation,
        "reviewExpiresAt": expires, "allocation": allocation_view(context), "paymentSymbol": "wUSDC.b",
        "vaultAuthType": "chia_bls" if is_bls else "evm", "unsignedProtocolEvidence": evidence.to_json(),
        "currentStateEvidence": observation, "fundingEvidence": funding,
        "signingCoinSpends": [_coin_spend_json(context.acceptance.vault_spend)] if is_bls else [],
        "vaultTypedData": None if is_bls else eip712_typed_data_for_redemption_accept(evidence.operation_hash, evidence.vault_coin_id),
        "review": {"network": "testnet11", "action": "Redeem SmartDeed", "assetIn": "SmartDeed", "assetOut": "wUSDC.b",
            "amount": terms["paymentAmount"], "destination": terms["destinationPuzzleHash"],
            "permanentOffer": True, "reversibleAfterSubmission": False}}


async def complete_review(vault, settlement, deed, body, request, settings, queue):
    from .funded_redemptions import _find_redemption, _redemption_context
    store = review_store(request, settings)
    operation = body.operation_hash.lower()
    retained = store.get(operation)
    if retained is None:
        raise ValueError("Prepare exact redemption evidence before signing")
    if any(retained.terms[key] != value.lower() for key, value in
           (("vaultLauncherId", vault), ("settlementId", settlement), ("deedLauncherId", deed))):
        raise ValueError("Redemption belongs to different terms")
    submitter = request.app.state.protocol_submitter
    if not isinstance(submitter, ProtocolBundleSubmitter):
        raise ProtocolSubmissionError("Protocol funding is unavailable")
    if retained.transaction_id or (store.expired_execution(operation) is not None and retained.quote_expires_at <= time()):
        return await resume_execution(operation, request, settings, replay=True)
    async with PrimaryReadSnapshot(request.app.state.coinset, settings.network) as snapshot:
        record, allocation = _find_redemption(queue, settlement, deed)
        context = await _redemption_context(record=record, allocation=allocation, vault_launcher_id=vault,
            request=request, settings=settings, build_acceptance=True, owner_authorization=body.vault_owner_authorization)
        if context.vault_record.auth_type == 1:
            if body.aggregated_signature is None or body.vault_owner_authorization is not None:
                raise ValueError("Exact BLS redemption signature is required")
            signature = G2Element.from_bytes(bytes.fromhex(body.aggregated_signature.removeprefix("0x")))
        else:
            if body.vault_owner_authorization is None or body.aggregated_signature is not None:
                raise ValueError("Exact EVM redemption authorization is required")
            signature = G2Element()
        pending = replace(context.acceptance, vault_spend=normalize_vault(context.acceptance.vault_spend))
        evidence = prepare_unsigned_direct_redemption(maker_offer=context.maker_offer, acceptance=pending)
        terms = terms_for(context, evidence)
        if terms != retained.terms or hx(evidence.operation_hash) != operation:
            raise ValueError("Redemption no longer matches reviewed state")
        authorize = lambda: authority(request, settings, queue, context, terms)
        binding = authorize()
        snapshot.recheck(authorize, binding)
        identity = funding_identity(submitter, evidence, binding, operation, retained.quote_expires_at)
        require_hold(store, identity, body.funding_reservation_hash)
        taker = context.acceptance.taker_offer
        signed_taker = Offer(taker.requested_payments, WalletSpendBundle(taker.coin_spends(), signature), taker.driver_dict)
        bundle = aggregate_direct_redemption(maker_offer=context.maker_offer,
            acceptance=replace(context.acceptance, taker_offer=signed_taker)).to_valid_spend()
        await snapshot.finish(list(zip(evidence.roles[:3], [s.coin for s in evidence.coin_spends[:3]])),
                              {"quoteExpiresAt": retained.quote_expires_at})

    async def before_push(prepared):
        # Revalidate the complete signed consensus before retaining or sending it.
        await run_offer_job("swap_signature", bundle=WalletSpendBundle.from_bytes(bytes(prepared.bundle)), network=settings.network)
        async with PrimaryReadSnapshot(request.app.state.coinset, settings.network) as current:
            current.recheck(authorize, binding)
            await current.finish([*zip(evidence.roles[:3], [s.coin for s in evidence.coin_spends[:3]]),
                ("fee", next(s.coin for s in prepared.bundle.coin_spends if hx(s.coin.name()) == prepared.fee_coin_id))],
                {"quoteExpiresAt": retained.quote_expires_at})
        execution = {**prepared.to_json(), "network": settings.network,
            "feeTargetSeconds": identity["policy"]["target_seconds"], "fundingReservationHash": body.funding_reservation_hash}
        store.seal_execution(operation, execution, body.funding_reservation_hash)

    result = await submit_reserved_funding(submitter, store, evidence, identity, body.funding_reservation_hash,
                                          bundle, authorize, before_push)
    store.mark_submitted(operation, {key: result[key] for key in
        ("spendBundleId", "submissionProvider", "mempoolObservedAt")})
    return await resume_execution(operation, request, settings)


async def resume_execution(operation, request, settings, *, replay=False):
    store = review_store(request, settings)
    retained = store.get(operation)
    if retained is None:
        raise ValueError("No exact redemption execution is retained")
    verify_vault_session(settings, request, retained.terms["vaultLauncherId"])
    if retained.transaction_id is None:
        archive = store.expired_execution(operation)
        if archive is None:
            raise ValueError("No exact redemption execution is retained")
        return expired_view(archive)
    execution = store.execution(operation)
    bundle = SpendBundle.from_json_dict(execution["spendBundle"])
    node = request.app.state.coinset
    confirmed = await execution_confirmation_height(node, bundle, retained.terms["expectedPaymentCoinId"])
    if confirmed:
        store.mark_confirmed(operation, confirmed, execution["spendBundleId"])
    elif retained.confirmed_height:
        raise ValueError("Confirmed redemption requires chain reconciliation; keep the retained execution")
    elif replay:
        # Replay only the sealed bytes. A stale review never creates a new bundle.
        submitter = request.app.state.protocol_submitter
        if not isinstance(submitter, ProtocolBundleSubmitter):
            raise ProtocolSubmissionError("Protocol submission is unavailable")
        async with submitter.funding_guard:
            verify_vault_session(settings, request, retained.terms["vaultLauncherId"])
            current_execution = store.execution(operation)
            if current_execution is None or current_execution["spendBundleId"] != execution["spendBundleId"]:
                raise ValueError("The retained redemption attempt changed during recovery")
            if time() >= retained.quote_expires_at:
                # A local timeout is insufficient. Reconcile against a fresh,
                # unchanged primary tip and all persistent unspent inputs.
                additions = {coin.name() for coin in bundle.additions()}
                persistent = [(f"input_{i}", spend.coin) for i, spend in enumerate(bundle.coin_spends)
                              if spend.coin.name() not in additions]
                async with PrimaryReadSnapshot(node, settings.network) as snapshot:
                    if snapshot.transaction_time < retained.quote_expires_at:
                        raise ValueError("Wait for the primary chain clock to pass the saved fee deadline")
                    def authorized():
                        verify_vault_session(settings, request, retained.terms["vaultLauncherId"])
                        return True
                    snapshot.recheck(authorized, True)
                    observation = await snapshot.finish(persistent, {"operationHash": operation,
                        "spendBundleId": execution["spendBundleId"], "expiredAt": retained.quote_expires_at,
                        "quoteExpiresAt": int(time()) + 60})
                store.reconcile_expired(operation, execution["spendBundleId"], observation)
                return expired_view(store.expired_execution(operation))
            result = await submitter.provider.push_tx_confirmed_in_primary_mempool(bundle.to_json_dict(),
                required_coin_id=execution["feeCoinId"], required_spend_bundle_id=execution["spendBundleId"],
                timeout_seconds=submitter.policy.mempool_timeout_seconds, poll_seconds=submitter.policy.mempool_poll_seconds)
            store.mark_submitted(operation, {"spendBundleId": execution["spendBundleId"],
                "submissionProvider": result["provider"], "mempoolObservedAt": result["observed_at"]})
    retained = store.get(operation)
    receipt = retained.receipt or {}
    return {"operationHash": operation, **retained.terms, "paymentSymbol": "wUSDC.b",
        "status": "CONFIRMED" if retained.confirmed_height else "SUBMITTED" if receipt else "SUBMITTING",
        "transactionId": execution["spendBundleId"], "feeMojos": execution["feeMojos"],
        "feeTargetSeconds": execution["feeTargetSeconds"], "submissionProvider": receipt.get("submissionProvider"),
        "mempoolObservedAt": receipt.get("mempoolObservedAt"), "confirmedHeight": retained.confirmed_height,
        "updatedAt": int(time())}


def expired_view(archive):
    execution = archive["execution"]
    return {"operationHash": archive["operationHash"], **archive["terms"], "paymentSymbol": "wUSDC.b", "status": "EXPIRED",
        "transactionId": execution["spendBundleId"], "feeMojos": execution["feeMojos"],
        "feeTargetSeconds": execution["feeTargetSeconds"], "submissionProvider": None, "mempoolObservedAt": None,
        "confirmedHeight": None, "updatedAt": archive["observation"]["observedAt"]}
