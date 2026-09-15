"""Base adapter for the existing durable renewal and independent terminal lanes."""
from copy import deepcopy
import time

from fastapi import HTTPException
from .base_inventory_hold_coordinator import base_checkout_status
from .base_lifecycle_claims import BasePaymentStartClaim, base_lifecycle_activation
from .base_checkout_terminals import reconcile_base_terminal, base_terminal_status
from .base_settlement_proof import settlement_hint
from .inventory_extension_chain import current_position
from .inventory_extensions import advance_extension
from .inventory_extension_store import conflict
from .payment_start import adopt_payment_start, verify_start_receipt
from .validator_base_terminal import bounded_terminal_rpc


async def advance_base_lifecycle(worker, purchase_id, lane):
    artifact = deepcopy(worker.load_artifact())
    cap = base_lifecycle_activation(artifact, worker.settings.runtime_environment+'-alpha')
    store = worker.store
    held = store.base_checkout_hold(purchase_id)
    if store.checkout_terminal(purchase_id):
        base_terminal_status(store, purchase_id, artifact)
        return 'COMPLETE', True
    base_checkout_status(held, artifact)
    args = dict(store=store, node=worker.node, settings=worker.settings, purchase_id=purchase_id, load_artifact=worker.load_artifact)
    stored = store.get(purchase_id)
    if lane == 'terminal':
        pending = store.base_terminal_attempt(purchase_id)
        if pending or stored.external_message is None:
            if not pending:
                # A live unspent reservation is an ordinary waiting state.
                position = current_position(stored, store.inventory_items(purchase_id), artifact)
                from .base_checkout_terminals import CoordinatorNode
                from .inventory_recovery import hx, record_coin
                node = CoordinatorNode(worker.node)
                raw, _ = await node.record(hx(position.coin.name()))
                _, spent = record_coin(raw, position.coin)
                if not spent:
                    return 'WAITING_FOR_CHAIN', False
            await reconcile_base_terminal(**args)
            return 'COMPLETE', True
        try:
            record = worker.presales.base_settlement_authorization_by_payment(held['claim']['global_payment_id'])
        except KeyError:
            return 'WAITING_FOR_ESCROW_PROOF', False
        if not record or not record.get('relayEvidence'):
            return 'WAITING_FOR_ESCROW_PROOF', False
        hint = await bounded_terminal_rpc(lambda: settlement_hint(rpc_url=worker.settings.payment_omnichain_rpc_url,
            transaction_hash=record['relayEvidence']['baseTransactionHash'], cap=cap,
            global_payment_id=held['claim']['global_payment_id']))
        bundle = None
        if record['authorization']['outcome'] == 'DELIVERED':
            voucher = worker.presales.voucher_for_purchase(purchase_id)
            if not voucher or voucher['state'] != 'REDEEMED' or voucher['paymentRail'] != 'BASE_SEPOLIA_USDC':
                raise conflict('Base terminal needs its actual current voucher delivery')
            execution = worker.presales.retained_voucher_execution(stored.purchase_artifact['presaleTermsHash'], voucher['serial'], 'base_redemption')
            if execution is None:
                raise conflict('Base delivery is missing its retained exact execution')
            bundle = execution['spendBundle']
        await reconcile_base_terminal(**args, settlement=hint, spend_bundle=bundle)
        return 'COMPLETE', True
    if held['state'] != 'ARMED':
        return 'REVIEW_REQUIRED', False
    if stored.external_message is None:
        return 'WAITING_FOR_PAYMENT', False
    retained = store.payment_start(purchase_id)
    if retained:
        start = BasePaymentStartClaim.model_validate(retained['claim'])
        verify_start_receipt(start, retained['receipt'], artifact)
        payment = start.payment()
    else:
        payment = await adopt_payment_start(store=store, settings=worker.settings, purchase_id=purchase_id,
            payment=dict(hold=held['claim'], payment_evidence=stored.external_message), load_artifact=worker.load_artifact)
    def authorize():
        if (not worker.settings.checkout_lifecycle_worker_enabled or not worker.settings.protocol_fee_funding_enabled
                or worker.submitter is None):
            raise HTTPException(status_code=503, detail='Reservation renewal is paused; the original payment is retained.')
        if base_lifecycle_activation(worker.load_artifact(), worker.settings.runtime_environment+'-alpha') != cap:
            raise conflict('Base lifecycle release changed before dispatch')
        worker.authorize()
    extension_args = dict(**args, submitter=worker.submitter, presales=worker.presales, payment=payment, authorize=authorize)
    await advance_extension(**extension_args, observe_only=True)
    stored = store.get(purchase_id)
    position = current_position(stored, store.inventory_items(purchase_id), artifact)
    if position.reservation.expires_at <= int(time.time()):
        return 'EXPIRED_REVIEW', False
    authorize()
    await advance_extension(**extension_args)
    return 'PAYMENT_HELD', False
