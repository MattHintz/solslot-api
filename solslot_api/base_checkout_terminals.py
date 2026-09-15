"""Base terminal coordination: preserve quorum, then re-observe canonical Chia."""
import asyncio
from copy import deepcopy
import time
import uuid
from types import SimpleNamespace

from chia_rs import SpendBundle
from .base_inventory_hold import parse_base_hold
from .base_lifecycle_claims import BaseTerminalClaim, base_lifecycle_activation
from .checkout_terminals import observe_return, timeout, paid_output
from .inventory_extension_chain import current_position, verify_signature
from .inventory_extension_store import conflict
from .inventory_recovery import hx, release_peak, equivalent_timeout_spend, decode_spend
from .payment_start import verify_start_receipt
from .validator_base_terminal import terminal_context, verify_terminal_chain, bounded_terminal_payment
from .validator_inventory_extension import IndependentNode
from .validator_quorum import _collect_inventory_quorum, configured_validator_pubkeys

SCHEMA = 'solslot.base-checkout-terminal-evidence.v1'


class CoordinatorNode(IndependentNode):
    """Use the existing coordinator provider through the shared proof interface."""
    def __init__(self, provider):
        self.provider = provider

    async def call(self, method, body=None):
        body = body or {}
        if method == 'get_coin_record_by_name':
            value = dict(success=True, coin_record=await self.provider.get_coin_record_by_name(body['name']))
        elif method == 'get_puzzle_and_solution':
            value = dict(success=True, coin_solution=await self.provider.get_puzzle_and_solution(body['coin_id'], body['height']))
        else:
            value = await getattr(self.provider, method)()
        if not isinstance(value, dict) or value.get('success') is not True:
            raise conflict('Base terminal coordinator node evidence unavailable')
        return value


def validate_base_terminal_evidence(snapshot, evidence, artifact):
    try:
        stored, rows, _, _ = snapshot
        claim = BaseTerminalClaim.model_validate(evidence['claim'])
        terminal_context(claim, artifact, claim.activation['environment'])
        verify_start_receipt(claim, evidence['quorum'], artifact)
        position = current_position(stored, rows, artifact)
        if (evidence['schema'] != SCHEMA or evidence['network'] != 'testnet11'
                or stored.rail not in ('base_usdc', 'evm_usdc') or stored.purchase_artifact != claim.hold.purchase_artifact
                or evidence['purchaseId'] != stored.purchase_id or evidence['kind'] != claim.kind
                or claim.reserved_coin_id != hx(position.coin.name())
                or claim.reservation_expires_at != position.reservation.expires_at
                or claim.confirmation_height <= position.height
                or type(evidence['peakHeight']) is not int or evidence['peakHeight']-claim.confirmation_height+1 < 3
                or len(bytes.fromhex(evidence['peakHash'].removeprefix('0x'))) != 32):
            raise ValueError('Base terminal differs from the exact original inventory history')
        if claim.kind == 'RETURNED':
            returned = timeout(position)
            item, = evidence['items']
            if (item['ordinal'] != rows[0].ordinal or item['deedLauncherId'] != rows[0].deed_launcher_id
                    or item['reservedCoinId'] != claim.reserved_coin_id
                    or item['availableCoinId'] != claim.output_coin_id or claim.output_coin_id != hx(returned.next_coin.name())
                    or item['availablePuzzleHash'] != hx(returned.next_coin.puzzle_hash)
                    or item['confirmationHeight'] != claim.confirmation_height
                    or not equivalent_timeout_spend(decode_spend(item['releaseSpend'], position.coin), returned.spend)):
                raise ValueError('Base terminal return differs from its canonical successor')
        else:
            bundle = SpendBundle.from_json_dict(claim.spend_bundle)
            verify_signature(bundle, 'testnet11')
            if (sum(s.coin == position.coin for s in bundle.coin_spends) != 1
                    or hx(paid_output(position, bundle).name()) != claim.output_coin_id):
                raise ValueError('Base terminal delivery differs from its actual SmartDeed destination')
        if stored.external_message is not None:
            from .escrow_deposit import same_deposit_message
            if claim.payment_evidence is None or not same_deposit_message(stored.external_message, claim.payment_evidence):
                raise ValueError('Base terminal cannot erase or replace retained payment')
    except (KeyError, TypeError, ValueError, RuntimeError, IndexError) as exc:
        raise conflict('Base terminal evidence is incomplete or inconsistent') from exc


def base_terminal_status(store, purchase_id, artifact):
    evidence = store.checkout_terminal(purchase_id)
    if evidence is None:
        raise conflict('Base terminal evidence is missing')
    validate_base_terminal_evidence(store.inventory_status_snapshot(purchase_id), evidence, artifact)
    claim = BaseTerminalClaim.model_validate(evidence['claim'])
    held = store.base_checkout_hold(purchase_id)
    if (held is None or held['state'] != claim.kind or held['claim'] != claim.hold.model_dump(mode='json')
            or not store.checkout_admission_closed(purchase_id, claim.hold.activation)):
        raise conflict('Base terminal disagrees with retained checkout state')
    return dict(state=claim.kind, capacityReleased=True, terminalReceipt=evidence,
        confirmationAllowed=False, paymentRetryAllowed=False, inventoryReusable=False)


async def reconcile_base_terminal(*, store, node, settings, purchase_id, load_artifact,
                                  settlement=None, spend_bundle=None):
    artifact = deepcopy(load_artifact())
    cap = base_lifecycle_activation(artifact, settings.runtime_environment+'-alpha')
    if (settings.network != 'testnet11' or settings.zkpassport_validator_threshold != 2
            or [hx(k) for k in configured_validator_pubkeys(settings)] != artifact['validatorSet']['pubkeys']):
        raise conflict('Base terminal requires the exact reviewed coordinator roster')
    if store.checkout_terminal(purchase_id) is not None:
        return base_terminal_status(store, purchase_id, artifact)
    held = store.base_checkout_hold(purchase_id)
    if held is None:
        raise conflict('Base terminal has no original coordinator hold')
    hold = parse_base_hold(held['claim'])
    snapshot = store.inventory_status_snapshot(purchase_id)
    position = current_position(snapshot[0], snapshot[1], artifact)
    retained = store.base_terminal_attempt(purchase_id)
    if retained:
        claim = BaseTerminalClaim.model_validate(retained['claim'])
    else:
        if spend_bundle is None:
            _, height, returned, _ = await observe_return(node, position)
            kind, output = 'RETURNED', returned.next_coin
        else:
            bundle = SpendBundle.from_json_dict(spend_bundle)
            raw = await node.get_coin_record_by_name(hx(position.coin.name()))
            height = raw['spent_block_index']
            kind, output = 'DELIVERED', paid_output(position, bundle)
        claim = BaseTerminalClaim(network='testnet11', genesis_artifact_hash=artifact['artifactHash'], activation=cap,
            hold=hold, kind=kind, reserved_coin_id=hx(position.coin.name()), reservation_expires_at=position.reservation.expires_at,
            output_coin_id=hx(output.name()), confirmation_height=height, payment_evidence=snapshot[0].external_message,
            settlement=settlement, spend_bundle=spend_bundle)
        purchase, struct, terms = terminal_context(claim, artifact, settings.runtime_environment+'-alpha')
        await verify_terminal_chain(CoordinatorNode(node), claim, purchase, struct, terms)
        # Prove the hint through the reviewed route before it can pin an attempt;
        # independent validators repeat the proof before signing a tombstone.
        if settings.payment_evm_usdc_tokens.get(str(cap['chainId'])) != cap['token']:
            raise conflict('Base terminal token differs from the coordinator configuration')
        proof_settings = SimpleNamespace(network=settings.network, base_sepolia_spoke_address=cap['spoke'],
            base_sepolia_usdc_address=cap['token'], base_sepolia_min_confirmations=cap['minConfirmations'],
            base_sepolia_rpc_url=settings.payment_omnichain_rpc_url)
        await bounded_terminal_payment(proof_settings, claim)
        if load_artifact() != artifact:
            raise conflict('Base terminal release changed before claim retention')
        store.claim_base_terminal_attempt(purchase_id, claim, snapshot, held)
    owner = uuid.uuid4().hex
    store.claim_checkout_quorum(purchase_id, kind='return', owner=owner, now=int(time.time()))
    try:
        quorum = await asyncio.wait_for(_collect_inventory_quorum(settings, claim, '/v1/base-checkout/terminal'), 35)
        receipt = dict(claimHash=claim.canonical_hash(), signerIndices=list(quorum.signer_indices), signature=hx(quorum.aggregated_signature))
        verify_start_receipt(claim, receipt, artifact)
        if load_artifact() != artifact:
            raise conflict('Base terminal release changed during quorum')
        store.preserve_base_terminal_quorum(purchase_id, claim, receipt, artifact)
    finally:
        store.finish_checkout_quorum(purchase_id, owner=owner, now=int(time.time()))
    retained = store.base_terminal_attempt(purchase_id)
    claim = BaseTerminalClaim.model_validate(retained['claim'])
    purchase, struct, terms = terminal_context(claim, artifact, settings.runtime_environment+'-alpha')
    peak = await verify_terminal_chain(CoordinatorNode(node), claim, purchase, struct, terms)
    evidence = dict(schema=SCHEMA, kind=claim.kind, network='testnet11', purchaseId=purchase_id,
        claim=claim.model_dump(mode='json'), quorum=retained['quorum'], peakHeight=peak[0], peakHash=peak[1])
    if claim.kind == 'RETURNED':
        _, height, returned, spend = await observe_return(node, position)
        evidence['items'] = [dict(ordinal=snapshot[1][0].ordinal, deedLauncherId=snapshot[1][0].deed_launcher_id,
            reservedCoinId=claim.reserved_coin_id, availableCoinId=hx(returned.next_coin.name()),
            availablePuzzleHash=hx(returned.next_coin.puzzle_hash), confirmationHeight=height, releaseSpend=spend.to_json_dict())]
    if load_artifact() != artifact:
        raise conflict('Base terminal release changed during final observation')
    store.record_base_terminal(purchase_id, evidence, artifact, snapshot)
    return base_terminal_status(store, purchase_id, artifact)
