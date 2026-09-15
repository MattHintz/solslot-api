"""Verify retained extension bytes and advance only proven singleton successors."""
from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program, INFINITE_COST
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from chia_rs import AugSchemeMPL, G2Element, SpendBundle

from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1, build_inventory_extension_spend, MAX_RESERVATION_EXTENSION_SECONDS,
)
from .faucet import AGG_SIG_ME_DATA
from .inventory_extension_claims import InventoryExtensionClaim, extension_activation
from .base_lifecycle_claims import parse_extension, BaseInventoryExtensionClaim, validate_base_start
from .inventory_recovery import timeout_items, hx, record_coin, decode_spend, release_peak
from .payment_purchase_store import PaymentPurchaseConflict
from .validator_inventory_extension import extension_coordinates


@dataclass(frozen=True)
class InventoryPosition:
    coin: object
    creation_spend: object
    reservation: object
    struct: object
    terms: object
    height: int


def verify_signature(bundle, network):
    keys, messages = [], []
    for spend in bundle.coin_spends:
        conditions = conditions_dict_for_solution(Program.from_bytes(bytes(spend.puzzle_reveal)),
            Program.from_bytes(bytes(spend.solution)), INFINITE_COST)
        pairs = pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA[network])
        keys.extend(pk for pk, _ in pairs); messages.extend(message for _, message in pairs)
    if not AugSchemeMPL.aggregate_verify(keys, messages, bundle.aggregated_signature):
        raise ValueError('retained bundle signature is invalid')


def transition_for(position, claim, indices):
    from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
    if (type(indices) not in (list, tuple) or len(indices) != 2
            or any(type(i) is not int for i in indices) or sorted(set(indices)) != list(indices)
            or any(i not in (0, 1, 2) for i in indices)
            or claim.purchase_artifact != purchase_artifact_v3_to_json(position.reservation.artifact)):
        raise ValueError('extension changes the original purchase or signer set')
    if (claim.reserved_coin_id != hx(position.coin.name())
            or claim.reserved_puzzle_hash != hx(position.coin.puzzle_hash)
            or claim.reservation_expires_at != position.reservation.expires_at
            or claim.next_expires_at != claim.reservation_expires_at + MAX_RESERVATION_EXTENSION_SECONDS):
        raise ValueError('extension is not the next bounded transition of this reservation')
    result = build_inventory_extension_spend(reserved_coin=position.coin, deed_singleton_struct=position.struct,
        lineage_proof=lineage_proof_for_coinsol(position.creation_spend), reservation=position.reservation,
        next_expires_at=claim.next_expires_at, signer_indices=indices, terms=position.terms)
    if claim.validator_message != hx(result.validator_message):
        raise ValueError('extension message differs from its actual spend')
    return result


def validate_execution(position, claim, operation):
    """Validate protocol and funded signatures, exact input/output and actual fee."""
    try:
        transition = transition_for(position, claim, operation['signerIndices'])
        protocol = SpendBundle.from_json_dict(operation['protocol'])
        if list(protocol.coin_spends) != [transition.spend]:
            raise ValueError('another protocol spend')
        verify_signature(protocol, claim.network)
        prepared = operation['prepared']
        if prepared is None:
            return transition, None
        bundle = SpendBundle.from_json_dict(prepared['spendBundle'])
        spends = bundle.coin_spends
        if (len(spends) != 2 or sum(s == transition.spend for s in spends) != 1
                or sum(hx(s.coin.name()) == prepared['feeCoinId'] for s in spends) != 1
                or prepared['feeCoinId'] == claim.reserved_coin_id
                or prepared['spendBundleId'] != hx(bundle.name())
                or type(prepared['feeMojos']) is not str or not prepared['feeMojos'].isdigit()
                or int(prepared['feeMojos']) <= 0):
            raise ValueError('another funded input or bundle')
        verify_signature(bundle, claim.network)
        additions = bundle.additions()
        if (sum(c == transition.next_coin for c in additions) != 1
                or sum(int(c.amount) for c in bundle.removals()) - sum(int(c.amount) for c in additions)
                != int(prepared['feeMojos'])):
            raise ValueError('another destination or fee')
        return transition, bundle
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise PaymentPurchaseConflict('retained extension execution is inconsistent') from exc


def current_position(stored, rows, artifact):
    """Original receipt is immutable; replay the bounded confirmed history separately."""
    try:
        history = getattr(stored, 'inventory_extension_receipts', ())
        if len(rows) != 1 or len(history) > 128 or stored.inventory_confirmation_height is None:
            raise ValueError('extension requires one confirmed original reservation')
        original, = timeout_items(SimpleNamespace(get=lambda _: stored, inventory_items=lambda _: rows), stored.purchase_id)
        # timeout_items reconstructs and verifies the original available->reserved commitments.
        from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json, purchase_artifact_v3_from_json
        original_purchase = purchase_artifact_v3_from_json(stored.purchase_artifact)
        _, outer = Program.from_bytes(bytes(original.reservation_spend.puzzle_reveal)).uncurry()
        _, inner_args = list(outer.as_iter())[1].uncurry()
        inner_hash = hx(list(inner_args.as_iter())[2].as_atom())
        coordinates = SimpleNamespace(purchase_artifact=purchase_artifact_v3_to_json(original_purchase), smart_deed_inner_hash=inner_hash)
        purchase, struct, terms = extension_coordinates(coordinates, artifact)
        verify_signature(SpendBundle.from_json_dict(stored.inventory_bundle), purchase.network)
        position = InventoryPosition(original.release_spend.coin, original.reservation_spend,
            InventoryReservationV1(purchase, stored.inventory_expires_at), struct, terms, stored.inventory_confirmation_height)
        for receipt in history:
            claim = parse_extension(receipt['claim'])
            binding = receipt['binding']
            if isinstance(claim, BaseInventoryExtensionClaim):
                validate_base_start(claim, artifact, claim.activation['environment'])
                active = claim.activation
            else:
                active = extension_activation(artifact, claim.activation['environment'])
            if (binding != dict(artifactHash=claim.genesis_artifact_hash, activation=claim.activation)
                    or claim.activation != active
                    or (not isinstance(claim, BaseInventoryExtensionClaim) and claim.genesis_artifact_hash != artifact['artifactHash'])
                    or claim.smart_deed_inner_hash != inner_hash):
                raise ValueError('retained extension deployment changed')
            transition, bundle = validate_execution(position, claim, receipt)
            evidence = receipt['confirmation']
            if (bundle is None or evidence['schema'] != 'solslot.inventory-extension-confirmation.v1'
                    or evidence['network'] != purchase.network
                    or evidence['sourceCoinId'] != hx(position.coin.name())
                    or evidence['reservedCoinId'] != hx(transition.next_coin.name())
                    or evidence['reservedPuzzleHash'] != hx(transition.next_coin.puzzle_hash)
                    or evidence['transactionId'] != hx(bundle.name())
                    or type(evidence['confirmationHeight']) is not int or evidence['confirmationHeight'] <= position.height
                    or type(evidence['peakHeight']) is not int or evidence['peakHeight'] - evidence['confirmationHeight'] + 1 < 3):
                raise ValueError('retained extension confirmation changed')
            position = InventoryPosition(transition.next_coin, transition.spend,
                InventoryReservationV1(purchase, claim.next_expires_at), struct, terms, evidence['confirmationHeight'])
        return position
    except (KeyError, IndexError, TypeError, ValueError, RuntimeError) as exc:
        raise PaymentPurchaseConflict('current reservation cannot be reconstructed from retained evidence') from exc


async def inspect_position(node, position, peak, *, require_unspent=True):
    created, spent = record_coin(await node.get_coin_record_by_name(hx(position.coin.name())), position.coin)
    if created != position.height or peak[0] - created + 1 < 3 or (require_unspent and spent):
        raise PaymentPurchaseConflict('current reservation is immature, changed or spent')
    parent = position.creation_spend
    _, parent_spent = record_coin(await node.get_coin_record_by_name(hx(parent.coin.name())), parent.coin)
    if (parent_spent != created or decode_spend(await node.get_puzzle_and_solution(hx(parent.coin.name()), parent_spent), parent.coin) != parent):
        raise PaymentPurchaseConflict('reservation creation is not its retained canonical spend')
    return spent


async def observe_extension(node, position, claim, operation):
    transition, bundle = validate_execution(position, claim, operation)
    if bundle is None:
        return None
    peak = await release_peak(node, claim.network)
    spent = await inspect_position(node, position, peak, require_unspent=False)
    if not spent:
        return None
    if peak[0] - spent + 1 < 3:
        return None
    for spend in bundle.coin_spends:
        record = await node.get_coin_record_by_name(hx(spend.coin.name()))
        if (not isinstance(record, dict) or record.get('coin') != spend.coin.to_json_dict()
                or type(record.get('spent_block_index')) is not int or record['spent_block_index'] != spent
                or record.get('spent') is not True
                or decode_spend(await node.get_puzzle_and_solution(hx(spend.coin.name()), spent), spend.coin) != spend):
            raise PaymentPurchaseConflict('extension source and fee did not confirm atomically as retained')
    created, _ = record_coin(await node.get_coin_record_by_name(hx(transition.next_coin.name())), transition.next_coin)
    if created != spent or await release_peak(node, claim.network) != peak:
        raise PaymentPurchaseConflict('extension successor is not atomically confirmed on a stable chain')
    return dict(schema='solslot.inventory-extension-confirmation.v1', network=claim.network,
        sourceCoinId=hx(position.coin.name()), reservedCoinId=hx(transition.next_coin.name()),
        reservedPuzzleHash=hx(transition.next_coin.puzzle_hash), transactionId=hx(bundle.name()),
        confirmationHeight=spent, peakHeight=peak[0], peakHash=peak[1])
