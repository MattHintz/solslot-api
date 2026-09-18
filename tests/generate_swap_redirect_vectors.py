"""Rebuild adversarial reverse swaps with real protocol builders, without signing/network.

Usage: python -m tests.generate_swap_redirect_vectors BASE_JSON OUTPUT_JSON
The original browser session/genesis context stays unchanged. Every unsigned
operation/offer/funding commitment is regenerated for another custody destination.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys

from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from solslot_api import sols_swaps as swaps
from solslot_api.faucet import Faucet
from solslot_api.sols_swap_funding import canonical, digest, funding_spend, public_spend
from solslot_puzzles.sols_pool_v4 import prepare_deed_to_sols
from solslot_puzzles.sols_swap_v4_driver import prepare_unsigned_deed_to_sols_swap
from tests import test_sols_swaps as fixtures


def redirected(base):
    evm = base['intent']['vaultAuthType'] == 'evm'
    context = fixtures._reverse_fixture(Faucet.from_seed_hex('77' * 32, 'testnet11'), evm=evm)
    intent = deepcopy(base['intent'])
    assert fixtures._hex32(context.vault_coin.name()) == intent['unsignedProtocolEvidence']['vaultCoinId']
    receipt = context.receipt
    receipt = prepare_deed_to_sols(pool_coin_id=context.pool_coin.name(), state=context.pool_state,
        inventory=context.pool_inventory, deed_launcher_id=receipt.record.deed_launcher_id,
        custody_coin_id=receipt.record.custody_coin_id, deed_commitment=receipt.record.deed_commitment,
        collection=context.collection, share_ppm=receipt.record.share_ppm, parameters=context.statutes.parameters,
        statutes_state=context.statutes.state, pause=None, vault_launcher_id=context.vault_record.launcher_id,
        vault_coin_id=context.vault_coin.name(), seller_sols_puzzle_hash=bytes32(b'\xab' * 32),
        quote_expires_at=intent['quoteExpiresAt'])
    context = replace(context, receipt=receipt)
    evidence = prepare_unsigned_deed_to_sols_swap(**swaps._reverse_protocol_offer_arguments(context))
    intent['unsignedProtocolEvidence'] = swaps._unsigned_protocol_evidence_json(evidence, 'testnet11')
    intent['operationHash'] = fixtures._hex32(receipt.operation_hash)
    intent['destinationPuzzleHash'] = fixtures._hex32(receipt.counterparty_puzzle_hash)
    intent['review']['destinationPuzzleHash'] = intent['destinationPuzzleHash']
    if evm:
        intent['vaultTypedData'] = swaps._vault_swap_typed_data(context)
    else:
        offer = swaps._build_reverse_protocol_offer(context, signature_data=None)
        intent['signingCoinSpends'] = [swaps._coin_spend_json(offer.vault_spend)]
        intent['buyerOffer'] = offer.offer.to_bech32()
    funding = intent['fundingEvidence']
    raw = funding['fundingCoinSpend']['coin']
    coin = Coin(bytes32.from_hexstr(raw['parentCoinInfo']), bytes32.from_hexstr(raw['puzzleHash']), int(raw['amount']))
    submitter = fixtures.FakeProtocolSubmitter()
    spend, _ = funding_spend(submitter, evidence, coin, int(funding['feeMojos']), intent['quoteExpiresAt'])
    funding.update(operationHash=intent['operationHash'], protocolCandidateHash=fixtures._hex32(evidence.candidate_hash),
        fundingCoinSpend=public_spend(spend))
    funding.pop('reservationHash')
    funding.pop('reservationReviewJson', None)
    encoded = canonical(funding)
    funding['reservationHash'] = digest(funding)
    funding['reservationReviewJson'] = encoded
    return {**deepcopy(base), 'intent':intent}


if __name__ == '__main__':
    source, target = map(Path, sys.argv[1:])
    base = json.loads(source.read_text())
    output = {**base, 'vectors':[redirected(v) for v in base['vectors'] if v['intent']['direction'] == 'DEED_TO_SOLS']}
    target.write_text(json.dumps(output, sort_keys=True, separators=(',', ':')) + '\n')
    print(f'Generated {len(output["vectors"])} reconstructed redirect vectors; no owner signing or network.')
