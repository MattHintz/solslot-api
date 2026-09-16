"""Unsigned API wire evidence, using synthetic confirmed state and no owner signing."""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from fastapi import HTTPException

from solslot_api.faucet import Faucet
from solslot_api import sols_swaps as swaps
from solslot_puzzles.sols_swap_v4_driver import UnsignedSolsSwapEvidence
from tests import test_sols_swaps as fixtures

pytestmark = pytest.mark.asyncio


def _coin(raw):
    assert type(raw['amount']) is str and str(int(raw['amount'])) == raw['amount']
    return Coin(bytes32.from_hexstr(raw['parentCoinInfo']), bytes32.from_hexstr(raw['puzzleHash']), int(raw['amount']))


@pytest.mark.parametrize('evm', [False, True])
@pytest.mark.parametrize('reverse', [False, True])
async def test_prepare_returns_lossless_complete_protocol_candidate_without_signing(monkeypatch, evm, reverse):
    faucet = Faucet.from_seed_hex('77' * 32, 'testnet11')
    context = fixtures._reverse_fixture(faucet, evm=evm) if reverse else fixtures._fixture(evm=evm).context
    async def load(**kwargs): return context
    monkeypatch.setattr(swaps, '_load_reverse_swap_context' if reverse else '_load_swap_context', load)
    monkeypatch.setattr(swaps, '_authorize_swap', lambda *_: None)
    submitter = fixtures.FakeProtocolSubmitter()
    request = fixtures._request(fixtures.FakeNode(), submitter, faucet)
    prepared = await swaps.prepare_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER),
        swaps.PrepareSolsSwapRequest(direction='DEED_TO_SOLS' if reverse else 'SOLS_TO_DEED',
            deedLauncherId=fixtures._hex32(fixtures.DEED_LAUNCHER)), request, fixtures._settings())
    raw = prepared.model_dump(by_alias=True)['unsignedProtocolEvidence']
    assert prepared.schema_version == 3
    assert raw['schemaVersion'] == 1
    assert raw['status'] == 'UNSIGNED_PROTOCOL_CANDIDATE'
    assert raw['network'] == 'testnet11' and raw['direction'] == prepared.direction
    assert raw['ownerAuthorization'] == raw['feeFunding'] == 'PENDING'
    assert raw['consensusValidated'] is False
    assert raw['expectedVaultSuccessor']['basis'] == 'PINNED_TEMPLATE_PENDING_AUTHORIZATION'
    assert len(raw['coinSpends']) == (7 if reverse else 6)
    spends = tuple(make_spend(_coin(item['coin']), Program.from_bytes(bytes.fromhex(item['puzzleReveal'][2:])),
        Program.from_bytes(bytes.fromhex(item['solution'][2:]))) for item in raw['coinSpends'])
    for item, spend in zip(raw['coinSpends'], spends):
        assert item['coinId'] == fixtures._hex32(spend.coin.name())
        assert spend.coin.puzzle_hash == Program.from_bytes(bytes(spend.puzzle_reveal)).get_tree_hash()
    successor = _coin(raw['expectedVaultSuccessor'])
    assert raw['expectedVaultSuccessor']['coinId'] == fixtures._hex32(successor.name())
    restored = UnsignedSolsSwapEvidence(raw['direction'], spends, tuple(x['role'] for x in raw['coinSpends']),
        bytes32.from_hexstr(raw['vaultCoinId']), successor, int(raw['requiredBackingMojos']))
    assert fixtures._hex32(restored.candidate_hash) == raw['protocolCandidateHash']
    assert restored.required_backing_mojos == (context.receipt.deed_to_sols_quote.fresh_sols_mojos_minted if reverse else 0)
    assert restored.vault_coin_id == context.vault_coin.name()
    assert len(prepared.signing_coin_spends) == (0 if evm else 1)
    assert (prepared.vault_typed_data is not None) == evm
    assert (prepared.buyer_offer is None) == (evm and reverse)
    assert submitter.submitted is None


async def test_prepare_rejects_changed_vault_before_recording_protocol_evidence(monkeypatch):
    context = fixtures._fixture(evm=True).context
    context = replace(context, vault_coin=Coin(context.vault_coin.parent_coin_info, bytes32(bytes([211])*32), 1))
    async def load(**kwargs): return context
    monkeypatch.setattr(swaps, '_load_swap_context', load)
    monkeypatch.setattr(swaps, '_authorize_swap', lambda *_: None)
    submitter = fixtures.FakeProtocolSubmitter()
    request = fixtures._request(fixtures.FakeNode(), submitter)
    with pytest.raises(HTTPException) as error:
        await swaps.prepare_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER),
            swaps.PrepareSolsSwapRequest(deedLauncherId=fixtures._hex32(fixtures.DEED_LAUNCHER)),
            request, fixtures._settings())
    assert error.value.status_code == 409
    assert submitter.submitted is None
    assert request.app.state.sols_swap_store.get(fixtures._hex32(context.receipt.operation_hash)) is None
