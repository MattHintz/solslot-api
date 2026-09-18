"""Real signed Stripe refund builders through the shared fee/handoff boundary."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia_rs import Coin, SpendBundle, validate_clvm_and_signature, MEMPOOL_MODE, ENABLE_SECP_OPS, ENABLE_KECCAK_OPS_OUTSIDE_GUARD
from chia_rs.sized_bytes import bytes32

from solslot_api.faucet import Faucet, AGG_SIG_ME_DATA
from solslot_api.protocol_submission import ProtocolSubmissionError
from solslot_api.stripe_voucher_execution import prepare_and_dispatch_stripe_terminal, resume_stripe_terminal
from tests.test_protocol_submission import FakeProvider, submitter, b32


def fixture():
    return json.loads((Path(__file__).parent / 'fixtures/stripe-refund-fee.json').read_text())


class Store:
    execution = None

    def bind_stripe_terminal_execution(self, terms_hash, serial, execution):
        self.execution = deepcopy(execution)

    def voucher(self, terms_hash, serial):
        return {'terminalExactExecution': self.execution}


class Executor:
    def __init__(self, store):
        self.store, self.calls = store, []

    async def dispatch(self, request, prepared):
        assert self.store.execution['prepared'] == prepared.to_json()
        validate_clvm_and_signature(prepared.bundle, 11_000_000_000,
            DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32(AGG_SIG_ME_DATA['testnet11'])),
            MEMPOOL_MODE | ENABLE_SECP_OPS | ENABLE_KECCAK_OPS_OUTSIDE_GUARD)
        self.calls.append(prepared)
        return {'accepted': True}


async def execute(data, *, fee=7):
    faucet = Faucet.from_seed_hex('01' * 32, 'testnet11')
    fee_coin = Coin(b32(49), faucet.address_puzzle_hash, 100)
    provider = FakeProvider(fee_coin=fee_coin, aggregate_fee=fee)
    store = Store()
    executor = Executor(store)
    result = await prepare_and_dispatch_stripe_terminal(store=store,
        submitter=submitter(provider, faucet), exact_executor=executor,
        terms_hash=data['termsHash'], serial=data['serial'], mode='REFUND_OWNER', voucher_action=1,
        purchase_id=bytes32.from_hexstr(data['purchaseId']), artifact_hash=bytes32.from_hexstr(data['artifactHash']),
        claim_hash=b32(50), signer_indices=(0,1), protocol_bundle=SpendBundle.from_json_dict(data['spendBundle']),
        expected_outputs={k: Coin.from_json_dict(v) for k,v in data['outputs'].items()}, bindings=data['bindings'])
    return result, executor, fee_coin


@pytest.mark.asyncio
@pytest.mark.parametrize('fee', [1, 7, 100])
async def test_signed_refund_receipt_burn_counts_toward_capped_total_fee_and_exact_recovery(fee):
    data = fixture()
    (execution, _), executor, fee_coin = await execute(data, fee=fee)
    prepared = executor.calls[0]
    assert prepared.fee_mojos == fee
    assert sum(c.amount for c in prepared.bundle.removals()) - sum(c.amount for c in prepared.bundle.additions()) == fee
    change = [c for c in prepared.bundle.additions() if c.parent_coin_info == fee_coin.name()]
    assert sum(c.amount for c in change) == fee_coin.amount - (fee - 1)
    assert len(prepared.bundle.coin_spends) == 5
    await resume_stripe_terminal(exact_executor=executor, execution=execution,
        expected_purchase_id=bytes32.from_hexstr(data['purchaseId']), expected_artifact_hash=bytes32.from_hexstr(data['artifactHash']))
    assert bytes(executor.calls[0].bundle) == bytes(executor.calls[1].bundle)


@pytest.mark.asyncio
async def test_unrequested_existing_fee_still_rejected():
    data = fixture()
    faucet = Faucet.from_seed_hex('01' * 32, 'testnet11')
    provider = FakeProvider(fee_coin=Coin(b32(49), faucet.address_puzzle_hash, 100))
    with pytest.raises(ProtocolSubmissionError, match='separate user-funded fee'):
        await submitter(provider, faucet).submit(data['spendBundle'])


@pytest.mark.asyncio
@pytest.mark.parametrize('field', ['purchaseId','artifactHash','termsHash'])
async def test_receipt_cannot_be_relabelled_as_another_refund(field):
    data = fixture()
    data[field] = '0x'+'fe'*32
    with pytest.raises(ProtocolSubmissionError, match='receipt binding'):
        await execute(data)


@pytest.mark.asyncio
async def test_total_fee_above_cap_is_rejected_even_with_receipt_credit():
    with pytest.raises(ProtocolSubmissionError, match='cap'):
        await execute(fixture(), fee=101)


@pytest.mark.asyncio
@pytest.mark.parametrize('extra', [1,2])
async def test_receipt_credit_does_not_allow_an_extra_fee_input(extra):
    from chia.types.blockchain_format.program import Program
    from chia.types.coin_spend import make_spend
    from chia_rs import G2Element
    data = fixture()
    puzzle = Program.to((1, []))
    extra_bundle = SpendBundle([make_spend(Coin(b32(99), puzzle.get_tree_hash(), extra), puzzle, Program.to([]))], G2Element())
    data['spendBundle'] = SpendBundle.aggregate([SpendBundle.from_json_dict(data['spendBundle']),extra_bundle]).to_json_dict()
    with pytest.raises(ProtocolSubmissionError, match='separate user-funded fee'):
        await execute(data)
