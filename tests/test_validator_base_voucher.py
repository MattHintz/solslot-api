"""Real voucher verifier/ledger with synthetic node snapshot and Base provider boundary.

The fixture starts with confirmed reserved inventory; it does not prove long
reservation creation, live RPC/provider verification, or a public-chain outcome.
"""
import json
from copy import deepcopy
from types import SimpleNamespace
import httpx
import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
from chia_rs import AugSchemeMPL, G2Element
from chia_rs.sized_ints import uint64
from solslot_api import validator_service as service
from solslot_api.validator_ledger import ValidatorLedger
from solslot_puzzles.stripe_settlement_v1_driver import make_inventory_available_inner
from solslot_puzzles.vault_driver import puzzle_for_vault_full, one_leaf_merkle_root
from tests.test_current_base_voucher_delivery import base_case, submit, hx, _b32
from tests.test_single_external_delivery_context import coin_record


async def signer_case(tmp_path, monkeypatch, inventory_version=2):
    c = base_case(tmp_path, monkeypatch, inventory_version)
    await submit(c)
    c.claim = c.voucher_claims[0]
    genesis = dict(c.genesis, validatorSet={"pubkeys":[hx(k.get_g1()) for k in c.keys]},
        launcherIds={**c.genesis['launcherIds'], 'pool':hx(_b32(27))},
        bridgePolicy={'policyHash':hx(_b32(26))})
    owner = bytes(c.keys[0].get_g1())
    vault_puzzle = puzzle_for_vault_full(c.purchase.vault_launcher_id, owner, 1,
        one_leaf_merkle_root(owner), _b32(27), identity_attest_root=c.purchase.zkpassport_root,
        zkpassport_bridge_policy_hash=_b32(26))
    vault_parent = Coin(c.purchase.vault_launcher_id, vault_puzzle.get_tree_hash(), uint64(1))
    vault = Coin(vault_parent.name(), vault_puzzle.get_tree_hash(), uint64(1))
    c.claim = c.claim.model_copy(update={'vault_coin_id':hx(vault.name())})
    c.records[hx(vault.name())] = coin_record(vault, confirmed=150)
    c.records[hx(vault_parent.name())] = coin_record(vault_parent, confirmed=149, spent=150)
    c.records[hx(c.available.name())] = coin_record(c.available, confirmed=123, spent=124)
    # Parent puzzle/lineage snapshots exercise the verifier's parsing. Their
    # historical creation is outside this fixture's transaction proof.
    parents = {
        hx(vault_parent.name()): make_spend(vault_parent, vault_puzzle, Program.to([])),
        hx(c.available.name()): make_spend(c.available, SINGLETON_MOD.curry(c.deed_struct,
            make_inventory_available_inner(c.terms)), Program.to([])),
    }
    for coin_id, record in c.records.items():
        if record['spent_block_index'] in (200, 201):
            try:
                raw = await c.worker.provider.get_puzzle_and_solution(coin_id, record['spent_block_index'])
                parents[coin_id] = raw
            except StopIteration:
                pass
    requests, provider_checks, key_reads = [], [], []
    def handler(request):
        requests.append(request.url.path)
        args = json.loads(request.content)
        if request.url.path == '/get_coin_record_by_name':
            result = {'coin_record': deepcopy(c.records.get(args['name']))}
        elif request.url.path == '/get_puzzle_and_solution':
            spend = parents[args['coin_id']]
            result = {'coin_solution':spend if isinstance(spend, dict) else spend.to_json_dict()}
        else:
            raise AssertionError(request.url.path)
        return httpx.Response(200, json=result)
    original = httpx.Client
    monkeypatch.setattr(httpx, 'Client', lambda **kw: original(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(service, 'load_validator_artifact', lambda _:(deepcopy(genesis), None))
    def private_key(_):
        key_reads.append(True)
        return c.keys[0]
    monkeypatch.setattr(service, 'load_validator_private_key', private_key)
    def provider(settings, evidence, *, purchase, voucher):
        provider_checks.append(deepcopy(evidence))
        assert purchase == c.purchase
        assert evidence == c.claim.payment_evidence
    monkeypatch.setattr(service, '_verify_base_voucher_payment', provider)
    c.signer_settings = SimpleNamespace(network='testnet11', claim_clock_skew_seconds=60,
        roster_pubkeys=genesis['validatorSet']['pubkeys'], coinset_base_url='https://validator-node.invalid')
    c.ledger = ValidatorLedger(tmp_path/'validator.db')
    c.requests, c.provider_checks, c.key_reads = requests, provider_checks, key_reads
    return c


def sign(c, claim=None):
    claim = claim or c.claim
    return service.sign_voucher_transition_claim(c.signer_settings, c.ledger, claim, claim.canonical_hash())


@pytest.mark.asyncio
@pytest.mark.parametrize('inventory_version',[1,2])
async def test_base_validator_reconstructs_current_reserved_delivery_and_recovers_signature(tmp_path,monkeypatch,inventory_version):
    c = await signer_case(tmp_path,monkeypatch,inventory_version)
    try:
        signature = sign(c)
        expected = AugSchemeMPL.aggregate([AugSchemeMPL.sign(c.keys[0], m) for m in c.claim.signature_messages()])
        assert signature == hx(expected)
        assert c.provider_checks and '/get_puzzle_and_solution' in c.requests
        c.ledger.close(); c.ledger = ValidatorLedger(tmp_path/'validator.db')
        assert sign(c) == signature
    finally:
        c.ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('problem',['expired','expiry_changed','deed','root','spent','parent','provider','offer'])
async def test_base_validator_rejects_invalid_evidence_before_key_access(tmp_path,monkeypatch,problem):
    c = await signer_case(tmp_path,monkeypatch)
    claim = c.claim
    if problem == 'expired': c.clock[0] = claim.reservation_expires_at
    elif problem == 'expiry_changed': claim = claim.model_copy(update={'reservation_expires_at':claim.reservation_expires_at+1})
    elif problem == 'deed': claim = claim.model_copy(update={'smart_deed_inner_hash':hx(_b32(96))})
    elif problem == 'root': claim = claim.model_copy(update={'vault_identity_attest_root':hx(_b32(96))})
    elif problem == 'spent': c.records[claim.deed_coin_id].update(spent=True,spent_block_index=300)
    elif problem == 'parent': c.records[hx(c.reserved.parent_coin_info)]['spent_block_index'] = 125
    elif problem == 'provider':
        def unavailable(*args, **kwargs): raise service.ValidatorEvidenceError('Base provider unavailable')
        monkeypatch.setattr(service,'_verify_base_voucher_payment',unavailable)
    elif problem == 'offer': claim = claim.model_copy(update={'buyer_offer':'offer1invalid'})
    try:
        with pytest.raises(service.ValidatorEvidenceError): sign(c,claim)
        assert c.key_reads == []
    finally:
        c.ledger.close()
