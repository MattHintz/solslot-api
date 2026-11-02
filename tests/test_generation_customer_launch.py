"""Synchronous native construction tests; no RPC, wallet or live funds."""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data

from solslot_puzzles import load_puzzle
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, one_leaf_merkle_root, puzzle_for_vault_inner
from solslot_api.faucet import Faucet
from solslot_api.singleton_launcher import launcher_coin_for_parent
from solslot_api.generation_customer_launch import (
    CustomerLaunchBindings, CustomerLaunchConsent, assemble_customer_launch,
)


def fixture(auth='chia_bls'):
    faucet = Faucet.from_seed_hex('42' * 32, 'testnet11')
    funding = Coin(bytes32(b'f' * 32), faucet.address_puzzle_hash, uint64(10000))
    bindings = CustomerLaunchBindings(bytes32(b'g' * 32), bytes32(b'm' * 32),
        bytes32(b'p' * 32), bytes32(b'b' * 32),
        load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash())
    secret = AugSchemeMPL.key_gen(b'k' * 32) if auth == 'chia_bls' else Account.from_key(b'e' * 32)
    owner = '0x' + bytes(secret.get_g1()).hex() if auth == 'chia_bls' else secret.address
    consent = CustomerLaunchConsent(bindings, bytes32(b'n' * 32), owner, auth,
        funding.name(), launcher_coin_for_parent(funding).name(), 1200)
    return faucet, funding, bindings, consent, secret


def sign(consent, secret):
    if consent.auth_type == 'evm':
        return '0x' + Account.sign_message(encode_typed_data(full_message=consent.typed_data()), secret.key).signature.hex()
    digest = bytes(Program.to(('Chia Signed Message', consent.bls_message())).get_tree_hash())
    return '0x' + bytes(AugSchemeMPL.sign(secret, digest)).hex()


def assemble(data, consent=None, signature=None, now=1000):
    faucet, funding, bindings, original, secret = data
    selected = consent or original
    return assemble_customer_launch(bindings=bindings, consent=selected,
        signature=signature or sign(selected, secret), funding_coin=funding,
        faucet=faucet, now=now)


@pytest.mark.parametrize('auth', ['chia_bls', 'evm'])
def test_fresh_generation_launch_preserves_exact_owner_and_destination(auth):
    data = fixture(auth)
    operation = assemble(data)
    _, funding, bindings, consent, _ = data
    tip, = operation.successors
    assert operation.kind == 'CREATE_CUSTOMER_VAULT'
    assert operation.generation == bindings.generation
    assert tip.launcher_id == consent.vault_launcher_id
    assert tip.coin.amount == 1
    assert len(operation.spends) == 2
    assert operation.spends[0].coin == funding
    assert operation.bundle().aggregated_signature != type(operation.bundle().aggregated_signature)()
    mod, args = tip.inner.uncurry()
    assert mod.get_tree_hash() == bindings.vault_module
    assert bytes(bindings.pool_launcher) in [v.atom for v in args.as_iter() if v.atom is not None]
    assert consent.message()['purpose'] == 'CREATE_FRESH_CUSTOMER_VAULT_REQUIRES_NEW_ID_CHECK'


@pytest.mark.parametrize('auth', ['chia_bls', 'evm'])
def test_old_generation_signature_cannot_authorize_new_generation(auth):
    data = fixture(auth)
    signature = sign(data[3], data[4])
    changed = replace(data[3], bindings=replace(data[2], generation=bytes32(b'x' * 32)))
    with pytest.raises(ValueError, match='another confirmed generation'):
        assemble(data, changed, signature)
    # Even if the service is separately bound to that other generation, the
    # exact same signature cannot recover the original owner there.
    with pytest.raises(ValueError, match='another owner'):
        changed.verified_owner(signature, 1000)


@pytest.mark.parametrize('field,value', [
    ('pool_launcher', bytes32(b'q' * 32)),
    ('bridge_policy', bytes32(b'c' * 32)),
    ('preparation_manifest', bytes32(b'd' * 32)),
])
def test_changed_pool_policy_or_preparation_requires_new_consent(field, value):
    data = fixture()
    changed = replace(data[3], bindings=replace(data[2], **{field: value}))
    with pytest.raises(ValueError, match='another confirmed generation'):
        assemble(data, changed, sign(data[3], data[4]))


def test_different_reserved_parent_is_never_silently_selected():
    data = fixture()
    changed = replace(data[3], funding_coin_id=bytes32(b'z' * 32))
    with pytest.raises(ValueError, match='reserved destination'):
        assemble(data, changed)


def test_expired_or_excessive_consent_is_rejected():
    data = fixture()
    with pytest.raises(ValueError, match='expired'):
        assemble(data, now=1200)
    with pytest.raises(ValueError, match='five-minute'):
        assemble(data, replace(data[3], expires_at=10000))


def test_old_custody_module_is_not_a_registration_option():
    data = fixture()
    old = replace(data[2], vault_module=load_puzzle('vault_singleton_inner.clsp').get_tree_hash())
    with pytest.raises(ValueError, match='reviewed generation custody'):
        old.validate()


def test_same_wallet_new_vault_is_not_the_legacy_native_puzzle():
    data = fixture()
    operation = assemble(data)
    tip, = operation.successors
    owner = bytes(data[4].get_g1())
    old = puzzle_for_vault_inner(tip.launcher_id, owner, AUTH_TYPE_BLS, one_leaf_merkle_root(owner),
        data[2].pool_launcher, zkpassport_bridge_policy_hash=data[2].bridge_policy)
    assert tip.coin.puzzle_hash != puzzle_for_singleton(tip.launcher_id, old).get_tree_hash()


def test_new_customer_operation_requires_its_scoped_review(tmp_path):
    from solslot_api.generation_operations import GenerationOperationJournal
    data=fixture()
    journal=GenerationOperationJournal(str(tmp_path/'operations.db'),'0x'+data[2].generation.hex())
    with pytest.raises(ValueError,match='complete exact creation review'):
        journal.prepare(assemble(data),'customer:no-review',100,1000)
    assert not journal.reserved_input_coin_ids()


@pytest.mark.parametrize('auth', ['chia_bls', 'evm'])
@pytest.mark.parametrize('field,value', [
    ('nonce', bytes32(b'v' * 32)),
    ('vault_launcher_id', bytes32(b'w' * 32)),
    ('expires_at', 1199),
])
def test_signed_nonce_destination_and_expiry_are_immutable(auth, field, value):
    data = fixture(auth)
    signature = sign(data[3], data[4])
    changed = replace(data[3], **{field: value})
    with pytest.raises(ValueError, match='another owner'):
        changed.verified_owner(signature, 1000)


def test_identity_bls_public_key_and_wrong_network_are_not_accepted():
    data = fixture()
    with pytest.raises(ValueError, match='nonidentity'):
        replace(data[3], owner='0x' + bytes(type(data[4].get_g1())()).hex()).validate()
    # This assembler exposes only the Testnet11 network. A request cannot
    # select another network through an unvalidated optional field.
    assert data[3].message()['network'] == 'testnet11'
