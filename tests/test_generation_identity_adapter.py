"""Generation/legacy custody separation and thread-safe ID stamp continuation."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH,puzzle_for_singleton
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia_rs import Coin,AugSchemeMPL,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.vault_driver import one_leaf_merkle_root,puzzle_for_vault_full
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash
from solslot_api.zkpassport_enrollments import _custody_full,_custody_identity_bundle
from solslot_api.vault_puzzle_hash import puzzle_hash_for_vault_full
from solslot_api.stamp_funding import stamp_timestamp,continue_stamp
from solslot_api.faucet import AGG_SIG_ME_DATA


def h(n):return bytes32(bytes([n])*32)


@pytest.mark.parametrize('auth',[1,3])
def test_generation_api_hash_matches_native_custody_on_worker_threads(auth):
    if auth==1:owner=bytes(AugSchemeMPL.key_gen(bytes([1])*32).get_g1())
    else:
        from eth_keys import keys
        owner=keys.PrivateKey(bytes([1])*32).public_key.to_compressed_bytes()
    fields=(h(2),owner,auth,one_leaf_merkle_root(owner),h(3))
    options={'identity_attest_root':h(4),'zkpassport_bridge_policy_hash':h(5)}
    settings=SimpleNamespace(deployment_generation_id='0x'+h(6).hex())
    expected=_custody_full(settings,*fields,**options).get_tree_hash()
    legacy=puzzle_for_vault_full(*fields,**options).get_tree_hash()
    assert expected!=legacy
    with ThreadPoolExecutor(max_workers=4) as workers:
        hashes=list(workers.map(lambda _:puzzle_hash_for_vault_full(*fields,**options,generation_vault=True),range(16)))
    assert hashes==[expected]*16
    assert _custody_full(SimpleNamespace(deployment_generation_id=None),*fields,**options).get_tree_hash()==legacy


def test_generation_stamp_uses_same_bridge_and_preserves_signed_effects_on_retry():
    owner=AugSchemeMPL.key_gen(bytes([8])*32)
    validators=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (11,12,13)]
    public=tuple(bytes(k.get_g1()) for k in validators);policy=make_bridge_policy_hash(public,2)
    launcher_coin=Coin(h(9),SINGLETON_LAUNCHER_HASH,uint64(1));launcher=launcher_coin.name()
    inner=vault_inner(vault_launcher_id=launcher,owner_pubkey=bytes(owner.get_g1()),auth_type=1,
        members_merkle_root=one_leaf_merkle_root(bytes(owner.get_g1())),pool_launcher_id=h(10),zkpassport_bridge_policy_hash=policy)
    coin=Coin(launcher,puzzle_for_singleton(launcher,inner).get_tree_hash(),uint64(1));timestamp=1_800_000_000
    args=dict(bridge_parent_id=h(14),bridge_amount=1,validator_pubkeys=public,threshold=2,signer_indices=(0,1),
        vault_coin=coin,vault_launcher_id=launcher,owner_pubkey_bytes=bytes(owner.get_g1()),auth_type=1,
        members_merkle_root=one_leaf_merkle_root(bytes(owner.get_g1())),pool_launcher_id=h(10),new_identity_attest_root=h(15),
        attestation_leaf_hash=h(15),scoped_nullifier=h(16),nullifier_type=1,service_scope_hash=h(17),
        service_subscope_hash=h(18),proof_timestamp=timestamp,current_timestamp=timestamp,
        lineage_proof=LineageProof(h(9),None,uint64(1)))
    built=_custody_identity_bundle(SimpleNamespace(deployment_generation_id='0x'+h(6).hex()),**args)
    keys={bytes(k.get_g1()):k for k in [owner,*validators]};signatures=[]
    for spend in built.spend_bundle.coin_spends:
        cd=conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000)
        signatures.extend(AugSchemeMPL.sign(keys[bytes(pk)],message) for pk,message in
            pkm_pairs_for_conditions_dict(cd,spend.coin,AGG_SIG_ME_DATA['testnet11']))
    bundle=SpendBundle(built.spend_bundle.coin_spends,AugSchemeMPL.aggregate(signatures))
    assert stamp_timestamp(bundle,'0x'+coin.name().hex())==timestamp
    continued=continue_stamp(bundle,'0x'+coin.name().hex(),timestamp+30)
    assert continued.aggregated_signature==bundle.aggregated_signature
    assert continued.additions()==bundle.additions() and continued.removals()==bundle.removals()
    with pytest.raises(ValueError):
        _custody_identity_bundle(SimpleNamespace(deployment_generation_id='0x'+h(6).hex()),
            **{**args,'vault_coin':Coin(launcher,h(99),uint64(1))})
