"""Synthetic consensus proof for EVM identity re-clock, not a live recovery."""
from dataclasses import replace
import pytest
from chia._tests.util.spend_sim import SpendSim,SimClient
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL,Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data
from solslot_api.generation_customer_launch import assemble_customer_launch
from solslot_api.generation_customer_vault import trace_current_customer_vault
from solslot_api.singleton_launcher import launcher_coin_for_parent
from solslot_puzzles.generation_vault_identity import build_generation_identity_bundle
from solslot_puzzles.vault_driver import one_leaf_merkle_root,eip712_typed_data_for_vault_spend,compact_signature_from_evm
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash
from tests.test_generation_customer_launch import fixture,sign


@pytest.mark.asyncio
async def test_native_evm_stamp_reclock_reuses_exact_owner_and_two_validator_signatures():
    faucet,_,bindings,original,owner_secret=fixture('evm')
    validators=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (31,32,33)]
    keys=[bytes(key.get_g1()) for key in validators]
    policy=make_bridge_policy_hash(keys,2);bindings=replace(bindings,bridge_policy=policy)
    constants=DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=faucet.agg_sig_me_data)
    async with SpendSim.managed(None,defaults=constants) as sim:
        client=SimClient(sim);acs=Program.to(1)
        for _ in range(3):await sim.farm_block(acs.get_tree_hash())
        origins=[r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())]
        funding=Coin(origins[0].name(),faucet.address_puzzle_hash,uint64(10000))
        bridge=Coin(origins[1].name(),policy,uint64(1))
        setup=[make_spend(origin,acs,Program.to([[51,output.puzzle_hash,int(output.amount)],
            [51,acs.get_tree_hash(),int(origin.amount)-int(output.amount)]]))
            for origin,output in zip(origins,(funding,bridge))]
        assert await client.push_tx(SpendBundle(setup,G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        consent=replace(original,bindings=bindings,funding_coin_id=funding.name(),
            vault_launcher_id=launcher_coin_for_parent(funding).name())
        consent_sig=sign(consent,owner_secret)
        creation=assemble_customer_launch(bindings=bindings,consent=consent,signature=consent_sig,
            funding_coin=funding,faucet=faucet,now=1000)
        assert await client.push_tx(creation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block();tip,=creation.successors
        owner,kind=consent.verified_owner(consent_sig,1000)
        root=bytes32(b'i'*32);old_time=int(sim.timestamp)
        typed=eip712_typed_data_for_vault_spend(b'z',root,tip.coin.name())
        evm_sig='0x'+Account.sign_message(encode_typed_data(full_message=typed),owner_secret.key).signature.hex()
        compact=compact_signature_from_evm(evm_sig)
        args=dict(bridge_parent_id=bridge.parent_coin_info,bridge_amount=1,validator_pubkeys=keys,
            threshold=2,signer_indices=[1,2],vault_coin=tip.coin,vault_launcher_id=tip.launcher_id,
            owner_pubkey_bytes=owner,auth_type=kind,members_merkle_root=one_leaf_merkle_root(owner),
            pool_launcher_id=bindings.pool_launcher,new_identity_attest_root=root,
            attestation_leaf_hash=bytes32(b'l'*32),scoped_nullifier=bytes32(b'n'*32),nullifier_type=1,
            service_scope_hash=bytes32(b's'*32),service_subscope_hash=bytes32(b'u'*32),
            proof_timestamp=old_time,current_timestamp=old_time,
            lineage_proof=LineageProof(parent_name=funding.name(),amount=uint64(1)),signature_data=compact)
        old=build_generation_identity_bundle(**args)
        message=bytes(old.bridge.validator_message)+bridge.name()+faucet.agg_sig_me_data
        retained=AugSchemeMPL.aggregate([AugSchemeMPL.sign(validators[i],message) for i in (1,2)])
        sim.pass_time(uint64(180));await sim.farm_block()
        assert (await client.push_tx(SpendBundle(list(old.spend_bundle.coin_spends),retained)))[0]!=MempoolInclusionStatus.SUCCESS
        fresh=build_generation_identity_bundle(**{**args,'current_timestamp':int(sim.timestamp)})
        assert fresh.bridge.validator_message==old.bridge.validator_message
        altered=build_generation_identity_bundle(**{**args,'current_timestamp':int(sim.timestamp),
            'new_identity_attest_root':bytes32(b'x'*32)})
        assert (await client.push_tx(SpendBundle(list(altered.spend_bundle.coin_spends),retained)))[0]!=MempoolInclusionStatus.SUCCESS
        bundle=SpendBundle(list(fresh.spend_bundle.coin_spends),retained)
        assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        class Primary:
            async def get_network_info_primary(self):return {'network_name':'testnet11'}
            async def get_coin_record_by_name_primary(self,value):
                row=await client.get_coin_record_by_name(bytes32.from_hexstr(value))
                return row.to_json_dict() if row else None
            async def get_puzzle_and_solution_primary(self,value,height):
                from chia_rs.sized_ints import uint32
                return (await client.get_puzzle_and_solution(bytes32.from_hexstr(value),uint32(height))).to_json_dict()
        confirmed=await trace_current_customer_vault(bindings=bindings,launcher=tip.launcher_id,
            owner_pubkey=owner,auth_type=kind,initial_coin=tip.coin,provider=Primary())
        assert confirmed.identity_verified and confirmed.root==root
        assert (await client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
