"""Fresh generation custody accepts only a new jointly authorized ID stamp.

Real consensus simulation with synthetic bridge validators. This is a native
compatibility test, not proof that live EVM/validator configuration is ready.
"""
from dataclasses import replace

import pytest
from chia._tests.util.spend_sim import SpendSim,SimClient
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs import AugSchemeMPL,Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data

from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.generation_vault_identity import build_generation_identity_bundle
from solslot_puzzles.vault_driver import one_leaf_merkle_root,eip712_typed_data_for_vault_spend,compact_signature_from_evm
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash
from solslot_api.generation_customer_launch import assemble_customer_launch
from solslot_api.singleton_launcher import launcher_coin_for_parent
from solslot_api.generation_customer_vault import trace_current_customer_vault,resolve_native_identity_vault
from tests.test_generation_customer_launch import fixture,sign


@pytest.mark.asyncio
@pytest.mark.parametrize('auth',['chia_bls','evm'])
async def test_native_fresh_generation_identity_stamp_preserves_owner_and_rejects_replay(auth):
    faucet,_,bindings,original,owner_secret=fixture(auth)
    validators=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (31,32,33)]
    keys=[bytes(key.get_g1()) for key in validators]
    policy=make_bridge_policy_hash(keys,2)
    bindings=replace(bindings,bridge_policy=policy)
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
        creation=assemble_customer_launch(bindings=bindings,consent=consent,signature=sign(consent,owner_secret),
            funding_coin=funding,faucet=faucet,now=1000)
        assert await client.push_tx(creation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        tip,=creation.successors
        owner,kind=consent.verified_owner(sign(consent,owner_secret),1000)
        class Primary:
            async def get_network_info_primary(self):return {'network_name':'testnet11'}
            async def get_coin_record_by_name_primary(self,value):
                record=await client.get_coin_record_by_name(bytes32.from_hexstr(value))
                return record.to_json_dict() if record else None
            async def get_puzzle_and_solution_primary(self,value,height):
                from chia_rs.sized_ints import uint32
                return (await client.get_puzzle_and_solution(bytes32.from_hexstr(value),uint32(height))).to_json_dict()
        trace_args=dict(bindings=bindings,launcher=tip.launcher_id,owner_pubkey=owner,
            auth_type=kind,initial_coin=tip.coin,provider=Primary())
        initial=await trace_current_customer_vault(**trace_args)
        assert not initial.identity_verified and initial.public()['identityStatus']=='FRESH_ID_REQUIRED'
        with pytest.raises(ValueError,match='FRESH_CHECK_REQUIRED'):
            await resolve_native_identity_vault(bindings=bindings,launcher=tip.launcher_id,provider=Primary())
        root=bytes32(b'i'*32);timestamp=int(sim.timestamp)
        compact=None
        if auth=='evm':
            typed=eip712_typed_data_for_vault_spend(b'z',root,tip.coin.name())
            signature='0x'+Account.sign_message(encode_typed_data(full_message=typed),owner_secret.key).signature.hex()
            compact=compact_signature_from_evm(signature)
        args=dict(bridge_parent_id=bridge.parent_coin_info,bridge_amount=1,validator_pubkeys=keys,
            threshold=2,signer_indices=[0,1],vault_coin=tip.coin,vault_launcher_id=tip.launcher_id,
            owner_pubkey_bytes=owner,auth_type=kind,members_merkle_root=one_leaf_merkle_root(owner),
            pool_launcher_id=bindings.pool_launcher,new_identity_attest_root=root,
            attestation_leaf_hash=bytes32(b'l'*32),scoped_nullifier=bytes32(b'n'*32),nullifier_type=1,
            service_scope_hash=bytes32(b's'*32),service_subscope_hash=bytes32(b'u'*32),
            proof_timestamp=timestamp,current_timestamp=timestamp,
            lineage_proof=LineageProof(parent_name=funding.name(),amount=uint64(1)),signature_data=compact)
        built=build_generation_identity_bundle(**args)
        sigs=[AugSchemeMPL.sign(validators[n],bytes(built.bridge.validator_message)+bridge.name()+faucet.agg_sig_me_data)
            for n in (0,1)]
        if auth=='chia_bls':
            message=bytes(Program.to([b'z',root,tip.coin.name()]).get_tree_hash())+tip.coin.name()+faucet.agg_sig_me_data
            sigs.append(AugSchemeMPL.sign(owner_secret,message))
        aggregate=AugSchemeMPL.aggregate(sigs)
        full=SpendBundle(list(built.spend_bundle.coin_spends),aggregate)
        # Private signers must independently prove the original unstamped
        # custody input and exact allowed bridge before authorizing a stamp.
        from tests.test_generation_customer_identity_context import profile
        from tests.test_generation_customer_identity_validators import current_claim
        from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile
        from solslot_api.generation_customer_identity_validators import verify_current_identity_vault
        from hashlib import sha256
        profile_data,_=profile()
        profile_data['bridgeCoins']=[{'parentId':'0x'+bridge.parent_coin_info.hex(),'coinId':'0x'+bridge.name().hex()}]
        pins=CurrentCustomerIdentityProfile.model_validate(profile_data).require_native(bindings)
        owner_authorization=signature if auth=='evm' else '0x'+bytes(sigs[-1]).hex()
        claim=current_claim(pins,vault_launcher_id='0x'+tip.launcher_id.hex(),
            current_vault_coin_id='0x'+tip.coin.name().hex(),owner_key=consent.owner,
            owner_auth_type=kind,owner_authorization=owner_authorization,
            owner_authorization_hash='0x'+sha256(bytes.fromhex(owner_authorization[2:])).hexdigest(),
            identity_attest_root='0x'+root.hex(),current_timestamp=timestamp,proof_timestamp=timestamp)
        proved_inputs=await verify_current_identity_vault(claim,bindings=bindings,profile=pins,provider=Primary())
        assert proved_inputs[1].coin==tip.coin and proved_inputs[2].coin==bridge
        with pytest.raises(ValueError):
            await verify_current_identity_vault(claim.model_copy(update={'identity_profile_hash':'0x'+'99'*32}),
                bindings=bindings,profile=pins,provider=Primary())
        # A missing bridge, one validator or a changed credential cannot
        # establish identity on this custody output.
        assert (await client.push_tx(SpendBundle([built.vault_spend],aggregate)))[0]!=MempoolInclusionStatus.SUCCESS
        insufficient=SpendBundle(list(full.coin_spends),AugSchemeMPL.aggregate(sigs[1:]))
        assert (await client.push_tx(insufficient))[0]!=MempoolInclusionStatus.SUCCESS
        wrong=build_generation_identity_bundle(**{**args,'new_identity_attest_root':bytes32(b'x'*32)})
        assert (await client.push_tx(SpendBundle(list(wrong.spend_bundle.coin_spends),aggregate)))[0]!=MempoolInclusionStatus.SUCCESS
        assert await client.push_tx(full)==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        inner=vault_inner(vault_launcher_id=tip.launcher_id,owner_pubkey=owner,auth_type=kind,
            members_merkle_root=one_leaf_merkle_root(owner),pool_launcher_id=bindings.pool_launcher,
            identity_attest_root=root,zkpassport_bridge_policy_hash=policy)
        expected=Coin(tip.coin.name(),puzzle_for_singleton(tip.launcher_id,inner).get_tree_hash(),uint64(1))
        confirmed=await client.get_coin_record_by_name(expected.name())
        assert confirmed is not None and not confirmed.spent and confirmed.confirmed_block_index>0
        with pytest.raises(ValueError):
            await verify_current_identity_vault(claim,bindings=bindings,profile=pins,provider=Primary())
        proved=await trace_current_customer_vault(**trace_args)
        assert proved.identity_verified and proved.root==root and proved.coin==expected
        assert proved.bridge_coin_id==bridge.name() and proved.stamp_coin_id==expected.name()
        independent=await resolve_native_identity_vault(bindings=bindings,launcher=tip.launcher_id,provider=Primary())
        assert independent.public()==proved.public()
        for invalid in ({'bindings':replace(bindings,pool_launcher=bytes32(b'X'*32))},
                {'bindings':replace(bindings,bridge_policy=bytes32(b'Y'*32))}):
            with pytest.raises(ValueError):await trace_current_customer_vault(**{**trace_args,**invalid})
        assert (await client.push_tx(full))[0]!=MempoolInclusionStatus.SUCCESS
