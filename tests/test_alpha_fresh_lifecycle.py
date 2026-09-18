"""Farming -> selected genesis -> launch -> permit enrollment, with no injected coins.

Synthetic wallets and validator attestations, not live issuer/provider acceptance.
Both swap directions and governed inventory remain a separate outstanding segment.
"""
from types import SimpleNamespace
import pytest
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys
from solslot_api.faucet import Faucet, AGG_SIG_ME_DATA
from solslot_api.vault_launcher import build_and_sign_launch
from solslot_puzzles import load_puzzle
from solslot_puzzles.genesis_ceremony_rc23 import (RC23GenesisFundingCoins,
    build_rc23_genesis_ceremony_plan, build_rc23_genesis_ceremony_bundle)
from solslot_puzzles.enrollment_activation import activation_context, enrollment_release_identity
from solslot_puzzles.enrollment_permit import EnrollmentPermit, permit_owner_from_native
from solslot_puzzles.enrollment_permit_driver import make_permit_bridge_puzzle
from solslot_puzzles.zkpassport_attestation import ZkPassportAttestation, compute_attestation_root
from solslot_puzzles.zkpassport_bridge_driver import build_bridge_and_vault_update_identity_bundle
from solslot_puzzles.vault_driver import one_leaf_merkle_root, puzzle_for_vault_full, signing_message_for_vault_spend

B = lambda n: bytes32(bytes([n])*32)
HX = lambda value: '0x'+bytes(value).hex()
CONSTANTS = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32(AGG_SIG_ME_DATA['testnet11']))

async def include(sim, client, bundle):
    status, error = await client.push_tx(bundle)
    assert status is MempoolInclusionStatus.SUCCESS, error
    await sim.farm_block()
    for spend in bundle.coin_spends:
        record = await client.get_coin_record_by_name(spend.coin.name())
        assert record and record.spent
    for coin in bundle.additions():
        assert await client.get_coin_record_by_name(coin.name()) is not None


def sign_spends(spends, private_keys):
    by_pk = {bytes(sk.get_g1()):sk for sk in private_keys}
    signatures = []
    for spend in spends:
        conditions = conditions_dict_for_solution(Program.from_bytes(bytes(spend.puzzle_reveal)),
            Program.from_bytes(bytes(spend.solution)), 11_000_000_000)
        for pk, message in pkm_pairs_for_conditions_dict(conditions, spend.coin, AGG_SIG_ME_DATA['testnet11']):
            assert bytes(pk) in by_pk, 'unexpected required signer'
            signatures.append(AugSchemeMPL.sign(by_pk[bytes(pk)], message))
    return SpendBundle(spends, AugSchemeMPL.aggregate(signatures))


async def fresh_genesis(sim, client):
    faucet = Faucet.from_seed_hex('b1'*32, 'testnet11')
    await sim.farm_block()
    sim.pass_time(uint64(1_900_000_000))
    for _ in range(7): await sim.farm_block(faucet.address_puzzle_hash)
    origins = sorted([r.coin for r in await client.get_coin_records_by_puzzle_hash(
        faucet.address_puzzle_hash, include_spent_coins=False)], key=lambda c:c.name())
    funding = []
    for origin, amount in zip(origins, (1_000_100,2,100,100,100,100,16,100,530)):
        conditions = Program.to([[51,faucet.address_puzzle_hash,amount],
            [51,faucet.address_puzzle_hash,int(origin.amount)-amount]])
        spend = make_spend(origin, faucet.key.puzzle, Program.to([0,(1,conditions),0]))
        bundle = SpendBundle([spend], G2Element.from_bytes(faucet.sign_delegated_spend(origin,conditions)))
        await include(sim,client,bundle)
        funding.append(next(c for c in bundle.additions() if c.amount==amount))
    funding = RC23GenesisFundingCoins(*funding)
    validators = tuple(AugSchemeMPL.key_gen(bytes([i])*32) for i in (71,72,73))
    pubkeys = tuple(bytes(sk.get_g1()) for sk in validators)
    admins = tuple(keys.PrivateKey(bytes([i])*32).public_key.to_compressed_bytes() for i in (61,62,63))
    recovery = tuple(AugSchemeMPL.key_gen(bytes([i])*32) for i in (81,82,83))
    sources = {key:str(i)*40 for i,key in enumerate(('protocol','api','customerWeb','evm','omnichain',
        'legacyBackend','keyOfSolomon','samuel','adminPortal'),1)}
    addresses = {key:HX(bytes([i])*20) for key,i in [('forwarder',21),('verifierAdapter',22),('attestationEmitter',23)]}
    activation = dict(schema='solslot.enrollment-activation.v1',environment='production-alpha',network='testnet11',
        evmChainId=84532,deploymentId=HX(B(31)),sourceShas=sources,releaseIdentity=enrollment_release_identity(sources),
        emitter=addresses['attestationEmitter'],issuer='0x7e5f4552091a69125d5dfcb7b8c2659029395bdf',
        issuerKeyRef='https://solslot-test.vault.azure.net/keys/permit-test/'+'ab'*16,
        issuerIdentityClientId='12345678-1234-1234-1234-123456789abc',permitVersion=1,adapterVersion=1,
        validatorMessageVersion=1,bridgeModuleHash=HX(load_puzzle('zkpassport_bridge_permit_v1.clsp').get_tree_hash()),
        permitLifetimeSeconds=900,reviewEvidenceSha256='cd'*32)
    context = activation_context(activation)
    activation.update(contextHash=HX(context.context_hash),bridgePolicyHash=HX(make_permit_bridge_puzzle(pubkeys,context.context_hash).get_tree_hash()))
    plan = build_rc23_genesis_ceremony_plan(ceremony_id=B(31),expires_at=int(sim.timestamp)+3600,source_shas=sources,
        evm_addresses=addresses,funding=funding.ids(),faucet_puzzle_hash=faucet.address_puzzle_hash,
        governance_bls_pubkey=bytes(validators[0].get_g1()),kos_mint_execute_pubkey=bytes(validators[1].get_g1()),
        admin_compressed_pubkeys=admins,admin_recovery_bls_pubkeys=[bytes(sk.get_g1()) for sk in recovery],
        admin_recovery_evm_guardians=[HX(bytes([i])*20) for i in (41,42,43)],admin_recovery_revisions=(1,1,1),
        admin_recovery_drill_hashes=(B(51),B(52),B(53)),validator_pubkeys=pubkeys,
        trusted_treasury_reserve_puzzle_hash=faucet.address_puzzle_hash,trusted_protocol_treasury_puzzle_hash=B(91),
        company_sgt_sale_treasury_puzzle_hash=B(92),wusdc_b_asset_id=B(93),
        trusted_governance_rewards_puzzle_hash=B(94),trusted_governance_rewards_root=B(95),retired_coordinates=(),
        enrollment_activation=activation,evm_chain_id=84532)
    built = build_rc23_genesis_ceremony_bundle(plan=plan,faucet=faucet,funding_coins=funding)
    await include(sim,client,built.spend_bundle)
    for coin in plan.bridge_batch.bridge_coins:
        record = await client.get_coin_record_by_name(coin.name())
        assert record and not record.spent
    return SimpleNamespace(faucet=faucet,plan=plan,built=built,validators=validators,context=context,origins=origins[9:])


async def launch_and_enroll(world,sim,client,auth_type):
    owner = AugSchemeMPL.key_gen(b'o'*32)
    evm = keys.PrivateKey(b'e'*32)
    owner_key = bytes(owner.get_g1()) if auth_type==1 else evm.public_key.to_compressed_bytes()
    permit_key = owner_key if auth_type==1 else evm.public_key.to_canonical_address()
    policy = world.plan.bridge_batch.policy_hash
    launch = build_and_sign_launch(faucet=world.faucet,faucet_coin_json=world.origins[0].to_json_dict(),
        owner_pubkey=owner_key,auth_type=auth_type,pool_launcher_id=world.plan.protocol.pool_launcher_id,
        zkpassport_bridge_policy_hash=policy)
    await include(sim,client,launch.spend_bundle)
    vault = next(c for c in launch.spend_bundle.additions() if c.parent_coin_info==launch.vault_launcher_id)
    launcher = next(s.coin for s in launch.spend_bundle.coin_spends if s.coin.name()==launch.vault_launcher_id)
    bridge = world.plan.bridge_batch.bridge_coins[0]
    now = int(sim.timestamp)
    attestation = ZkPassportAttestation(launch.vault_launcher_id,B(111),1,B(112),B(113),now)
    root = compute_attestation_root([attestation.leaf_hash])
    kind,owner_hash = permit_owner_from_native(auth_type,permit_key)
    permit = EnrollmentPermit(B(114),world.context.context_hash,launch.vault_launcher_id,vault.name(),
        kind,owner_hash,bridge.name(),now,now+900)
    signature = None
    if auth_type==3:
        sig = evm.sign_msg_hash(signing_message_for_vault_spend(b'z',root,vault.name()))
        signature = sig.r.to_bytes(32,'big')+sig.s.to_bytes(32,'big')
    built = build_bridge_and_vault_update_identity_bundle(bridge_parent_id=bridge.parent_coin_info,bridge_amount=int(bridge.amount),
        validator_pubkeys=world.plan.validator_pubkeys,threshold=2,signer_indices=[0,1],vault_coin=vault,
        vault_launcher_id=launch.vault_launcher_id,owner_pubkey_bytes=owner_key,auth_type=auth_type,
        members_merkle_root=one_leaf_merkle_root(owner_key),pool_launcher_id=world.plan.protocol.pool_launcher_id,
        new_identity_attest_root=root,attestation_leaf_hash=attestation.leaf_hash,scoped_nullifier=attestation.scoped_nullifier,
        nullifier_type=1,service_scope_hash=attestation.service_scope_hash,service_subscope_hash=attestation.service_subscope_hash,
        proof_timestamp=now,current_timestamp=now,lineage_proof=LineageProof(parent_name=launcher.parent_coin_info,amount=uint64(1)),
        signature_data=signature,enrollment_permit=permit)
    signed = sign_spends(built.spend_bundle.coin_spends,[owner,*world.validators])
    await include(sim,client,signed)
    full = puzzle_for_vault_full(launch.vault_launcher_id,owner_key,auth_type,one_leaf_merkle_root(owner_key),
        world.plan.protocol.pool_launcher_id,identity_attest_root=root,zkpassport_bridge_policy_hash=policy)
    successor = Coin(vault.name(),full.get_tree_hash(),1)
    record = await client.get_coin_record_by_name(successor.name())
    assert record and not record.spent
    assert (await client.get_coin_record_by_name(bridge.name())).spent
    assert (await SimClient(sim).get_coin_record_by_name(successor.name())).coin==successor
    return SimpleNamespace(vault=successor,full=full,owner=owner,evm=evm,owner_key=owner_key,
        auth_type=auth_type,launcher_id=launch.vault_launcher_id,root=root,enrollment=signed)


@pytest.mark.asyncio
@pytest.mark.parametrize('auth_type',[1,3],ids=['bls','evm'])
async def test_farmed_genesis_launch_enrollment_and_successor(auth_type):
    async with SpendSim.managed(None,defaults=CONSTANTS) as sim:
        client = SimClient(sim)
        world = await fresh_genesis(sim,client)
        await launch_and_enroll(world,sim,client,auth_type)
