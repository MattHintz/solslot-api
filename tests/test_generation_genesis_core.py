"""Actual standard-p2 funding, recovery authority and conserved native genesis.

All keys/coins/documents are synthetic. This exercises only the core assembler;
there is deliberately no whole-generation launch endpoint or pool placeholder.
"""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest
import pytest_asyncio
from chia._tests.util.spend_sim import SpendSim, SimClient
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api.faucet import Faucet
from solslot_api.generation_genesis_core import (CORE_FUNDING_NAMES, GenerationCoreArtifact,
    genesis_core_funding_requests, assemble_genesis_core)
from solslot_api.generation_preparation import GenerationPreparation
from solslot_api.generation_recipient_evidence import verify_recipient_custody
from solslot_api.generation_recipient_launch import build_recipient_launch
from solslot_api.generation_chain_evidence import resolve_generation_chain
from solslot_api.generation_index import load_generation_read_anchor
from solslot_api.generation_operations import GenerationOperationJournal
from solslot_puzzles.admin_authority_v3_driver import parse_inner_puzzle
from tests.test_generation_preparation import manifest, bind_custody, bind_identities, signatures, b32
from tests.test_generation_recipient_evidence import Primary


def standard_spend(faucet, coin, conditions):
    return make_spend(coin, faucet.key.puzzle, Program.to([0, Program.to((1, conditions)), 0]))


@pytest_asyncio.fixture
async def core():
    faucet = Faucet.from_seed_hex('04'*32, 'testnet11')
    constants = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=faucet.agg_sig_me_data)
    async with SpendSim.managed(None, defaults=constants) as sim:
        client, acs = SimClient(sim), Program.to(1)
        for _ in range(6): await sim.farm_block(acs.get_tree_hash())
        origins = [r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())]
        parents, spends = [], []
        for i, origin in enumerate(origins[:11]):
            amount = 2_000_000+i
            parents.append(Coin(origin.name(), faucet.address_puzzle_hash, uint64(amount)))
            spends.append(make_spend(origin, acs, Program.to([[51, faucet.address_puzzle_hash, amount],
                [51, acs.get_tree_hash(), int(origin.amount)-amount]])))
        assert await client.push_tx(SpendBundle(spends, G2Element())) == (MempoolInclusionStatus.SUCCESS, None)
        await sim.farm_block()
        prep, accounts = manifest(); raw = prep.model_dump(mode='json', by_alias=True)
        def reserve(coin):
            return {'fundingCoinId': '0x'+coin.name().hex(),
                    'launcherId': '0x'+Coin(coin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name().hex()}
        for i, name in enumerate(sorted(raw['coordinates'])): raw['coordinates'][name] = reserve(parents[i])
        for i, admin in enumerate(raw['administrators']): admin['custody'] = reserve(parents[7+i])
        raw['sgtFundingCoinId'] = '0x'+parents[10].name().hex()
        bind_identities(raw); bind_custody(raw); prep = GenerationPreparation.model_validate(raw)
        spends, sigs = [], []
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import launch_conditions_and_coinsol
        for admin in prep.administrators:
            coin = next(c for c in parents if '0x'+c.name().hex() == admin.custody.funding_coin_id)
            conditions, _ = launch_conditions_and_coinsol(coin, prep.custody_inner(admin), [], uint64(1))
            conditions.append(Program.to([51, coin.puzzle_hash, int(coin.amount)-1]))
            conditions = Program.to(conditions)
            funding = standard_spend(faucet, coin, conditions)
            operation = build_recipient_launch(prep, admin.slot, funding, trusted_preparation_hash=prep.manifest_hash)
            spends.extend(operation.spends)
            sigs.append(G2Element.from_bytes(faucet.sign_delegated_spend(coin, conditions, purpose='genesis')))
        assert await client.push_tx(SpendBundle(spends, AugSchemeMPL.aggregate(sigs))) == (MempoolInclusionStatus.SUCCESS, None)
        await sim.farm_block()
        provider = Primary(client)
        evidence = await verify_recipient_custody(prep, signatures(prep, accounts),
            trusted_preparation_hash=prep.manifest_hash, provider=provider)
        artifact = GenerationCoreArtifact.model_validate(dict(generationId=prep.generation_id,
            preparationManifest=prep.manifest_hash,
            dailyPublicKeys=[a.custody_owner_public_key for a in prep.administrators],
            recoveryPublicKeys=['0x'+bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()).hex() for n in (21,22,23)],
            treasuryPuzzleHash=b32(61), protocolPuzzleHash=b32(62),
            priceOraclePublicKeys=['0x'+bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()).hex() for n in (41,42,43)],
            deliveryValidatorPublicKeys=['0x'+bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()).hex() for n in (31,32,33)],
            deliveryProviderId=b32(63)))
        funding = {name: next(c for c in parents if '0x'+c.name().hex() == (prep.sgt_funding_coin_id if name == 'sgt'
                  else prep.coordinates[name].funding_coin_id)) for name in CORE_FUNDING_NAMES}
        yield SimpleNamespace(faucet=faucet, sim=sim, client=client, provider=provider,
            prep=prep, artifact=artifact, evidence=evidence, funding=funding, parents=parents)


def requests(c, **overrides):
    args = dict(preparation=c.prep, artifact=c.artifact, evidence=c.evidence, funding_coins=c.funding,
        trusted_preparation_hash=c.prep.manifest_hash, trusted_artifact_hash=c.artifact.artifact_hash)
    args.update(overrides)
    return genesis_core_funding_requests(**args)


def assembly(c, **overrides):
    funding, signatures = {}, []
    for request in requests(c):
        funding[request.name] = standard_spend(c.faucet, request.coin, request.conditions)
        signatures.append(G2Element.from_bytes(c.faucet.sign_delegated_spend(request.coin, request.conditions, purpose='genesis')))
    args = dict(preparation=c.prep, artifact=c.artifact, evidence=c.evidence, funding_spends=funding,
        trusted_preparation_hash=c.prep.manifest_hash, trusted_artifact_hash=c.artifact.artifact_hash,
        aggregated_signature=AugSchemeMPL.aggregate(signatures))
    args.update(overrides)
    return assemble_genesis_core(**args)


@pytest.mark.asyncio
async def test_core_launches_real_recovery_authority_exact_grants_and_readable_chain(core, tmp_path):
    c = core; built = assembly(c); bundle = built.operation.bundle()
    again = assembly(c)
    assert bundle == again.operation.bundle() and built.review() == again.review()
    assert built.issuance.holdings.root == again.issuance.holdings.root
    view = built.review()
    assert not view['launchComplete'] and 'POOL_AND_ECONOMIC_BINDINGS' in view['remainingAssembly']
    assert view['supply'] == dict(total=1000000, distributed=30000, reserve=970000, quorum=15000)
    assert view['exchangeFees'] == dict(totalBps=100, protocolBps=70, sgtRewardsBps=30)
    parsed = parse_inner_puzzle(built.authority.inner_puzzle)
    assert parsed.authority_puzzle_version == 4
    assert parsed.source_manifest_hash == bytes32.from_hexstr(c.artifact.artifact_hash)
    assert await c.client.push_tx(bundle) == (MempoolInclusionStatus.SUCCESS, None)
    await c.sim.farm_block()
    chain = await resolve_generation_chain(built.anchor, provider=c.provider)
    assert chain.public_status(123)['supply']['nextProposalQuorum'] == 15000
    assert chain.public_status(123)['exchangeFees']['protocolBps'] == 70
    assert [coin.amount for coin in built.issuance.coins] == [10000,10000,10000,970000]
    for coin in built.operation.auxiliary_outputs:
        assert not (await c.client.get_coin_record_by_name(coin.name())).spent
    for tip in built.operation.successors:
        assert not (await c.client.get_coin_record_by_name(tip.coin.name())).spent
    pool = next(coin for coin in c.parents if '0x'+coin.name().hex() == c.prep.coordinates['pool'].funding_coin_id)
    assert not (await c.client.get_coin_record_by_name(pool.name())).spent
    assert (await c.client.push_tx(bundle))[0] == MempoolInclusionStatus.FAILED
    # Use the same original state artifact as the persisted production reader.
    import json
    from hashlib import sha256
    prep_file = tmp_path/'prep.json'; prep_file.write_text(c.prep.model_dump_json(by_alias=True))
    anchor_file = tmp_path/'anchor.json'; anchor_file.write_text(json.dumps(view['readAnchor']))
    settings = SimpleNamespace(network='testnet11', deployment_generation_id=c.prep.generation_id,
        generation_preparation_path=str(prep_file), generation_preparation_hash=c.prep.manifest_hash,
        generation_chain_anchor_path=str(anchor_file), generation_chain_anchor_hash='0x'+sha256(anchor_file.read_bytes()).hexdigest())
    reloaded = load_generation_read_anchor(settings)
    assert reloaded.issuance == built.anchor.issuance
    assert reloaded.registry.inner() == built.anchor.registry.inner()
    assert reloaded.governance.inner() == built.anchor.governance.inner()
    assert reloaded.administrator.inner_puzzle == built.authority.inner_puzzle
    assert [s.inner() for s in reloaded.economic_components] == [s.inner() for s in built.anchor.economic_components]
    assert (await resolve_generation_chain(reloaded, provider=c.provider)).public_status(124)['supply']['distributed'] == 30000
    # A partial core is intentionally not a public operation kind: it cannot
    # reach the generic maintenance endpoint or masquerade as launch completion.
    journal = GenerationOperationJournal(str(tmp_path/'ops.db'), c.prep.generation_id)
    with pytest.raises(ValueError): journal.prepare(built.operation, 'genesis', 1, 123)


@pytest.mark.asyncio
async def test_native_consensus_rejects_every_partial_core_and_unsigned_launcher_substitution(core):
    c = core; bundle = assembly(c).operation.bundle()
    for index in range(len(bundle.coin_spends)):
        changed = SpendBundle(bundle.coin_spends[:index]+bundle.coin_spends[index+1:], bundle.aggregated_signature)
        assert (await c.client.push_tx(changed))[0] != MempoolInclusionStatus.SUCCESS, index
    for index, spend in enumerate(bundle.coin_spends):
        if spend.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH: continue
        parts = list(Program.from_bytes(bytes(spend.solution)).as_iter())
        parts[0] = Program.to(bytes32(b'X'*32))
        changed_spend = make_spend(spend.coin, Program.from_bytes(bytes(spend.puzzle_reveal)), Program.to(parts))
        changed = SpendBundle(bundle.coin_spends[:index]+[changed_spend]+bundle.coin_spends[index+1:], bundle.aggregated_signature)
        assert (await c.client.push_tx(changed))[0] != MempoolInclusionStatus.SUCCESS, index
    # Re-sign the surviving real funding inputs, so a partial-graph rejection
    # cannot merely be attributed to the original aggregate's missing signer.
    for missing in ('authority', 'registry', 'governance', 'parameters', 'mint'):
        omitted = {c.funding[missing].name()}
        for spend in bundle.coin_spends:
            if spend.coin.parent_coin_info == c.funding[missing].name():
                omitted.add(spend.coin.name())
        surviving = [s for s in bundle.coin_spends if s.coin.name() not in omitted]
        signatures = [G2Element.from_bytes(c.faucet.sign_delegated_spend(r.coin,r.conditions,purpose='genesis'))
                      for r in requests(c) if r.name != missing]
        status, error = await c.client.push_tx(SpendBundle(surviving,AugSchemeMPL.aggregate(signatures)))
        assert status != MempoolInclusionStatus.SUCCESS and 'ANNOUNCE' in error.name, (missing,error)
    assert await c.client.push_tx(bundle) == (MempoolInclusionStatus.SUCCESS, None)


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['generation','preparation','artifact','administrator','treasury','recovery','validator',
    'missing_funding','reused_funding','recipient_coin','recipient_height','unknown_field'])
async def test_core_rejects_unreviewed_or_incomplete_bindings(core, fault):
    c = core; raw = c.artifact.model_dump(mode='json', by_alias=True)
    if fault == 'generation': raw['generationId'] = b32(99)
    if fault == 'preparation': raw['preparationManifest'] = b32(99)
    if fault == 'administrator': raw['dailyPublicKeys'][0],raw['dailyPublicKeys'][1] = raw['dailyPublicKeys'][1],raw['dailyPublicKeys'][0]
    if fault == 'treasury': raw['treasuryPuzzleHash'] = b32(99)
    if fault == 'recovery': raw['recoveryPublicKeys'][0] = '0x'+'00'*48
    if fault == 'validator': raw['deliveryValidatorPublicKeys'][0] = raw['deliveryValidatorPublicKeys'][1]
    if fault == 'unknown_field': raw['quorumBps'] = 1
    kwargs = {}
    if fault == 'artifact': kwargs['trusted_artifact_hash'] = b32(99)
    if fault == 'missing_funding': kwargs['funding_coins'] = {k:v for k,v in c.funding.items() if k != 'mint'}
    if fault == 'reused_funding': kwargs['funding_coins'] = {**c.funding, 'mint': c.funding['parameters']}
    if fault.startswith('recipient_'):
        receipt = c.evidence.recipients[0]
        receipt = replace(receipt, **({'coin_id': bytes32(b'X'*32)} if fault == 'recipient_coin' else {'confirmed_height':0}))
        kwargs['evidence'] = replace(c.evidence, recipients=(receipt,*c.evidence.recipients[1:]))
    with pytest.raises((ValueError, TypeError)):
        kwargs['artifact'] = GenerationCoreArtifact.model_validate(raw)
        requests(c, **kwargs)
    # A separately reviewed artifact with someone else's daily keys still
    # cannot rewrite the acknowledged three-person administrator roster.
    if fault == 'administrator':
        artifact = GenerationCoreArtifact.model_validate(raw)
        with pytest.raises(ValueError, match='administrator wallet'):
            requests(c, artifact=artifact, trusted_artifact_hash=artifact.artifact_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['change_destination', 'hidden_fee', 'extra_output', 'extra_condition', 'missing_assert', 'wrong_reveal'])
async def test_core_funding_cannot_change_destinations_fees_or_atomicity(core, fault):
    c = core; funding = {r.name:standard_spend(c.faucet,r.coin,r.conditions) for r in requests(c)}
    request = requests(c)[0]; conditions = list(request.conditions.as_iter())
    if fault in ('change_destination','hidden_fee'):
        index = next(i for i,p in enumerate(conditions) if p.first().as_int() == 51 and p.rest().first().as_atom() == bytes(request.coin.puzzle_hash))
        parts = list(conditions[index].as_iter())
        if fault == 'change_destination': parts[1] = Program.to(bytes32(b'X'*32))
        else: parts[2] = Program.to(parts[2].as_int()-1)
        conditions[index] = Program.to(parts)
    elif fault == 'extra_output': conditions.append(Program.to([51, bytes32(b'X'*32), 0]))
    elif fault == 'extra_condition': conditions.append(Program.to([52,1]))
    elif fault == 'missing_assert': conditions = [p for p in conditions if p.first().as_int() != 61]
    funding[request.name] = standard_spend(c.faucet,request.coin,Program.to(conditions))
    if fault == 'wrong_reveal': funding[request.name] = make_spend(request.coin,Program.to(1),Program.to(conditions))
    with pytest.raises(ValueError): assembly(c, funding_spends=funding)


@pytest.mark.asyncio
async def test_core_condition_order_is_independent_of_dictionary_insertion_order(core):
    c = core
    assert requests(c, funding_coins=dict(reversed(tuple(c.funding.items())))) == requests(c)


@pytest.mark.asyncio
async def test_administrator_reader_rejects_inconsistent_inputs_and_reorgs(core):
    from solslot_api.generation_administrator_evidence import resolve_generation_administrators
    c=core; built=assembly(c)
    assert await c.client.push_tx(built.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    authority=built.anchor.administrator
    identity='0x'+authority.identity_vaults[0].launcher_id.hex()
    class Faulty(Primary):
        def __init__(self,client,fault):super().__init__(client);self.fault=fault;self.reads=0
        async def get_network_info_primary(self):
            return {'network_name':'mainnet' if self.fault=='network' else 'testnet11'}
        async def get_coin_record_by_name_primary(self,name):
            raw=await super().get_coin_record_by_name_primary(name)
            if name==identity:
                self.reads+=1
                if self.fault=='missing':return None
                if self.fault=='amount':raw['coin']['amount']=1
                if self.fault=='spent_flag':raw['spent']=False
                if self.fault=='height':raw['confirmed_block_index']=False
                if self.fault=='reorg' and self.reads>1:raw['confirmed_block_index']+=1
            return raw
        async def get_puzzle_and_solution_primary(self,name,height):
            raw=await super().get_puzzle_and_solution_primary(name,height)
            if name==identity and self.fault=='reveal':raw['puzzle_reveal']=bytes(Program.to(1)).hex()
            return raw
    for fault in ('network','missing','amount','spent_flag','height','reorg','reveal'):
        with pytest.raises(ValueError):await resolve_generation_administrators(authority,provider=Faulty(c.client,fault))
    with pytest.raises(ValueError,match='frozen recovery policy'):
        await resolve_generation_administrators(replace(authority,source_manifest_hash=bytes32(b'Z'*32)),provider=c.provider)
    valid=await resolve_generation_administrators(authority,provider=c.provider)
    assert len(valid.identities)==3 and [i.current.coin.amount for i in valid.identities]==[3,5,7]
    with pytest.raises(ValueError,match='current on-chain identity'):
        valid.identities[0].verified_tip(authority.identity_vaults[1],authority.authority_launcher_id)


@pytest.mark.asyncio
async def test_native_recovery_is_observed_without_blocking_holder_state_and_new_key_can_pause(core):
    from eth_keys import keys
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import (lineage_proof_for_coinsol,
        puzzle_for_singleton,solution_for_singleton)
    from solslot_puzzles import admin_authority_v3_driver as driver
    from solslot_puzzles.eip712_helpers import (TESTNET11_GENESIS_CHALLENGE,eip712_hash_to_sign,eip712_prefix_and_domain_separator)
    from solslot_puzzles.generation_admin_transactions import PreparedAdministratorAction,scoped_pause
    from solslot_api.generation_administrator_evidence import resolve_generation_administrators
    c=core; built=assembly(c); native=built.authority
    assert await c.client.push_tx(built.operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    observed=await resolve_generation_administrators(native,provider=c.provider)
    admin=observed.authority.verified_tip(native.authority_launcher_id,observed.authority.state)
    daily=tuple(keys.PrivateKey(bytes([n])*32) for n in (1,2,3));replacement=keys.PrivateKey(bytes([5])*32)
    prefix=eip712_prefix_and_domain_separator(TESTNET11_GENESIS_CHALLENGE)
    def member(key,coin_id,action_hash):
        digest=eip712_hash_to_sign(prefix,coin_id,action_hash)
        return Program.to([coin_id,digest,key.sign_msg_hash(digest).to_bytes()[:64]])
    def identity_spend(evidence,inner,solution):
        return make_spend(evidence.current.coin,puzzle_for_singleton(evidence.launcher_id,inner),
            solution_for_singleton(lineage_proof_for_coinsol(evidence.parent_spend),evidence.current.coin.amount,solution))
    target=native.identity_vaults[1]
    transition=driver.build_identity_vault_transition(identity=target,authority_current_inner_puzzle=admin.inner,
        network='testnet11',kind=driver.PENDING_ROUTINE,intent_hash=bytes32(b'I'*32),
        current_identity_coin_id=observed.identities[1].current.coin.name(),
        replacement_daily_compressed_pubkey=replacement.public_key.to_compressed_bytes())
    mips=driver.build_authority_prepare_mips_spend(authority=native,transition=transition,
        current_identities=native.identity_vaults,current_identity_coin_ids=tuple(i.current.coin.name() for i in observed.identities))
    authority_spend=admin.spend(driver.build_prepare_solution(transition=transition,my_amount=1,new_authority_version=2,
        mips_reveal=mips.reveal,mips_solution=mips.solution,
        replacement_member_solution=member(replacement,admin.coin.name(),transition.prepare_binding_hash),
        identity_records=mips.identity_records))
    owner=native.identity_vaults[0]
    owner_action=driver.build_identity_approval_action(identity=owner,transition=transition)
    owner_spend=identity_spend(observed.identities[0],owner.custody_reveal,
        driver.build_identity_approval_solution(identity=owner,transition=transition,
            current_identity_coin_id=observed.identities[0].current.coin.name(),
            daily_member_solution=member(daily[0],observed.identities[0].current.coin.name(),owner_action.get_tree_hash())))
    target_spend=identity_spend(observed.identities[1],target.custody_reveal,
        driver.build_routine_identity_prepare_solution(identity=target,transition=transition,
            daily_member_solution=member(daily[1],observed.identities[1].current.coin.name(),
                transition.prepare_delegated_puzzle.get_tree_hash())))
    assert await c.client.push_tx(SpendBundle([authority_spend,owner_spend,target_spend],G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    pending=await resolve_generation_administrators(native,provider=c.provider)
    assert pending.authority.state==transition.authority_pending_inner_puzzle
    assert parse_inner_puzzle(pending.authority.state).state.pending_kind==driver.PENDING_ROUTINE
    assert pending.identities[1].current.coin.name()==transition.intermediate_identity_coin_id
    # Administrative key recovery does not invalidate holder proofs or make
    # the public holder index depend on availability of replacement-key data.
    state=await resolve_generation_chain(built.anchor,provider=c.provider)
    assert state.public_status(123)['supply']['nextProposalQuorum']==15000
    assert state.holdings.state[0].root==built.issuance.holdings.root
    pending_tip=pending.authority.verified_tip(native.authority_launcher_id,pending.authority.state)
    finish_authority=pending_tip.spend(driver.build_complete_solution(my_amount=1,new_authority_version=3))
    finish_identity=identity_spend(pending.identities[1],transition.intermediate_custody_reveal,
        driver.build_identity_finish_solution(transition))
    finish=SpendBundle([finish_authority,finish_identity],G2Element())
    assert (await c.client.push_tx(finish))[0]!=MempoolInclusionStatus.SUCCESS
    c.sim.pass_time(uint64(86401));await c.sim.farm_block()
    assert await c.client.push_tx(finish)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    current=await resolve_generation_administrators(native,provider=c.provider)
    assert parse_inner_puzzle(current.authority.state).state.authority_version==3
    assert parse_inner_puzzle(current.authority.state).state.pending_kind==0
    policies=list(native.identity_vaults)
    policies[1]=driver.build_admin_identity_vault(slot=1,launcher_id=target.launcher_id,
        authority_launcher_id=native.authority_launcher_id,network='testnet11',
        daily_compressed_pubkey=replacement.public_key.to_compressed_bytes(),recovery_bls_pubkey=target.recovery_bls_pubkey)
    with pytest.raises(ValueError,match='current on-chain identity'):
        current.identities[1].verified_tip(target,native.authority_launcher_id)
    reg_tip=state.registry.verified_tip(state.registry.state.launcher_id,state.registry.state.inner())
    prepared=PreparedAdministratorAction(built.anchor.issuance.generation,native,
        current.authority.verified_tip(native.authority_launcher_id,current.authority.state),
        tuple(i.verified_tip(p,native.authority_launcher_id) for i,p in zip(current.identities,policies)),
        reg_tip.coin.puzzle_hash,'PAUSE_NEW_OPERATIONS',(0,1),0,1)
    signer=(daily[0],replacement,daily[2])
    signatures={ch.slot:signer[ch.slot].sign_msg_hash(ch.digest).to_bytes() for ch in prepared.challenges()}
    operation,registry,_=scoped_pause(state.registry.state,reg_tip,prepared,signatures)
    assert await c.client.push_tx(operation.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    assert (await resolve_generation_chain(built.anchor,provider=c.provider)).registry.state.pause_mask==1
    assert (await resolve_generation_administrators(native,provider=c.provider)).authority.state==operation.successors[0].inner


@pytest.mark.asyncio
async def test_real_genesis_publication_advances_authority_and_reuses_current_identities(core):
    """Two genuine MIPS publications, not an anyone-can-spend admin fixture."""
    from eth_keys import keys
    from solslot_puzzles.generation_admin_transactions import (AdministratorIdentityTip,PreparedAdministratorAction,
        complete_administrator_action,scoped_pause)
    from solslot_puzzles.generation_ballots import CurrentHoldings, CustodyAuthorization, SGTInput, open_proposal, unlock_stakes
    from solslot_puzzles.generation_transactions import SingletonTip, anchor_vote, finalize_vote
    from solslot_puzzles.generation_vault import signing_digest
    from solslot_puzzles.generation_sgt import transition_digest
    from solslot_puzzles.holdings import HoldingKind
    from solslot_api.generation_administrator_evidence import resolve_generation_administrators

    c = core; built = assembly(c)
    assert await c.client.push_tx(built.operation.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c.sim.farm_block()
    native = built.authority
    launch_spends = {s.coin.name(): s for s in built.operation.spends if s.coin.puzzle_hash == SINGLETON_LAUNCHER_HASH}
    authority_coin = next(o for o in built.operation.auxiliary_outputs if o.parent_coin_info == native.authority_launcher_id)
    admin = SingletonTip(native.authority_launcher_id, native.inner_puzzle, authority_coin,
        launch_spends[native.authority_launcher_id])
    identities = [next(o for o in built.operation.auxiliary_outputs if o.parent_coin_info == i.launcher_id)
                  for i in native.identity_vaults]
    identity_parents = [launch_spends[i.launcher_id] for i in native.identity_vaults]
    custody = []
    for row in c.evidence.recipients:
        record = await c.client.get_coin_record_by_name(row.coin_id)
        height = int((await c.client.get_coin_record_by_name(record.coin.parent_coin_info)).spent_block_index)
        parent = await c.client.get_puzzle_and_solution(record.coin.parent_coin_info, height)
        custody.append(SingletonTip(row.launcher_id,
            c.prep.custody_inner(c.prep.administrators[row.slot-1]), record.coin, parent))
    tips = {t.launcher_id: t for t in built.operation.successors}
    gov, registry = built.anchor.governance, built.anchor.registry
    holdings = CurrentHoldings(gov.sgt, built.issuance.holdings, 0, tips[gov.sgt.ledger_launcher_id])
    inputs = tuple(SGTInput(coin, desc, built.issuance.eve_spend)
                   for coin, desc in zip(built.issuance.coins[:2], built.issuance.outputs[:2]))
    daily = tuple(keys.PrivateKey(bytes([n])*32) for n in (1,2,3))

    async def apply(operation):
        assert await c.client.push_tx(operation.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
        await c.sim.farm_block()
        tips.update({t.launcher_id: t for t in operation.successors})

    c.sim.pass_time(uint64(100000));await c.sim.farm_block()
    for round_number in (1,2):
        c.sim.pass_time(uint64(1000)); await c.sim.farm_block()
        issued = int(c.sim.timestamp)-1
        bill = Program.to([b'REOPEN', 0, 2])
        proposal = gov.proposal_id(bill, holdings.tree)
        evidence = await resolve_generation_administrators(built.anchor.administrator,provider=c.provider)
        live_tip = evidence.authority.verified_tip(native.authority_launcher_id,evidence.authority.state)
        assert live_tip.coin == admin.coin and live_tip.inner == admin.inner
        prepared = PreparedAdministratorAction(gov.sgt.generation,native,live_tip,
            tuple(t.verified_tip(policy,native.authority_launcher_id) for t,policy in
                zip(evidence.identities,native.identity_vaults)),
            tips[gov.sgt.governance_launcher_id].coin.puzzle_hash,'PUBLICATION_APPROVAL',proposal,issued,1)
        challenges = prepared.challenges()
        assert [c.slot for c in challenges] == [0,1]
        assert all(c.typed_data()['message']['coin_id'] == '0x'+c.coin_id.hex() for c in challenges)
        signatures = {challenge.slot:daily[challenge.slot].sign_msg_hash(challenge.digest).to_bytes()
                      for challenge in challenges}
        with pytest.raises(ValueError,match='both and only'):
            complete_administrator_action(prepared,{0:signatures[0]})
        for changed in (replace(prepared,issued_at=issued+1),replace(prepared,generation=bytes32(b'Z'*32)),
                        replace(prepared,subject=bytes32(b'Z'*32)),replace(prepared,coadministrator_slot=2)):
            with pytest.raises(ValueError): complete_administrator_action(changed,signatures)
        with pytest.raises(ValueError,match='frozen recovery policy'):
            complete_administrator_action(replace(prepared,authority=replace(native,source_manifest_hash=bytes32(b'Z'*32))),signatures)
        with pytest.raises(ValueError):
            complete_administrator_action(prepared,{0:signatures[1],1:signatures[0]})
        consent = complete_administrator_action(prepared,signatures)
        pub = consent.spends
        sponsors = []
        for slot,item in enumerate(inputs):
            vault = custody[slot]; expiry = issued+600
            out = replace(item.descriptor, kind=HoldingKind.LOCKED_HOLDER, lock_id=proposal)
            digest = transition_digest(gov.sgt, item.coin, 'LOCK', (out,))
            signature = daily[slot].sign_msg_hash(signing_digest(gov.sgt.generation, vault.coin.name(),
                item.coin.name(), digest, expiry)).to_bytes()[:64]
            sponsors.append(CustodyAuthorization(item, vault, expiry, signature))
        args = (gov,tips[gov.sgt.governance_launcher_id],registry,tips[registry.launcher_id],holdings,bill,admin,tuple(pub))
        with pytest.raises(ValueError, match='exact action and authority version'):
            open_proposal(*args, issued+1, tuple(sponsors))
        opened = open_proposal(*args, issued, tuple(sponsors))
        if round_number == 1:
            # Native consensus enforces the full 24-hour consent window even
            # with correct cryptographic signatures and otherwise current inputs.
            for start in (issued-86401,issued+100):
                timed = replace(prepared,issued_at=start)
                signed = {ch.slot:daily[ch.slot].sign_msg_hash(ch.digest).to_bytes() for ch in timed.challenges()}
                timed_consent = complete_administrator_action(timed,signed)
                candidate = open_proposal(*args[:-1],timed_consent.spends,start,tuple(sponsors))
                status,error = await c.client.push_tx(candidate.operation.bundle())
                assert status != MempoolInclusionStatus.SUCCESS and 'SECONDS' in error.name
        successor = next(t for t in opened.operation.successors if t.launcher_id == admin.launcher_id)
        current = parse_inner_puzzle(successor.inner); old = parse_inner_puzzle(admin.inner)
        assert successor.inner != admin.inner and current.state.authority_version == round_number+1
        assert replace(current.state, authority_version=old.state.authority_version) == old.state
        assert current.operational_root_hash == old.operational_root_hash
        assert current.source_manifest_hash == old.source_manifest_hash
        assert opened.governance.active.yes_weight == 20000
        assert opened.governance.active.required_votes == 15000
        # Both administrator identities are consensus-required. A valid
        # sponsorship cannot replace either publication approval.
        for missing in pub[1:]:
            altered = SpendBundle([s for s in opened.operation.spends if s.coin != missing.coin], G2Element())
            assert (await c.client.push_tx(altered))[0] != MempoolInclusionStatus.SUCCESS
        await apply(opened.operation)
        admin = successor; gov,holdings,inputs = opened.governance,opened.holdings,opened.outputs
        identities = [t.coin for t in consent.identities]
        identity_parents = [t.parent for t in consent.identities]
        custody = [tips.get(v.launcher_id,v) for v in custody]
        clock = opened.operation.auxiliary_outputs[0]
        birth = int((await c.client.get_coin_record_by_name(clock.name())).timestamp)
        operation, gov = anchor_vote(gov,tips[gov.sgt.governance_launcher_id],clock,birth)
        await apply(operation)
        c.sim.pass_time(uint64(3601)); await c.sim.farm_block()
        operation,gov = finalize_vote(gov,tips[gov.sgt.governance_launcher_id]); await apply(operation)
    chain = await resolve_generation_chain(built.anchor, provider=c.provider)
    assert chain.public_status(123)['supply']['distributed'] == 30000
    assert parse_inner_puzzle(admin.inner).state.authority_version == 3
    # Use the other coadministrator for a real scoped pause. Broadening a
    # signed scope or substituting the registry/epoch is not an authorization.
    pause = PreparedAdministratorAction(gov.sgt.generation,native,admin,consent.identities,
        tips[registry.launcher_id].coin.puzzle_hash,'PAUSE_NEW_OPERATIONS',(registry.pause_epoch,31),0,2)
    signatures = {challenge.slot:daily[challenge.slot].sign_msg_hash(challenge.digest).to_bytes()
                  for challenge in pause.challenges()}
    for changed in (replace(pause,subject=(registry.pause_epoch,32)),
                    replace(pause,subject=(registry.pause_epoch+1,31)),
                    replace(pause,target=bytes32(b'Z'*32)),replace(pause,purpose='RECOVERY'),
                    replace(pause,coadministrator_slot=True)):
        with pytest.raises(ValueError):scoped_pause(registry,tips[registry.launcher_id],changed,signatures)
    operation,registry,consent = scoped_pause(registry,tips[registry.launcher_id],pause,signatures)
    assert registry.pause_mask == 31 and len(operation.auxiliary_outputs) == 2
    await apply(operation)
    assert parse_inner_puzzle(consent.administrator.inner).state.authority_version == 4
    observed = await resolve_generation_administrators(built.anchor.administrator,provider=c.provider)
    assert observed.authority.state == consent.administrator.inner
    assert [i.current.coin for i in observed.identities] == [t.coin for t in consent.identities]
    # The immutable pause scope leaves closed-stake return available even
    # when all five new-operation flags are paused.
    unlocked = unlock_stakes(gov,tips[gov.sgt.governance_launcher_id],holdings,inputs)
    await apply(unlocked.operation)
    assert [i.coin.amount for i in unlocked.outputs] == [10000,10000]
    assert [i.descriptor.owner for i in unlocked.outputs] == [i.descriptor.owner for i in inputs]
    assert (await resolve_generation_chain(built.anchor,provider=c.provider)).registry.state.pause_mask == 31
