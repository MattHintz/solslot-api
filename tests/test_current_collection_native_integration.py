"""Real simulator25-deed mint and two fresh native owner/ID vaults.

All wallets/validator signatures are the existing synthetic simulator fixture;
there is no live wallet, credential, network signer or public transaction.
These checks cover the quote boundary, not HTTP/signer/worker cutover.
"""
from dataclasses import replace
from types import SimpleNamespace
import asyncio
import pytest
import pytest_asyncio
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import LineageProof
from chia_rs import AugSchemeMPL,Coin,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_primary_price import SignedPrimaryPrice
from solslot_puzzles.generation_vault_identity import build_generation_identity_bundle
from solslot_puzzles.payment_artifacts_v2 import build_oracle_round,OracleObservationV1,oracle_operator_set_root,oracle_round_signature_message
from solslot_puzzles.vault_driver import one_leaf_merkle_root
from solslot_api.generation_customer_collection_policy import TestnetCollectionIssuerPolicy as CollectionPolicy
from solslot_api.generation_customer_inventory import resolve_current_primary_inventory
from solslot_api.generation_customer_launch import CustomerLaunchBindings,CustomerLaunchConsent,assemble_customer_launch
from solslot_api.generation_customer_quote import current_customer_xch_quote
from solslot_api.generation_customer_vault import trace_current_customer_vault
from solslot_api.generation_mint_execution import MintExecutionRequest,prepare_mint_execution
from solslot_api.generation_mint_reviews import h,reviewed_mint_edition
from solslot_api.singleton_launcher import launcher_coin_for_parent
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import initialize_and_upgrade
from tests.test_generation_mint_reviews import context
from tests.test_generation_mint_execution import approved
from tests.test_generation_customer_purchase_native import real_synthetic_identity_policy,signed,b32


@pytest_asyncio.fixture
async def collection_world(core,tmp_path,real_synthetic_identity_policy):
    c=core;initialized=await initialize_and_upgrade(c,tmp_path);built,_=initialized
    ctx=await context(c,tmp_path,initialized_generation=initialized)
    source,proposal,journal,chain=await approved(c,ctx,tmp_path)
    c.faucet.bind_generation_mint_reviews(ctx.store,generation_id=c.prep.generation_id,maximum_parent_mojos=1000)
    body=MintExecutionRequest.model_validate({'generationId':c.prep.generation_id,'sourceReviewId':source['packageId'],
        'proposalId':proposal,'feeCapMojos':1000,'expectedInputs':{
            **{name:h(getattr(chain,name).current.coin.name()) for name in ('registry','governance','holdings')},
            'components':{source['mintAuthority']['componentId']:source['mintAuthority']['coinId']}}})
    prepared=await prepare_mint_execution(body,settings=ctx.settings,collections=ctx.collections,reviews=ctx.store,
        journal=journal,anchor=built.anchor,provider=c.provider,faucet=c.faucet,funding_guard=asyncio.Lock(),clock=lambda:int(c.sim.timestamp))
    assert await c.client.push_tx(journal.protocol_bundle(prepared['operationId']))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block();edition=reviewed_mint_edition(source)
    inventory=await resolve_current_primary_inventory(settings=ctx.settings,anchor=built.anchor,provider=c.provider,
        collection=edition.collection,edition_hash=edition.commitment,metadata_root=edition.metadata_root)
    assert len(inventory.items)==25 and sum(x.available for x in inventory.items)==25
    validators=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (31,32,33)]
    # Reuse the existing fixture's synthetic wallet construction only.
    owners=[AugSchemeMPL.key_gen(letter*32) for letter in (b'Q',b'S')]
    acs=Program.to(1)
    origins=[x.coin for x in await c.client.get_coin_records_by_puzzle_hash(acs.get_tree_hash()) if not x.spent]
    bridge_policy=bytes32.from_hexstr(c.prep.bridge_policy_hash)
    pairs=[(Coin(origins[2*n].name(),c.faucet.address_puzzle_hash,uint64(10000)),
            Coin(origins[2*n+1].name(),bridge_policy,uint64(1))) for n in range(2)]
    setup=[]
    for original,created in zip(origins[:4],[coin for pair in pairs for coin in pair],strict=True):
        setup.append(make_spend(original,acs,Program.to([[51,created.puzzle_hash,int(created.amount)],
            [51,acs.get_tree_hash(),int(original.amount)-int(created.amount)]])))
    assert await c.client.push_tx(SpendBundle(setup,G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    bindings=CustomerLaunchBindings(bytes32.from_hexstr(c.prep.generation_id),bytes32.from_hexstr(c.prep.manifest_hash),
        inventory.pool_launcher_id,bridge_policy,load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash())
    vaults=[];empty_vaults=[]
    for n,(owner,(funding,bridge)) in enumerate(zip(owners,pairs,strict=True)):
        public=bytes(owner.get_g1());now=int(c.sim.timestamp)
        consent=CustomerLaunchConsent(bindings,b32(161+n),h(public),'chia_bls',funding.name(),launcher_coin_for_parent(funding).name(),now+300)
        signature=h(bytes(AugSchemeMPL.sign(owner,bytes(Program.to(('Chia Signed Message',consent.bls_message())).get_tree_hash()))))
        creation=assemble_customer_launch(bindings=bindings,consent=consent,signature=signature,funding_coin=funding,faucet=c.faucet,now=now)
        assert await c.client.push_tx(creation.bundle())==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
        tip,=creation.successors
        arguments=dict(bindings=bindings,launcher=tip.launcher_id,owner_pubkey=public,auth_type=1,initial_coin=tip.coin,provider=c.provider)
        empty_vaults.append(await trace_current_customer_vault(**arguments));now=int(c.sim.timestamp)
        identity=build_generation_identity_bundle(bridge_parent_id=bridge.parent_coin_info,bridge_amount=1,
            validator_pubkeys=[bytes(k.get_g1()) for k in validators],threshold=2,signer_indices=[0,1],
            vault_coin=tip.coin,vault_launcher_id=tip.launcher_id,owner_pubkey_bytes=public,auth_type=1,
            members_merkle_root=one_leaf_merkle_root(public),pool_launcher_id=bindings.pool_launcher,
            new_identity_attest_root=b32(170+n*8),attestation_leaf_hash=b32(171+n*8),scoped_nullifier=b32(172+n*8),nullifier_type=1,
            service_scope_hash=b32(173+n*8),service_subscope_hash=b32(174+n*8),proof_timestamp=now,current_timestamp=now,
            lineage_proof=LineageProof(parent_name=funding.name(),amount=uint64(1)))
        bundle=signed(identity.spend_bundle,[owner,*validators],c.faucet.agg_sig_me_data)
        assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None);await c.sim.farm_block()
        current=await trace_current_customer_vault(**arguments);assert current.identity_verified;vaults.append(current)
    now=int(c.sim.timestamp);price_keys=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (41,42,43)]
    oracle=build_oracle_round(network='testnet11',sequence=1,asset_id=bytes32.zeros,asset_decimals=12,
        operator_set_root=oracle_operator_set_root([bytes(k.get_g1()) for k in price_keys]),
        observations=tuple(OracleObservationV1(b32(n),bytes32.zeros,12,1_000_000_000,now,now+600,b32(n+2)) for n in (151,152)))
    price=SignedPrimaryPrice(oracle,tuple((i,bytes(AugSchemeMPL.sign(price_keys[i],oracle_round_signature_message(oracle.round_hash)))) for i in (0,1)))
    terms=inventory.items[0].original.terms
    policy=CollectionPolicy(bindings.generation,inventory.collection,inventory.edition,inventory.metadata_root,
        terms.protocol_puzhash,terms.protocol_treasury_puzzle_hash,bytes(c.faucet.key.wallet_pk),
        frozenset(x.original.terms.deed_launcher_id for x in inventory.items),10_000_000_000)
    policy.validate()
    yield SimpleNamespace(c=c,inventory=inventory,vaults=tuple(vaults),empty_vaults=tuple(empty_vaults),price=price,
        policy=policy,now=now,ctx=ctx)
    ctx.collections.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('real_synthetic_identity_policy',['forwarding'],indirect=True)
async def test_real_native_25_inventory_two_buyers_owner_id_price_issuer_fee_boundaries(collection_world):
    w=collection_world
    before=w.policy.public()
    assert not {'buyerVaultLauncherId','maximumPurchases','issuedAt','expiresAt'} & before.keys()
    def quote(index,vault=None,policy=None,**changed):
        args=dict(inventory=w.inventory,vault=vault or w.vaults[index%2],
            deed_launcher=w.inventory.items[index].original.terms.deed_launcher_id,price=w.price,
            nonce=bytes32((index+1).to_bytes(32,'big')),now=w.now,expires_at=w.now+300,
            forwarding_policy=policy or w.policy)
        args.update(changed);return current_customer_xch_quote(**args)
    # Concurrent request-local owners exercise all25 immutable deed terms;
    # no mutable shared buyer or three-deed scope is used.
    async def request(index):
        await asyncio.sleep(0)
        return quote(index)
    artifacts=await asyncio.gather(*(request(index) for index in range(25)))
    assert len({a.deed_launcher_id for a in artifacts})==25
    assert {a.vault_launcher_id for a in artifacts}=={v.launcher for v in w.vaults}
    for index,artifact in enumerate(artifacts):
        vault=w.vaults[index%2];terms=w.inventory.items[index].original.terms
        assert w.policy.require_purchase(artifact,terms,vault,launcher=vault.launcher,auth_type='chia_bls',now=w.now)==w.policy
        assert artifact.zkpassport_root==vault.root and artifact.protocol_treasury_puzzle_hash==terms.protocol_treasury_puzzle_hash
        with pytest.raises(ValueError):
            w.policy.require_purchase(artifact,terms,w.vaults[(index+1)%2],launcher=vault.launcher,auth_type='chia_bls',now=w.now)
    assert w.policy.public()==before
    first=artifacts[0];vault=w.vaults[0];terms=w.inventory.items[0].original.terms
    # Actual unstamped native vault and owner/session mismatch stay closed.
    with pytest.raises(ValueError,match='FRESH_ID_REQUIRED'):quote(0,vault=w.empty_vaults[0])
    with pytest.raises(ValueError):w.policy.require_purchase(first,terms,vault,launcher=vault.launcher,auth_type='evm',now=w.now)
    for changes in ({'zkpassport_root':b32(220)},{'rail_amount':0},
                    {'base_amount_minor':first.base_amount_minor+1},
                    {'technology_fee_bps':99},{'protocol_treasury_puzzle_hash':b32(221)}):
        with pytest.raises(ValueError):
            altered=replace(first,**changes)
            w.policy.require_purchase(altered,terms,vault,launcher=vault.launcher,auth_type='chia_bls',now=w.now)
    with pytest.raises(ValueError):quote(0,policy=replace(w.policy,issuer_public_key=list(vault.inner.uncurry()[1].as_iter())[1].as_atom()))
    with pytest.raises(ValueError):quote(0,policy=replace(w.policy,fee_puzzle=b32(222)))
    with pytest.raises(ValueError):quote(0,policy=replace(w.policy,maximum_gross_mojos=int(first.rail_amount)-1))
    with pytest.raises(ValueError):quote(0,now=w.now+301,expires_at=w.now+300)
    with pytest.raises(ValueError):
        quote(0,price=replace(w.price,signatures=((0,bytes(G2Element())),(1,bytes(G2Element())))))
    # Quote reads do not reserve/change physical inventory or vault state.
    assert sum(x.available for x in w.inventory.items)==25
    for v in w.vaults:
        record=await w.c.client.get_coin_record_by_name(v.coin.name());assert record and not record.spent
