"""Persisted mint metadata can only supply a chain-committed deed preimage."""
from types import SimpleNamespace
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs.sized_bytes import bytes32
from solslot_api.deed_witness import primary_deed_inner
from solslot_api.mint_proposals import MintProposalStore
from solslot_puzzles.mint_publish_driver import make_smart_deed_inner
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles import load_puzzle
from tests.test_mint_proposals import _new_args, _publish_args


def case():
    record = SimpleNamespace(state='EXECUTED',deed_launcher_id=b'd'*32,asset_class='RWA-RE-RES',
        par_value=12345,property_id='SYNTHETIC-DEED',collection_id='SYNTHETIC-COLLECTION',
        share_ppm=100_000,jurisdiction='US',royalty_puzhash=b't'*32,royalty_bps=100)
    config = SimpleNamespace(pool_launcher_id=bytes32(b'p'*32),p2_pool_v2_mod_hash=load_puzzle('p2_pool_v2.clsp').get_tree_hash(),
        p2_vault_mod_hash=load_puzzle('p2_vault.clsp').get_tree_hash())
    deed_id = bytes32(record.deed_launcher_id)
    struct = singleton_struct(deed_id)
    artifact = {'puzzleHashes':{'didFullPuzzleHash':'0x'+(b'i'*32).hex()}}
    inner = make_smart_deed_inner(deed_singleton_struct_program=struct,protocol_did_puzhash=bytes32(b'i'*32),
        par_value_mojos=record.par_value,asset_class=1,property_id_canon=canonicalise_property_id(record.property_id),
        collection_id_canon=canonicalise_property_id(record.collection_id),share_ppm=record.share_ppm,
        jurisdiction=b'US',royalty_puzhash=bytes32(record.royalty_puzhash),royalty_bps=record.royalty_bps,
        pool_singleton_launcher_id=config.pool_launcher_id,pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
        p2_pool_mod_hash=config.p2_pool_v2_mod_hash,p2_vault_mod_hash=config.p2_vault_mod_hash)
    record.smart_deed_inner_puzhash = bytes(inner.get_tree_hash())
    args = [Program.to(0) for _ in range(30)]
    args[1],args[9],args[10],args[13] = map(Program.to,[inner.get_tree_hash(),deed_id,
        canonicalise_property_id(record.collection_id),record.share_ppm])
    return dict(record=record,deed_id=deed_id,deed_struct=struct,inventory_args=args,config=config,artifact=artifact),inner


def test_primary_witness_reconstructs_exact_chain_commitment():
    args,expected = case()
    assert primary_deed_inner(**args) == expected


@pytest.mark.parametrize('field,value',[
    ('par_value',12346),('property_id','OTHER'),('collection_id','OTHER'),('share_ppm',200_000),
    ('jurisdiction','CA'),('royalty_puzhash',b'x'*32),('royalty_bps',101),('asset_class','UNKNOWN'),
    ('deed_launcher_id',b'x'*32),('smart_deed_inner_puzhash',b'x'*32),('state','PROPOSED')])
def test_changed_or_unexecuted_record_cannot_authorize_primary_deed(field,value):
    args,_ = case()
    setattr(args['record'],field,value)
    with pytest.raises(ValueError):
        primary_deed_inner(**args)


@pytest.mark.parametrize('index,value',[(1,b'x'*32),(9,b'x'*32),(10,b'x'*32),(13,200_000)])
def test_other_inventory_commitment_cannot_reuse_record(index,value):
    args,_=case();args['inventory_args'][index]=Program.to(value)
    with pytest.raises(ValueError):
        primary_deed_inner(**args)


def test_mint_store_lookup_survives_reopen_and_rejects_ambiguity(tmp_path):
    path=str(tmp_path/'mint.db')
    with MintProposalStore(path) as store:
        first=store.create(**_new_args())
        first=store.set_published(first.id,**_publish_args())
        expected=first.deed_launcher_id
    with MintProposalStore(path) as store:
        assert store.get_by_deed_launcher_id(expected)==first
        assert store.get_by_deed_launcher_id(b'z'*32) is None
        second=store.create(**_new_args(suffix=1))
        store.set_published(second.id,**_publish_args(suffix=1))
        with pytest.raises(ValueError,match='ambiguous'):
            store.get_by_deed_launcher_id(expected)
        with pytest.raises(ValueError,match='32 bytes'):
            store.get_by_deed_launcher_id(b'bad')


@pytest.mark.asyncio
@pytest.mark.parametrize('offer_parent',[False,True])
async def test_primary_loader_resolves_only_confirmed_commitment(monkeypatch,offer_parent):
    from chia.types.blockchain_format.coin import Coin
    from chia.wallet.lineage_proof import LineageProof
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
    from chia.wallet.trading.offer import OFFER_MOD
    from solslot_puzzles.vault_driver import puzzle_for_p2_vault
    from solslot_puzzles.sols_swap_v4_driver import SolsSwapOfferError
    from solslot_api import sols_swaps, sols_market, mint_endpoints
    args,expected=case();config=args['config'];config.deed_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH
    vault=bytes32(b'v'*32)
    held=SINGLETON_MOD.curry(args['deed_struct'],puzzle_for_p2_vault(vault))
    coin=Coin(bytes32(b'r'*32),held.get_tree_hash(),1)
    live=SimpleNamespace(puzzle_hash='0x'+coin.puzzle_hash.hex(),coin_id='0x'+coin.name().hex())
    earlier=SimpleNamespace(spent_height=8);settlement=SimpleNamespace(spent_height=8)
    tip=SimpleNamespace(live=live,lineage=(earlier,settlement,live))
    inventory=load_puzzle('mint_offer_delegate_v5.clsp').curry(*args['inventory_args'])
    def reveal(inner):
        return {'puzzle_reveal':bytes(SINGLETON_MOD.curry(args['deed_struct'],inner)).hex()}
    async def load_tip(*_):return tip
    async def latest(*_):return reveal(OFFER_MOD if offer_parent else inventory)
    async def preceding(provider,parent,child,**kwargs):
        assert parent is earlier and child is settlement
        return reveal(inventory),1
    async def confirmed(*_):return coin,LineageProof(bytes32(b'x'*32),bytes32(b'y'*32),1)
    monkeypatch.setattr(sols_swaps,'_singleton_tip',load_tip)
    monkeypatch.setattr(sols_swaps,'_latest_solution',latest)
    monkeypatch.setattr(sols_market,'_singleton_spend',preceding)
    monkeypatch.setattr(sols_swaps,'_confirmed_coin_and_lineage',confirmed)
    monkeypatch.setattr(mint_endpoints,'get_mint_proposal_store',lambda _:SimpleNamespace(
        get_by_deed_launcher_id=lambda _:args['record']))
    parameters=dict(provider=None,config=config,vault_launcher_id=vault,
        deed_launcher_id='0x'+args['deed_id'].hex(),settings=SimpleNamespace(),artifact=args['artifact'])
    loaded=await sols_swaps._load_vault_held_deed(**parameters)
    assert loaded.smart_deed_inner==expected and loaded.coin==coin
    args['record'].par_value+=1
    with pytest.raises(SolsSwapOfferError,match='witness'):
        await sols_swaps._load_vault_held_deed(**parameters)
    args['record'].par_value-=1
    if offer_parent:
        earlier.spent_height=7
        with pytest.raises(SolsSwapOfferError,match='atomic'):
            await sols_swaps._load_vault_held_deed(**parameters)


@pytest.mark.asyncio
async def test_pool_withdrawal_recovers_terms_from_exact_deposit_predecessor(monkeypatch):
    from chia.types.blockchain_format.coin import Coin
    from chia.wallet.lineage_proof import LineageProof
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, SINGLETON_MOD_HASH
    from chia.wallet.trading.offer import OFFER_MOD
    from solslot_puzzles.vault_driver import puzzle_for_p2_vault
    from solslot_puzzles.pool_economics_v2 import deed_metadata_commitment
    from solslot_puzzles.sols_swap_v4_driver import SolsSwapOfferError
    from solslot_api import sols_swaps, sols_market
    args,expected=case();config=args['config'];config.deed_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH
    vault=bytes32(b'v'*32);record=args['record']
    commitment=deed_metadata_commitment(args['deed_id'],record.par_value,1,
        canonicalise_property_id(record.property_id),canonicalise_property_id(record.collection_id),record.share_ppm)
    custody_args=[config.p2_pool_v2_mod_hash,SINGLETON_MOD_HASH,config.pool_launcher_id,SINGLETON_LAUNCHER_HASH,commitment]
    held=SINGLETON_MOD.curry(args['deed_struct'],puzzle_for_p2_vault(vault))
    coin=Coin(bytes32(b'r'*32),held.get_tree_hash(),1)
    live=SimpleNamespace(puzzle_hash='0x'+coin.puzzle_hash.hex(),coin_id='0x'+coin.name().hex())
    deposit=SimpleNamespace(spent_height=7);custody=SimpleNamespace(spent_height=8);offer=SimpleNamespace(spent_height=8)
    tip=SimpleNamespace(live=live,lineage=(deposit,custody,offer,live))
    def reveal(inner):return {'puzzle_reveal':bytes(SINGLETON_MOD.curry(args['deed_struct'],inner)).hex()}
    async def load_tip(*_):return tip
    async def latest(*_):return reveal(OFFER_MOD)
    async def preceding(provider,parent,child,**kwargs):
        if parent is custody and child is offer:
            return reveal(load_puzzle('p2_pool_v2.clsp').curry(*custody_args)),1
        assert parent is deposit and child is custody
        return reveal(expected),1
    async def confirmed(*_):return coin,LineageProof(bytes32(b'x'*32),bytes32(b'y'*32),1)
    monkeypatch.setattr(sols_swaps,'_singleton_tip',load_tip)
    monkeypatch.setattr(sols_swaps,'_latest_solution',latest)
    monkeypatch.setattr(sols_market,'_singleton_spend',preceding)
    monkeypatch.setattr(sols_swaps,'_confirmed_coin_and_lineage',confirmed)
    parameters=dict(provider=None,config=config,vault_launcher_id=vault,deed_launcher_id='0x'+args['deed_id'].hex())
    assert (await sols_swaps._load_vault_held_deed(**parameters)).smart_deed_inner==expected
    custody_args[4]=bytes32(b'x'*32)
    with pytest.raises(SolsSwapOfferError,match='commitment'):
        await sols_swaps._load_vault_held_deed(**parameters)
    custody_args[4]=commitment;custody_args[2]=bytes32(b'x'*32)
    with pytest.raises(SolsSwapOfferError,match='pool'):
        await sols_swaps._load_vault_held_deed(**parameters)
