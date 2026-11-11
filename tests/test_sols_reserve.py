from types import SimpleNamespace
import pytest
from chia.types.blockchain_format.coin import Coin
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia_rs.sized_bytes import bytes32
from solslot_api import sols_reserve
from solslot_api.faucet import Faucet
from tests.test_generation_chain_evidence import generation_chain
from tests.test_generation_recipient_evidence import prepared


def b(n):
    return bytes32(bytes([n])*32)


def fixture(monkeypatch,amounts=(1,30)):
    faucet=Faucet.from_seed_hex('b1'*32,'testnet11')
    inner=faucet.key.puzzle
    config=SimpleNamespace(reserve_puzzle_hash=inner.get_tree_hash(),permanent_rules=SimpleNamespace(sols_tail_hash=b(90)))
    puzzle=construct_cat_puzzle(CAT_MOD,b(90),inner)
    parents=[Coin(b(i+1),puzzle.get_tree_hash(),amount) for i,amount in enumerate(amounts)]
    coins=[Coin(parent.name(),puzzle.get_tree_hash(),parent.amount) for parent in parents]
    records=[dict(coin=coin.to_json_dict(),confirmed_block_index=5,spent_block_index=0,spent=False) for coin in coins]
    calls=[]
    async def lineage(**kwargs):
        calls.append(kwargs)
        coin=kwargs['coin'];parent=parents[coins.index(coin)]
        return LineageProof(parent_name=parent.parent_coin_info,inner_puzzle_hash=inner.get_tree_hash(),amount=parent.amount)
    monkeypatch.setattr(sols_reserve,'confirmed_cat_receipt_lineage',lineage)
    async def fetch(*args,**kwargs):
        return records
    args=dict(provider=SimpleNamespace(get_coin_records_by_puzzle_hash=fetch),
        artifact={'solsReserveSeed':{'coinId':'0x'+b(99).hex()}},config=config,
        pool_state=SimpleNamespace(economics=SimpleNamespace(reserve_sols_mojos=sum(amounts))),reserve_inner_puzzle=inner)
    return args,records,coins,calls


@pytest.mark.asyncio
async def test_fragmented_reserve_becomes_one_exact_atomic_anchor(monkeypatch):
    args,_,coins,calls=fixture(monkeypatch)
    anchor,lineage,consolidation=await sols_reserve.prepare_reserve_anchor(**args)
    assert anchor.amount==31 and len(consolidation)==2
    assert {item.spend.coin for item in consolidation}==set(coins)
    assert anchor.parent_coin_info==min(coins,key=lambda coin:coin.name()).name()
    assert lineage.inner_puzzle_hash==args['reserve_inner_puzzle'].get_tree_hash()
    assert len(calls)==2
    assert all(call['expected_tail_hash']==b(90) and
        call['expected_inner_hash']==args['reserve_inner_puzzle'].get_tree_hash() for call in calls)
    assert sum(len(list(item.signing_conditions.as_iter())) for item in consolidation)==1


@pytest.mark.asyncio
async def test_single_reserve_needs_no_consolidation(monkeypatch):
    args,_,coins,_=fixture(monkeypatch,(31,))
    anchor,_,consolidation=await sols_reserve.prepare_reserve_anchor(**args)
    assert anchor==coins[0] and consolidation==()


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['short','excess','duplicate','custody','unconfirmed','limit'])
async def test_inconsistent_reserve_fails_closed(monkeypatch,fault):
    args,records,_,_=fixture(monkeypatch,tuple([1]*33) if fault=='limit' else (1,30))
    if fault=='short': args['pool_state'].economics.reserve_sols_mojos=32
    if fault=='excess': args['pool_state'].economics.reserve_sols_mojos=30
    if fault=='duplicate': records.append(records[0])
    if fault=='custody': records[0]['coin']['puzzle_hash']='0x'+b(88).hex()
    if fault=='unconfirmed': records[0]['confirmed_block_index']=0
    with pytest.raises(ValueError):
        await sols_reserve.prepare_reserve_anchor(**args)


@pytest.mark.asyncio
async def test_bad_lineage_cannot_be_consolidated(monkeypatch):
    args,_,_,_=fixture(monkeypatch)
    async def reject(**kwargs):
        raise ValueError('parent reveal mismatch')
    monkeypatch.setattr(sols_reserve,'confirmed_cat_receipt_lineage',reject)
    with pytest.raises(ValueError,match='parent reveal'):
        await sols_reserve.prepare_reserve_anchor(**args)


@pytest.mark.asyncio
@pytest.mark.parametrize('generation_chain',['pool'],indirect=True)
async def test_generation_reserve_reuses_node_lineage_checks_and_constrained_merge(monkeypatch,generation_chain):
    from dataclasses import replace
    from solslot_puzzles.generation_sols_reserve import reserve_inner
    from chia.types.blockchain_format.program import Program
    _,_,_,anchor,_=generation_chain
    pool=anchor.economic_components[2]
    inner=reserve_inner(generation=pool.generation,registry_id=pool.registry_id,
        pool_id=pool.launcher_id,component_id=pool.component_id)
    pool=replace(pool,permanent=replace(pool.permanent,reserve_puzzle_hash=inner.get_tree_hash()))
    config=pool.config();puzzle=construct_cat_puzzle(CAT_MOD,config.permanent_rules.sols_tail_hash,inner)
    parents=[Coin(b(i+200),puzzle.get_tree_hash(),amount) for i,amount in enumerate((1,30))]
    coins=[Coin(parent.name(),puzzle.get_tree_hash(),parent.amount) for parent in parents]
    reads=[]
    async def fetch(hash,**kwargs):
        reads.append((hash,kwargs))
        return [dict(coin=c.to_json_dict(),confirmed_block_index=5,spent_block_index=0,spent=False) for c in coins]
    proofs=[]
    async def lineage(**kwargs):
        proofs.append(kwargs)
        parent=parents[coins.index(kwargs['coin'])]
        return LineageProof(parent.parent_coin_info,inner.get_tree_hash(),parent.amount)
    monkeypatch.setattr(sols_reserve,'confirmed_cat_receipt_lineage',lineage)
    result=await sols_reserve.prepare_reserve_anchor(provider=SimpleNamespace(get_coin_records_by_puzzle_hash=fetch),
        artifact={'solsReserveSeed':{'coinId':'0x'+b(99).hex()}},config=config,
        pool_state=SimpleNamespace(economics=SimpleNamespace(reserve_sols_mojos=31)),reserve_inner_puzzle=inner)
    successor,_,spends=result
    assert successor.amount==31 and successor.puzzle_hash==puzzle.get_tree_hash()
    assert {entry.spend.coin for entry in spends}==set(coins) and len(proofs)==2
    assert len(reads)==1 and reads[0][1]=={'include_spent':False}
    assert all(call['expected_inner_hash']==inner.get_tree_hash() and
        call['expected_tail_hash']==config.permanent_rules.sols_tail_hash for call in proofs)
    for entry in spends:
        assert all(v.first().as_int() not in range(43,51) for v in entry.signing_conditions.as_iter())
        assert Program.from_bytes(bytes(entry.spend.puzzle_reveal)).get_tree_hash()==entry.spend.coin.puzzle_hash
