"""Explicit primary-node evidence for fixed reward custody and earned claims."""
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_rewards import RewardFeeInput,RewardCustody,EarnedReward
from .generation_coin_evidence import read_confirmed_coin
from .generation_registry_evidence import _spend


async def verified_reward_inputs(identities,*,provider):
    identities=tuple(identities)
    if not 0<len(identities)<=64 or len(set(identities))!=len(identities):
        raise ValueError('select one to 64 distinct complete reward inputs')
    observed={};inputs=[]
    async def read(identity,*,allow_zero=False):
        record=read_confirmed_coin(await provider.get_coin_record_by_name_primary('0x'+identity.hex()),identity,allow_zero=allow_zero)
        if identity in observed and observed[identity]!=record:raise ValueError('reward funding changed during review')
        observed[identity]=record
        return record
    for identity in identities:
        source=await read(identity)
        if source.spent_height:raise ValueError('reward input is already spent; reconcile its saved transaction')
        parent=await read(source.coin.parent_coin_info,allow_zero=True)
        if parent.spent_height!=source.confirmed_height:
            raise ValueError('reward input lacks its exact atomic confirmed parent')
        spend=_spend(await provider.get_puzzle_and_solution_primary('0x'+parent.coin.name().hex(),parent.spent_height),parent.coin)
        inputs.append(RewardFeeInput(source.coin,spend))
    for identity in tuple(observed):await read(identity,allow_zero=observed[identity].coin.amount==0)
    return tuple(inputs),tuple(observed.values())


async def reward_records_unchanged(records,provider):
    for record in records:
        value=read_confirmed_coin(await provider.get_coin_record_by_name_primary('0x'+record.coin.name().hex()),record.coin.name(),allow_zero=record.coin.amount==0)
        if value!=record:raise ValueError('reward inputs changed before the reviewed action was saved')


def verify_reward_claim_source(claim,source,custody):
    from chia.types.blockchain_format.program import Program
    from chia.wallet.cat_wallet.cat_utils import CAT_MOD
    reveal=Program.from_bytes(bytes(source.parent.puzzle_reveal));mod,args=reveal.uncurry();values=list(args.as_iter())
    inner=reveal
    if claim.asset_id!=bytes32.zeros:
        if mod!=CAT_MOD or len(values)!=3 or values[1].as_atom()!=claim.asset_id:
            raise ValueError('earned reward differs from its exact CAT representation')
        inner=values[2]
    from solslot_puzzles import load_puzzle
    resumed_mod,args=inner.uncurry();resumed=list(args.as_iter())
    from solslot_puzzles.generation_rewards import RewardContinuation
    from solslot_puzzles.holdings import HoldingsTree
    reference=list(RewardContinuation(custody,claim.epoch_id,1,1,0,HoldingsTree({}),HoldingsTree({}),None).inner().uncurry()[1].as_iter())
    resumed_source=(resumed_mod==load_puzzle('generation_reward_resume_v1.clsp') and len(resumed)==len(reference)
        and resumed[:10]==reference[:10] and resumed[12].as_int()==1)
    if inner!=custody.epoch_inner() and not resumed_source:
        raise ValueError('earned reward does not come from this generation authenticated fee custody')
    if source.coin.puzzle_hash!=claim.full().get_tree_hash() or source.coin.amount!=claim.amount:
        raise ValueError('reward claim differs from its exact funded entitlement')


async def verified_reward_progress(identity,*,custody,snapshots,provider):
    """Rebuild bounded pages from their confirmed START and frozen snapshot.

    Saved browser fields do not supply holdings, owners or payout conditions.
    Every intermediate spend must reproduce the native continuation exactly.
    """
    from dataclasses import replace
    from chia.types.blockchain_format.program import Program
    from chia.wallet.cat_wallet.cat_utils import CAT_MOD
    from chia_rs import Coin
    from solslot_puzzles import load_puzzle
    from solslot_puzzles.generation_rewards import RewardContinuation
    from solslot_puzzles.holdings import HoldingsTree
    observed={};path=[]
    async def read_source(coin_id,*,unspent=False):
        raw=await provider.get_coin_record_by_name_primary('0x'+coin_id.hex())
        record=read_confirmed_coin(raw,coin_id)
        if unspent and record.spent_height:raise ValueError('reward progress input already spent; reconcile the saved page')
        parent=read_confirmed_coin(await provider.get_coin_record_by_name_primary('0x'+record.coin.parent_coin_info.hex()),record.coin.parent_coin_info,allow_zero=True)
        if parent.spent_height!=record.confirmed_height:raise ValueError('reward progress lacks its exact confirmed parent')
        for item in (record,parent):
            if item.coin.name() in observed and observed[item.coin.name()]!=item:raise ValueError('reward progress ancestry changed')
            observed[item.coin.name()]=item
        spend=_spend(await provider.get_puzzle_and_solution_primary('0x'+parent.coin.name().hex(),parent.spent_height),parent.coin)
        return RewardFeeInput(record.coin,spend)
    def inner(spend):
        reveal=Program.from_bytes(bytes(spend.puzzle_reveal))
        if custody.asset_id==bytes32.zeros:return reveal
        module,args=reveal.uncurry();values=list(args.as_iter())
        if module!=CAT_MOD or len(values)!=3 or values[1].as_atom()!=custody.asset_id:
            raise ValueError('reward progress asset changed')
        return values[2]
    def solution(spend):
        value=Program.from_bytes(bytes(spend.solution))
        return value if custody.asset_id==bytes32.zeros else value.first()
    current=await read_source(identity,unspent=True);source=current
    for _ in range(1024):
        parent_inner=inner(source.parent)
        if parent_inner==custody.epoch_inner():break
        module,args=parent_inner.uncurry()
        if module!=load_puzzle('generation_reward_resume_v1.clsp'):raise ValueError('reward progress does not descend from authenticated fee custody')
        path.append(source.parent)
        source=await read_source(source.parent.coin.name())
    else:raise ValueError('reward progress ancestry exceeds the bounded recovery read; restore its verified index checkpoint')
    fields=list(solution(source.parent).as_iter())
    if len(fields)!=9 or fields[0].as_atom()!=b'START':raise ValueError('reward progress requires the exact native START receipt')
    group,root,sequence,parameters=fields[2],fields[3],fields[4],fields[7]
    epoch=Program.to([b'SGT_FEE_EPOCH_V1',custody.bindings.generation,custody.asset_id,group,root,sequence,parameters,Program.to([]).get_tree_hash()]).get_tree_hash()
    snapshot=snapshots.get(epoch)
    if snapshot is None or Program.to(snapshot[0].root.program())!=root or snapshot[1]!=sequence.as_int():
        raise ValueError('reward START differs from its authenticated holder snapshot')
    budget=sum(v.at('rf').as_int() for v in group.as_iter())
    progress=RewardContinuation(custody,epoch,snapshot[0].root.eligible,budget,0,snapshot[0],HoldingsTree({}),source)
    if source.coin.puzzle_hash!=progress.full().get_tree_hash() or source.coin.amount!=budget:
        raise ValueError('reward START does not create the exact funded progress state')
    for spend in reversed(path):
        if progress is None:raise ValueError('completed rewards cannot acquire another continuation')
        rows=list(solution(spend).as_iter())
        if len(rows)!=4:raise ValueError('reward progress page changed shape')
        identities=tuple(bytes32(row.first().as_atom()) for row in rows[3].as_iter())
        operation,progress,_=progress.advance(identities,limit=16)
        if operation.spends!=(spend,):raise ValueError('reward page differs from exact native reconstruction')
    if progress is None or progress.source.coin!=current.coin:raise ValueError('reward progress does not match the current confirmed coin')
    await reward_records_unchanged(tuple(observed.values()),provider)
    return progress,tuple(observed.values())
