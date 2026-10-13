"""Exact primary-node CAT parents for explicit holder actions, never polling."""
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_ballots import SGTInput, MAX_BALLOT_INPUTS
from solslot_puzzles.generation_sgt import SGTOutput
from .generation_registry_evidence import _spend
from .generation_coin_evidence import read_confirmed_coin


def _record(raw, expected):
    return read_confirmed_coin(raw,expected)


async def verified_sgt_inputs(coin_ids,*,bindings,tree,provider):
    ids=tuple(coin_ids)
    if not 0<len(ids)<=MAX_BALLOT_INPUTS or len(set(ids))!=len(ids):
        raise ValueError('select one to 32 distinct complete SGT holdings')
    inputs,observed=[],{}
    async def read(identity):
        result=_record(await provider.get_coin_record_by_name_primary('0x'+identity.hex()),identity)
        if identity in observed and observed[identity]!=result:
            raise ValueError('SGT confirmation changed during review')
        observed[identity]=result
        return result
    for identity in ids:
        holding=tree.holdings.get(identity)
        if holding is None:raise ValueError('SGT input is absent from the authenticated holdings ledger')
        record=await read(identity)
        descriptor=SGTOutput(holding.kind,holding.owner_hash,holding.amount,holding.lock_id)
        if (record.spent_height or record.coin.puzzle_hash!=holding.puzzle_hash
                or record.coin.puzzle_hash!=descriptor.full(bindings).get_tree_hash() or record.coin.amount!=holding.amount):
            raise ValueError('SGT input is spent or differs from the authenticated holding')
        parent=await read(record.coin.parent_coin_info)
        if parent.spent_height!=record.confirmed_height:
            raise ValueError('SGT parent is not the atomic confirmed source of this input')
        spend=_spend(await provider.get_puzzle_and_solution_primary('0x'+parent.coin.name().hex(),parent.spent_height),parent.coin)
        item=SGTInput(record.coin,descriptor,spend)
        item.validate(bindings)
        inputs.append(item)
    # Reorgs or concurrent transfers invalidate preparation before anything
    # can be saved. Final native admission rechecks these inputs at dispatch.
    for identity in tuple(observed):await read(identity)
    return tuple(inputs)
