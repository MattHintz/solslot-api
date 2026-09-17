"""RPC consistency controls; these synthetic records are not chain proofs."""
from copy import deepcopy

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_api import sols_market as market


def hx(value):
    return "0x" + bytes(value).hex()


def record(parent, puzzle, confirmed, spent=0, amount=1):
    coin = Coin(bytes32.fromhex(parent[2:]), puzzle.get_tree_hash(), uint64(amount))
    return hx(coin.name()), dict(coin=coin.to_json_dict(), confirmed_block_index=confirmed,
                               spent_block_index=spent, spent=bool(spent))


class Chain:
    def __init__(self, depth=2, *, same_block=False, amount=1):
        self.records = {}
        self.children = {}
        self.spends = {}
        self.ids = []
        self.reads = []
        self.on_read = None
        parent = hx(bytes([9]) * 32)
        for i in range(depth + 1):
            puzzle = Program.to(1)
            height = 100 if same_block else 100 + i
            spent = (height if same_block else height + 1) if i < depth else 0
            name, row = record(parent, puzzle, height, spent, amount)
            self.ids.append(name)
            self.records[name] = row
            self.children[parent] = [row]
            self.spends[name] = dict(coin=deepcopy(row['coin']),
                                     puzzle_reveal=bytes(puzzle).hex(),
                                     solution=bytes(Program.to([[51, puzzle.get_tree_hash(), amount]])).hex())
            parent = name
        self.launcher = self.ids[0]
        self.tip = self.ids[-1]

    async def get_coin_record_by_name(self, name):
        self.reads.append(name)
        value = deepcopy(self.records.get(name))
        return self.on_read(name, value) if self.on_read else value

    async def get_coin_records_by_parent_ids(self, names, *, include_spent):
        assert include_spent and len(names) == 1
        return deepcopy(self.children.get(names[0], []))

    async def get_puzzle_and_solution(self, name, height):
        assert height == self.records[name]['spent_block_index']
        return deepcopy(self.spends.get(name))


@pytest.mark.asyncio
@pytest.mark.parametrize('depth', [0, 1, 2, 3])
@pytest.mark.parametrize('same_block', [False, True])
async def test_confirmed_launcher_eve_and_successors(depth, same_block):
    chain = Chain(depth, same_block=same_block)
    tip = await market._singleton_tip(chain, chain.launcher)
    assert tip.launcher_id == chain.launcher and tip.live.coin_id == chain.tip
    assert tip.depth == depth and len(tip.lineage) == depth + 1
    result = await market._latest_solution(chain, tip)
    assert (result is None) == (depth < 2)
    if result:
        assert result == chain.spends[chain.ids[-2]]


@pytest.mark.asyncio
async def test_absent_launcher_retains_none():
    chain = Chain()
    assert await market._singleton_tip(chain, hx(bytes(32))) is None


@pytest.mark.asyncio
async def test_side_outputs_and_uppercase_hex_are_compatible():
    chain = Chain(amount=3)
    _, side = record(chain.launcher, Program.to(1), 101, amount=2)
    chain.children[chain.launcher].append(side)
    for row in chain.records.values():
        for field in ['parent_coin_info', 'puzzle_hash']:
            row['coin'][field] = row['coin'][field].upper().removeprefix('0X')
    tip = await market._singleton_tip(chain, chain.launcher.upper().removeprefix('0X'))
    assert tip.live.coin_id == chain.tip and tip.live.amount == 3


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['foreign_launcher', 'foreign_parent', 'height_gap',
    'unconfirmed', 'ambiguous', 'changed_amount', 'missing_child', 'spent_before_confirmed',
    'flag_disagrees', 'flag_string', 'amount_bool', 'amount_float', 'amount_string',
    'height_bool', 'height_string', 'height_overflow', 'missing_height', 'missing_spent',
    'spent_float', 'negative_height', 'even_launcher', 'zero_launcher', 'malformed_child'])
async def test_unrelated_and_malformed_lineage_is_rejected(mutation):
    # Stop at the substituted record so a missing later child cannot mask the gap.
    chain = Chain(1 if mutation == 'foreign_parent' else 2)
    if mutation == 'foreign_launcher':
        chain.records[chain.launcher].update(spent=False, spent_block_index=0)
    launcher = chain.records[chain.launcher]
    child = chain.children[chain.launcher][0]
    if mutation == 'foreign_launcher': launcher['coin']['parent_coin_info'] = hx(bytes([77]) * 32)
    elif mutation == 'foreign_parent': child['coin']['parent_coin_info'] = hx(bytes([77]) * 32)
    elif mutation == 'height_gap': child['confirmed_block_index'] += 1
    elif mutation == 'unconfirmed': launcher['confirmed_block_index'] = 0
    elif mutation == 'ambiguous': chain.children[chain.launcher].append(deepcopy(child))
    elif mutation == 'changed_amount': child['coin']['amount'] = 3
    elif mutation == 'missing_child': chain.children[chain.launcher] = []
    elif mutation == 'spent_before_confirmed': launcher['spent_block_index'] = 99
    elif mutation == 'flag_disagrees': launcher['spent'] = False
    elif mutation == 'flag_string': launcher['spent'] = 'true'
    elif mutation.startswith('amount_'): launcher['coin']['amount'] = {'amount_bool':True,'amount_float':1.0,'amount_string':'1'}[mutation]
    elif mutation == 'height_bool': launcher['confirmed_block_index'] = True
    elif mutation == 'height_string': launcher['confirmed_block_index'] = '100'
    elif mutation == 'height_overflow': launcher['confirmed_block_index'] = 2**32
    elif mutation == 'missing_height': del launcher['confirmed_block_index']
    elif mutation == 'missing_spent': del launcher['spent_block_index']
    elif mutation == 'spent_float': launcher['spent_block_index'] = 101.0
    elif mutation == 'negative_height': launcher['confirmed_block_index'] = -1
    elif mutation == 'even_launcher': chain = Chain(amount=2)
    elif mutation == 'zero_launcher': chain = Chain(amount=0)
    elif mutation == 'malformed_child': chain.children[chain.launcher].append(None)
    with pytest.raises(ValueError):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['tip_spent', 'tip_missing', 'tip_height', 'launcher_reorg'])
async def test_observations_changed_during_traversal_reject(mutation):
    chain = Chain()
    def on_read(name, row):
        if name == chain.tip:
            if mutation == 'tip_spent': row.update(spent=True, spent_block_index=103)
            elif mutation == 'tip_missing': return None
            elif mutation == 'tip_height': row['confirmed_block_index'] += 1
        elif name == chain.launcher and chain.reads.count(name) > 1 and mutation == 'launcher_reorg':
            row['confirmed_block_index'] -= 1
        return row
    chain.on_read = on_read
    with pytest.raises(ValueError):
        await market._singleton_tip(chain, chain.launcher)


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['missing', 'foreign_coin', 'missing_coin', 'wrong_puzzle',
    'malformed_puzzle', 'trailing_puzzle', 'malformed_solution', 'trailing_solution',
    'oversized_solution', 'noncanonical_atom', 'missing_solution'])
async def test_latest_spend_is_bound_and_canonical(mutation):
    chain = Chain()
    tip = await market._singleton_tip(chain, chain.launcher)
    value = chain.spends[chain.ids[-2]]
    if mutation == 'missing': del chain.spends[chain.ids[-2]]
    elif mutation == 'foreign_coin': value['coin'] = chain.spends[chain.launcher]['coin']
    elif mutation == 'missing_coin': del value['coin']
    elif mutation == 'wrong_puzzle': value['puzzle_reveal'] = '80'
    elif mutation == 'malformed_puzzle': value['puzzle_reveal'] = 'ff'
    elif mutation == 'trailing_puzzle': value['puzzle_reveal'] += '80'
    elif mutation == 'malformed_solution': value['solution'] = 'ff'
    elif mutation == 'trailing_solution': value['solution'] = '8080'
    elif mutation == 'oversized_solution': value['solution'] = '80' * (2**21 + 1)
    elif mutation == 'noncanonical_atom': value['solution'] = '8101'
    elif mutation == 'missing_solution': del value['solution']
    with pytest.raises(ValueError):
        await market._latest_solution(chain, tip)


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['spent_height', 'tip_spent'])
async def test_spend_lookup_rechecks_observations(mutation):
    chain = Chain()
    tip = await market._singleton_tip(chain, chain.launcher)
    def on_read(name, row):
        if mutation == 'spent_height' and name == chain.ids[-2]: row['spent_block_index'] += 1
        if mutation == 'tip_spent' and name == chain.tip: row.update(spent=True, spent_block_index=103)
        return row
    chain.on_read = on_read
    with pytest.raises(ValueError, match='changed during'):
        await market._latest_solution(chain, tip)


@pytest.mark.asyncio
async def test_accepted_program_bytes_are_detached_before_await():
    chain = Chain()
    tip = await market._singleton_tip(chain, chain.launcher)
    response = chain.spends[chain.ids[-2]]
    original_solution = response['solution']
    async def fetch(*_args): return response
    chain.get_puzzle_and_solution = fetch
    def on_read(_name, row):
        response['solution'] = 'ff'
        response['coin']['amount'] = 77
        return row
    chain.on_read = on_read
    accepted = await market._latest_solution(chain, tip)
    assert accepted['solution'] == original_solution and accepted['coin']['amount'] == 1


@pytest.mark.asyncio
async def test_lineage_depth_bound_remains(monkeypatch):
    chain = Chain()
    monkeypatch.setattr(market, 'MAX_SINGLETON_DEPTH', 1)
    with pytest.raises(ValueError, match='safety limit'):
        await market._singleton_tip(chain, chain.launcher)
