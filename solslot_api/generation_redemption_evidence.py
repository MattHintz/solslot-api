"""Exact primary-node funding evidence, read only on an explicit review."""
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_redemptions import TreasuryInput
from .generation_coin_evidence import read_confirmed_coin
from .generation_registry_evidence import _spend


async def verified_redemption_source(intent, *, governance, provider):
    observed = {}
    async def read(identity):
        value = read_confirmed_coin(await provider.get_coin_record_by_name_primary('0x'+identity.hex()), identity)
        if identity in observed and observed[identity] != value:
            raise ValueError('redemption funding changed during review')
        observed[identity] = value
        return value
    record = await read(bytes32.from_hexstr(intent.treasury_coin_id))
    if record.spent_height or record.coin.parent_coin_info != bytes32.from_hexstr(intent.treasury_parent_id):
        raise ValueError('redemption treasury input is spent or its parent changed')
    parent = await read(record.coin.parent_coin_info)
    if parent.spent_height != record.confirmed_height:
        raise ValueError('treasury parent is not the atomic confirmed funding source')
    spend = _spend(await provider.get_puzzle_and_solution_primary('0x'+parent.coin.name().hex(), parent.spent_height), parent.coin)
    source = TreasuryInput(record.coin, spend)
    source.validate(governance, intent.plan(), bytes32.from_hexstr(intent.deed_launcher_puzzle_hash))
    for identity in tuple(observed): await read(identity)
    return source, tuple(observed.values())


async def redemption_inputs_unchanged(records, provider):
    for record in records:
        current = read_confirmed_coin(await provider.get_coin_record_by_name_primary('0x'+record.coin.name().hex()), record.coin.name())
        if current != record:
            raise ValueError('confirmed redemption funding changed before the review was saved')
