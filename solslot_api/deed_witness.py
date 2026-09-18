"""Recover primary-purchase deed terms only under their chain commitment."""
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.mint_publish_driver import make_smart_deed_inner
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from solslot_puzzles.real_estate_profiles import ASSET_CLASS_CODES


def primary_deed_inner(*, record, deed_id: bytes32, deed_struct: Program,
                       inventory_args: list[Program], config, artifact) -> Program:
    """The record supplies a preimage, never authority over immutable terms."""
    if (record is None or record.state not in ('EXECUTED', 'MINTED')
        or record.deed_launcher_id != bytes(deed_id)
        or len(inventory_args) != 30
        or inventory_args[9].as_atom() != bytes(deed_id)):
        raise ValueError('confirmed primary deed has no matching executed mint witness')
    asset_class = ASSET_CLASS_CODES.get(record.asset_class.upper())
    if asset_class is None:
        raise ValueError('mint witness has unsupported asset class')
    inner = make_smart_deed_inner(deed_singleton_struct_program=deed_struct,
        protocol_did_puzhash=bytes32.from_hexstr(artifact['puzzleHashes']['didFullPuzzleHash']),
        par_value_mojos=record.par_value, asset_class=int(asset_class),
        property_id_canon=canonicalise_property_id(record.property_id),
        collection_id_canon=canonicalise_property_id(record.collection_id),share_ppm=record.share_ppm,
        jurisdiction=record.jurisdiction.encode('utf-8'),royalty_puzhash=bytes32(record.royalty_puzhash),
        royalty_bps=record.royalty_bps,pool_singleton_launcher_id=config.pool_launcher_id,
        pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
        p2_pool_mod_hash=config.p2_pool_v2_mod_hash,p2_vault_mod_hash=config.p2_vault_mod_hash)
    expected = bytes(inner.get_tree_hash())
    if (inventory_args[1].as_atom() != expected or record.smart_deed_inner_puzhash != expected
        or inventory_args[10].as_atom() != bytes(canonicalise_property_id(record.collection_id))
        or inventory_args[13].as_int() != record.share_ppm):
        raise ValueError('mint witness does not match the confirmed primary deed commitment')
    return inner
