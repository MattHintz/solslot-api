"""Confirmed SGT receipt lineage, including reserve grants and unlocked stakes."""
from .cat_lineage import confirmed_cat_receipt_lineage


async def confirmed_sgt_lineage(*, provider, coin, expected_inner_hash, expected_tail_hash):
    return await confirmed_cat_receipt_lineage(provider=provider, coin=coin,
        expected_inner_hash=expected_inner_hash, expected_tail_hash=expected_tail_hash,
        asset_label='SGT')
