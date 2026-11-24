from dataclasses import replace
from types import SimpleNamespace

from chia_rs.sized_bytes import bytes32
import pytest

from solslot_api.generation_customer_cat_test_window import CatTestWindow
from solslot_api.generation_customer_collection_policy import CheckoutCat, read_collection_issuer_policy
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from tests.test_current_collection_issuer_policy import make_policy, save


def key(n):
    return bytes32(bytes([n]) * 32)


@pytest.fixture
def window():
    return CatTestWindow(key(10), key(11), 3_030_000, 1_000, 4_600)


def inputs(window):
    item = dict(network='testnet11', rail=PaymentRail.CHIA_CAT, vault_launcher_id=window.vault,
                rail_asset_id=window.asset, rail_amount=window.amount_per_deed, quote_expires_at=2_400)
    return [SimpleNamespace(**item, deed_launcher_id=key(index)) for index in (1, 2)]


def test_scoped_policy_round_trip_preserves_custody_but_binds_the_window(tmp_path, window):
    legacy, _ = make_policy()
    cat = CheckoutCat(window.asset, 'SLTC', 3, 100, 3_030_000)
    standing = replace(legacy, checkout_cats=(cat,))
    scoped = replace(standing, test_window=window)
    assert scoped.commitment == standing.commitment
    assert scoped.asset_policy_hash != standing.asset_policy_hash
    assert read_collection_issuer_policy(*save(tmp_path, scoped.public())) == scoped
    document = scoped.public()
    document['singleCatOrder']['quantity'] = 3
    with pytest.raises(ValueError):
        read_collection_issuer_policy(*save(tmp_path, document))


@pytest.mark.parametrize('change', [
    {'ends_at': 4_601}, {'ends_at': 999}, {'starts_at': True}, {'asset': bytes32.zeros},
    {'vault': bytes32.zeros}, {'amount_per_deed': False},
])
def test_invalid_window(window, change):
    with pytest.raises(ValueError):
        replace(window, **change).validate()


@pytest.mark.parametrize('field,value', [
    ('network', 'mainnet'), ('rail', PaymentRail.CHIA_XCH), ('rail_asset_id', key(12)),
    ('vault_launcher_id', key(13)), ('rail_amount', 3_029_999), ('quote_expires_at', 4_601),
    ('quote_expires_at', 1_100), ('deed_launcher_id', key(1)),
])
def test_both_deeds_must_match(window, field, value):
    items = inputs(window)
    window.require_artifacts(items, buyer_paid=True, now=1_100)
    setattr(items[1], field, value)
    with pytest.raises(ValueError):
        window.require_artifacts(items, buyer_paid=True, now=1_100)


@pytest.mark.parametrize('quantity,mode,time', [(1, True, 1_100), (3, True, 1_100),
                                                  (2, False, 1_100), (2, True, 999), (2, True, 4_600)])
def test_window_bounds(window, quantity, mode, time):
    with pytest.raises(ValueError):
        window.require_order(window.vault, window.asset, quantity, mode, time)
