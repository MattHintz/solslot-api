"""Real partial-offer signatures, durable receipts and cached-only polling."""
from pathlib import Path
from types import SimpleNamespace
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.conditions import CreateCoin
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    puzzle_for_pk, solution_for_conditions, calculate_synthetic_secret_key, DEFAULT_HIDDEN_PUZZLE_HASH)
from chia.wallet.trading.offer import Offer, OFFER_MOD_HASH
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia_rs import AugSchemeMPL, Coin, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver
from solslot_api.generation_sols_batches import GenerationSolsOrderBook

def h(n): return bytes32(bytes([n]) * 32)
GEN = '0x' + h(1).hex(); SOLS = h(2); DEST = h(3)

def offer(*, seed=4, signature=True, expires=2000):
    sk = AugSchemeMPL.key_gen(b'S' * 32)
    wallet = puzzle_for_pk(sk.get_g1()); coin = Coin(h(seed), wallet.get_tree_hash(), uint64(101))
    drivers = {SOLS: chia_cat_driver(SOLS)}
    requested = Offer.notarize_payments({SOLS: [CreateCoin(DEST, uint64(900))]}, [coin])
    spend = make_spend(coin, wallet, solution_for_conditions([[51, OFFER_MOD_HASH, 101], [85, expires],
        *[v.to_program() for v in Offer.calculate_announcements(requested, drivers)]]))
    synthetic = calculate_synthetic_secret_key(sk, DEFAULT_HIDDEN_PUZZLE_HASH)
    cd = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 100_000_000)
    sig = AugSchemeMPL.aggregate([AugSchemeMPL.sign(synthetic, msg) for key, msg in
        pkm_pairs_for_conditions_dict(cd, coin, bytes.fromhex('37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615'))]) if signature else G2Element()
    return Offer(requested, WalletSpendBundle([spend], sig), drivers)

def book(tmp_path): return GenerationSolsOrderBook(str(tmp_path / 'orders.sqlite3'), GEN, SOLS)

def place(b, source): return b.place(source, payment_asset=None, destination=DEST, now=1000)

def test_original_signed_offer_retained_idempotently_and_cached_reads_do_not_write(tmp_path):
    b = book(tmp_path); source = offer(); saved = place(b, source)
    assert saved['stage'] == 'WAITING_FOR_MATCH' and saved['expiresAt'] == 2000
    assert place(b, source) == saved
    original = Path(b.path).read_bytes()
    for _ in range(25): assert b.status(saved['orderId']) == saved
    assert Path(b.path).read_bytes() == original
    reopened = book(tmp_path)
    assert bytes(reopened.original(saved['orderId'])) == bytes(source)
    assert reopened.status(saved['orderId']) == saved
    assert saved['paymentAmount'] == '101' and saved['solsAmount'] == '900'

@pytest.mark.parametrize('fault', ['signature', 'expiry', 'destination', 'asset'])
def test_invalid_offer_cannot_enter_matching(tmp_path, fault):
    b = book(tmp_path); source = offer(signature=fault != 'signature', expires=999 if fault == 'expiry' else 2000)
    with pytest.raises(ValueError):
        b.place(source, payment_asset=h(7) if fault == 'asset' else None,
            destination=h(8) if fault == 'destination' else DEST, now=1000)
    with b.db() as db: assert db.execute('SELECT COUNT(*) FROM sols_orders').fetchone()[0] == 0

def test_competing_offer_cannot_reuse_listed_inputs_or_claim_web_removal_is_cancellation(tmp_path):
    b = book(tmp_path); saved = place(b, offer())
    with pytest.raises(ValueError, match='INPUT_ALREADY_LISTED'): place(b, offer(expires=1900))
    removed = b.remove_from_matching(saved['orderId'])
    assert removed['stage'] == 'REMOVED_FROM_MATCHING' and 'does not cancel' in removed['nextAction']
    assert bytes(b.original(saved['orderId'])) == bytes(offer())

@pytest.mark.asyncio
async def test_spent_input_is_not_reported_as_success_and_confirmed_exact_fill_wins(tmp_path):
    b = book(tmp_path); saved = place(b, offer())
    class Node:
        async def get_coin_record_by_name_primary(self, identity):
            return {'coin_record': {'coin':offer()._bundle.coin_spends[0].coin.to_json_dict(),
                'confirmed_block_index':10,'spent_block_index':11,'spent':True}}
    journal = SimpleNamespace(status=lambda identity: {'stage': 'CONFIRMED','transactionId':GEN,'confirmedHeight':11})
    first = await b.check_inputs(saved['orderId'], provider=Node(), journal=journal, now=1100)
    assert first['stage'] == 'INPUT_SPENT'
    assert first['errorCode'] == 'ORDER_INPUT_SPENT'
    with b.db(write=True) as db:
        db.execute("UPDATE sols_orders SET operation_id=?,stage='READY_TO_SETTLE' WHERE order_id=?", (GEN, saved['orderId']))
    confirmed = await b.check_inputs(saved['orderId'], provider=Node(), journal=journal, now=1101)
    assert confirmed['stage'] == 'FILLED' and confirmed['errorCode'] is None
    assert confirmed['transactionId']==GEN and confirmed['confirmedHeight']==11
    assert 'delivered' in confirmed['nextAction'] and confirmed['pollAfterSeconds']==30
    # Later cancellation/retry observations cannot erase confirmed receipt.
    journal.status = lambda identity: {'stage': 'SUBMITTED'}
    assert (await b.check_inputs(saved['orderId'], provider=Node(), journal=journal, now=1102))['stage'] == 'FILLED'


@pytest.mark.asyncio
async def test_missing_record_can_recover_but_inconsistent_record_cannot_enter_matching(tmp_path):
    b=book(tmp_path);source=offer();saved=place(b,source);coin=source._bundle.coin_spends[0].coin
    class Node:
        raw=None
        async def get_coin_record_by_name_primary(self,identity):return {'coin_record':self.raw}
    node=Node();journal=SimpleNamespace(status=lambda _:None)
    assert (await b.check_inputs(saved['orderId'],provider=node,journal=journal,now=1100))['stage']=='INPUT_UNAVAILABLE'
    node.raw={'coin':coin.to_json_dict(),'confirmed_block_index':10,'spent_block_index':0,'spent':False}
    recovered=await b.check_inputs(saved['orderId'],provider=node,journal=journal,now=1101)
    assert recovered['stage']=='WAITING_FOR_MATCH' and recovered['errorCode'] is None
    node.raw['coin']={**coin.to_json_dict(),'amount':102}
    with pytest.raises(ValueError):await b.check_inputs(saved['orderId'],provider=node,journal=journal,now=1102)
    assert b.status(saved['orderId'])==recovered


def test_receipt_access_and_compression_are_bounded_before_native_review(tmp_path):
    from solslot_api.generation_sols_batches import parse_signed_order
    from chia.util.bech32m import bech32_encode,convertbits
    from chia.wallet.util.puzzle_compression import zdict_for_version
    import zlib
    b=book(tmp_path);source=offer();key='0x'+'aa'*32
    saved=b.place(source,payment_asset=None,destination=DEST,now=1000,receipt_key=key)
    assert b.existing_receipt(source,key)==saved
    b.authorize_receipt(saved['orderId'],key)
    with pytest.raises(ValueError):b.authorize_receipt(saved['orderId'],'0x'+'bb'*32)
    assert bytes(parse_signed_order(source.to_bech32()))==bytes(source)
    compressor=zlib.compressobj(zdict=zdict_for_version(1))
    oversized=(1).to_bytes(2,'big')+compressor.compress(b'Z'*(1_048_576+1))+compressor.flush()
    wire=bech32_encode('offer',convertbits(oversized,8,5))
    with pytest.raises(ValueError,match='COMPRESSION_LIMIT'):parse_signed_order(wire)
