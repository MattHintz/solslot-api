"""Checkpoint a fully signed purchase before submission and confirm its exact effects."""
import asyncio
import json

from chia_rs import SpendBundle
from chia_rs.sized_bytes import bytes32

from .generation_coin_evidence import read_confirmed_coin
from .generation_operations import bundle_id
from .generation_registry_evidence import _spend
from .protocol_admission import admission_conditions


class SettlementConflict(ValueError):
    """A primary-chain observation conflicts with the saved transaction."""


def migrate_settlement_receipts(db):
    db.execute('''CREATE TABLE IF NOT EXISTS current_native_settlements (
        intent_id TEXT PRIMARY KEY REFERENCES current_native_carts(intent_id),
        bundle_id TEXT NOT NULL UNIQUE,
        signed_bundle BLOB NOT NULL,
        outputs_json TEXT NOT NULL)''')


def save_settlement(store, identity, purchase, *, browser_hash, forwarding_spends, signed, height, now):
    """Only the exact approved offer and independently reconstructed protocol spends can proceed."""
    if not isinstance(signed, SpendBundle):
        raise ValueError('Fully signed settlement required')
    expected = purchase.bundle(forwarding_spends)
    if signed.coin_spends != expected.coin_spends:
        raise ValueError('Settlement spends differ from the buyer purchase')
    conditions = admission_conditions(signed, height, 'testnet11')
    if int(conditions.reserve_fee) != purchase.network_fee_mojos:
        raise ValueError('Approved fee differs from final settlement')
    raw = bytes(signed)
    tx = bundle_id(signed)
    outputs = json.dumps([o.coin_id for o in purchase.delivery_outputs])
    offer = purchase.buyer_offer.to_bech32()
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        _, claim = store._row(db, identity, browser_hash)
        cart = db.execute('SELECT state,expires_at,offer FROM current_native_carts WHERE intent_id=?', (identity,)).fetchone()
        if claim.digest()!=purchase.claim_digest or cart is None or cart['offer']!=offer or cart['state'] not in ('APPROVED','CONFIRMED'):
            raise ValueError('A matching approved cart is required')
        saved = db.execute('SELECT bundle_id,signed_bundle,outputs_json FROM current_native_settlements WHERE intent_id=?',(identity,)).fetchone()
        if saved is not None:
            if tuple(saved)!=(tx,raw,outputs):
                raise ValueError('A different settlement is already recorded')
            return tx
        if cart['expires_at'] <= now or conditions.before_seconds_absolute != cart['expires_at']:
            raise ValueError('Final transaction does not fit the approved cart window')
        if len(raw)>store.MAX_EXECUTION_BYTES:
            raise ValueError('Settlement exceeds supported size')
        store._execution_capacity(db,len(raw)+len(outputs)+256)
        db.execute('INSERT INTO current_native_settlements VALUES(?,?,?,?)',(identity,tx,raw,outputs))
        db.execute('UPDATE current_native_carts SET settlement_id=? WHERE intent_id=?',(tx,identity))
        db.commit()
        return tx


async def confirm_settlement(store, identity, *, browser_hash, provider):
    """Compare each spent puzzle and solution and both the height and ID of every delivered deed."""
    with store._connect() as db:
        store._row(db,identity,browser_hash)
        row=db.execute('SELECT bundle_id,signed_bundle,outputs_json FROM current_native_settlements WHERE intent_id=?',(identity,)).fetchone()
    if row is None:
        raise ValueError('Saved transaction required')
    bundle=SpendBundle.from_bytes(row['signed_bundle'])
    if bundle_id(bundle)!=row['bundle_id']:
        raise ValueError('Saved transaction changed')
    async def peak():
        reply = await provider.get_blockchain_state_primary()
        chain = reply['blockchain_state']
        if chain['sync']['synced'] is not True or chain['sync']['sync_mode'] is not False:
            raise ValueError('CURRENT_CHECKOUT_PRIMARY_UNAVAILABLE')
        return int(chain['peak']['height']), bytes32.from_hexstr(chain['peak']['header_hash'])

    async def spend_height(spend):
        name = spend.coin.name()
        raw = await provider.get_coin_record_by_name_primary('0x' + name.hex())
        if not raw:
            return None
        record = read_confirmed_coin(raw, name, allow_zero=True)
        if not record.spent_height:
            return None
        solution = await provider.get_puzzle_and_solution_primary('0x' + name.hex(), record.spent_height)
        if bytes(_spend(solution, spend.coin)) != bytes(spend):
            raise SettlementConflict('The recorded input was spent differently')
        return record.spent_height

    async def delivery_height(name):
        record = read_confirmed_coin(await provider.get_coin_record_by_name_primary(name), bytes32.from_hexstr(name))
        return record.confirmed_height

    start_peak = await peak()
    height = None
    for start in range(0, len(bundle.coin_spends), 4):
        observed = await asyncio.gather(*(spend_height(spend) for spend in bundle.coin_spends[start:start+4]))
        if any(value is None for value in observed):
            return None
        height = height or observed[0]
        if any(value != height for value in observed):
            raise SettlementConflict('The expected spends did not confirm together')
    outputs = json.loads(row['outputs_json'])
    for start in range(0, len(outputs), 4):
        delivered = await asyncio.gather(*(delivery_height(name) for name in outputs[start:start+4]))
        if any(value != height for value in delivered):
            raise SettlementConflict('Delivery height differs from settlement')
    if height is None or height > start_peak[0] or await peak() != start_peak:
        return None
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        updated=db.execute("""UPDATE current_native_carts SET state='CONFIRMED',confirmed_height=?
            WHERE intent_id=? AND settlement_id=? AND (state='APPROVED' OR (state='CONFIRMED' AND confirmed_height=?))""",
            (height,identity,row['bundle_id'],height)).rowcount
        if updated!=1:
            raise ValueError('Checkout changed during confirmation')
        db.execute('UPDATE current_native_cart_items SET active=0 WHERE intent_id=?',(identity,))
        db.commit()
    return {'transactionId':row['bundle_id'],'confirmedHeight':height,'deedCoinIds':json.loads(row['outputs_json'])}
