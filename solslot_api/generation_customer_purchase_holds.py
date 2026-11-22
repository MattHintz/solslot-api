"""Durable stock holds before an on-chain purchase. An unpaid expiry is local."""
import sqlite3

from .generation_customer_purchase_batch import CurrentReservationBatch, artifacts


def migrate_native_holds(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS current_native_quote_modes (
            intent_id TEXT PRIMARY KEY REFERENCES current_customer_purchase_reviews(intent_id));
        CREATE TABLE IF NOT EXISTS current_native_carts (
            intent_id TEXT PRIMARY KEY REFERENCES current_customer_purchase_reviews(intent_id),
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('HELD','APPROVED','EXPIRED','CANCELED','CONFIRMED')),
            offer TEXT,
            settlement_id TEXT,
            confirmed_height INTEGER);
        CREATE TABLE IF NOT EXISTS current_native_cart_approvals (
            intent_id TEXT PRIMARY KEY REFERENCES current_native_carts(intent_id),
            approval_digest TEXT NOT NULL UNIQUE,
            approval_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS current_native_payment_reviews (
            intent_id TEXT NOT NULL REFERENCES current_native_carts(intent_id),
            spend_hash TEXT NOT NULL,
            wallet_selection TEXT NOT NULL,
            PRIMARY KEY(intent_id, spend_hash));
        CREATE TABLE IF NOT EXISTS current_native_expiries (
            intent_id TEXT PRIMARY KEY REFERENCES current_native_carts(intent_id),
            proof_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS current_native_cart_outputs (
            intent_id TEXT PRIMARY KEY REFERENCES current_native_carts(intent_id),
            output_ids TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS current_native_cart_items (
            intent_id TEXT NOT NULL REFERENCES current_native_carts(intent_id),
            coin_id TEXT NOT NULL,
            active INTEGER NOT NULL CHECK(active IN (0,1)),
            PRIMARY KEY(intent_id,coin_id));
        CREATE UNIQUE INDEX IF NOT EXISTS current_native_held_coin
            ON current_native_cart_items(coin_id) WHERE active=1;
    ''')


def cart_inputs(claim):
    children = claim.children if isinstance(claim, CurrentReservationBatch) else (claim,)
    return tuple(child.available_coin_id for child in children)


def expire_unsigned(db, now):
    db.execute("UPDATE current_native_carts SET state='EXPIRED' WHERE state='HELD' AND expires_at<=?", (now,))
    db.execute("""UPDATE current_native_cart_items SET active=0 WHERE active=1 AND intent_id IN (
               SELECT intent_id FROM current_native_carts WHERE state='EXPIRED')""")


def guard_legacy_reservation(db, identity, claim, now):
    expire_unsigned(db, now)
    if db.execute('SELECT 1 FROM current_native_carts WHERE intent_id=?', (identity,)).fetchone():
        raise ValueError('Checkout is bound to an off-chain cart')
    coins = cart_inputs(claim)
    placeholders = ','.join('?' for _ in coins)
    if db.execute(f'SELECT 1 FROM current_native_cart_items WHERE active=1 AND coin_id IN ({placeholders})', coins).fetchone():
        raise ValueError('CURRENT_PRIMARY_DEED_NOT_AVAILABLE')


def hold_cart(store, identity, *, browser_hash, now):
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        _, claim = store._row(db, identity, browser_hash)
        expire_unsigned(db, now)
        row = db.execute('SELECT state,expires_at FROM current_native_carts WHERE intent_id=?', (identity,)).fetchone()
        if row is None:
            deadline = artifacts(claim)[0].quote_expires_at
            if now >= deadline:
                raise ValueError('Checkout quote expired')
            for table in ('current_customer_reservation_requests', 'current_purchase_executions',
                          'current_customer_purchase_signatures', 'current_customer_purchase_delivery'):
                if db.execute(f'SELECT 1 FROM {table} WHERE intent_id=?', (identity,)).fetchone():
                    raise ValueError('Existing checkout requires on-chain recovery')
            store._admit_reservation(db, identity, claim, check_inventory=True)
            store._require_unreserved_inventory(db, identity, claim)
            coins = cart_inputs(claim)
            store._execution_capacity(db, 256 + 128 * len(coins))
            db.execute("INSERT INTO current_native_carts(intent_id,expires_at,state) VALUES(?,?,'HELD')", (identity,deadline))
            try:
                db.executemany('INSERT INTO current_native_cart_items VALUES(?,?,1)', [(identity,coin) for coin in coins])
            except sqlite3.IntegrityError as exc:
                raise ValueError('CURRENT_PRIMARY_DEED_NOT_AVAILABLE') from exc
            state, deadline = 'HELD', deadline
        else:
            state, deadline = row
        db.commit()
        return {'intentId':identity,'state':state,'expiresAt':deadline}


def cancel_cart(store, identity, *, browser_hash, now):
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        store._row(db, identity, browser_hash)
        expire_unsigned(db, now)
        row = db.execute('SELECT state FROM current_native_carts WHERE intent_id=?', (identity,)).fetchone()
        if row is None or row[0] not in ('HELD','CANCELED','EXPIRED'):
            raise ValueError('Only unpaid carts can be canceled locally')
        if row[0] == 'HELD':
            db.execute("UPDATE current_native_carts SET state='CANCELED' WHERE intent_id=?", (identity,))
            db.execute('UPDATE current_native_cart_items SET active=0 WHERE intent_id=?', (identity,))
        db.commit()
        return 'CANCELED' if row[0]=='HELD' else row[0]


def hold_verified_cart(store, identity, evidence, *, browser_hash, now):
    import json
    from .generation_customer_purchase_atomic import purchase_inputs
    from .generation_customer_purchase_batch import h
    children, _, _ = purchase_inputs(evidence)
    outputs = json.dumps([h(child.transition.reserved_coin.name()) for child in children])
    hold_cart(store, identity, browser_hash=browser_hash, now=now)
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        _, claim = store._row(db, identity, browser_hash)
        if claim.digest() != evidence.claim.digest():
            raise ValueError('CURRENT_CHECKOUT_CART_TERMS_CHANGED')
        db.execute('INSERT OR IGNORE INTO current_native_cart_outputs VALUES(?,?)', (identity, outputs))
        if db.execute('SELECT output_ids FROM current_native_cart_outputs WHERE intent_id=?',(identity,)).fetchone()[0] != outputs:
            raise ValueError('CURRENT_CHECKOUT_CART_TERMS_CHANGED')
        db.commit()


def cart_status(store, identity, *, browser_hash, now):
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        store._row(db, identity, browser_hash)
        expire_unsigned(db, now)
        row = db.execute(
            'SELECT expires_at, state, settlement_id, confirmed_height FROM current_native_carts WHERE intent_id=?',
            (identity,),
        ).fetchone()
        if row is None:
            raise ValueError('CURRENT_CHECKOUT_HOLD_REQUIRED')
        db.commit()
        return {'intentId': identity, 'state': row['state'], 'expiresAt': row['expires_at'],
                'transactionId': row['settlement_id'], 'confirmedHeight': row['confirmed_height']}


def retain_approved_cart(store, identity, verified, *, browser_hash, now):
    """Save the verified authorization before contacting private signers."""
    from .generation_customer_purchase_atomic_signing import ApprovedSettlement
    if not isinstance(verified, ApprovedSettlement):
        raise ValueError('Verified buyer purchase required')
    approval, purchase = verified.claim, verified.purchase
    if purchase.buyer_offer.to_bech32() != approval.buyer_offer or purchase.network_fee_mojos != approval.network_fee_mojos:
        raise ValueError('Buyer authorization differs from verified offer')
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        _, claim = store._row(db, identity, browser_hash)
        if purchase.claim_digest != claim.digest() or approval.reservation != claim:
            raise ValueError('Buyer approval differs from saved checkout')
        cart = db.execute('SELECT state,expires_at FROM current_native_carts WHERE intent_id=?', (identity,)).fetchone()
        if cart is None:
            raise ValueError('CURRENT_CHECKOUT_HOLD_REQUIRED')
        retained = db.execute('SELECT approval_digest FROM current_native_cart_approvals WHERE intent_id=?',
                              (identity,)).fetchone()
        digest = approval.digest()
        if retained is not None:
            if retained['approval_digest'] != digest:
                raise ValueError('A different buyer approval is already saved')
            return cart['state']
        if cart['state'] != 'HELD' or cart['expires_at'] <= now:
            raise ValueError('CURRENT_CHECKOUT_HOLD_EXPIRED')
        document = approval.canonical()
        store._execution_capacity(db, len(document) + len(approval.buyer_offer) + 256)
        db.execute('INSERT INTO current_native_cart_approvals VALUES(?,?,?)', (identity, digest, document))
        db.execute("UPDATE current_native_carts SET state='APPROVED', offer=? WHERE intent_id=?",
                   (approval.buyer_offer, identity))
        db.commit()
        return 'APPROVED'


def saved_approval(store, identity, *, browser_hash):
    from .generation_customer_purchase_atomic_signing import AtomicBuyerApproval
    with store._connect() as db:
        _, claim = store._row(db, identity, browser_hash)
        row = db.execute('SELECT approval_digest, approval_json FROM current_native_cart_approvals WHERE intent_id=?',
                         (identity,)).fetchone()
        if row is None:
            return None
        approval = AtomicBuyerApproval.model_validate_json(row['approval_json'])
        if approval.reservation != claim or approval.digest() != row['approval_digest']:
            raise ValueError('CURRENT_CHECKOUT_SAVED_APPROVAL_CHANGED')
        return approval
