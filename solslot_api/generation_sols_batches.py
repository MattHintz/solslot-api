"""Bounded, generation-scoped order receipts and exact batch dispatch.

Receipt/status reads never rebuild, sign or select coins. The original offer
is retained. A wallet cancellation remains a competing chain spend; removing
an order from matching never claims to have cancelled that signed offer.
"""
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3

from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL,G2Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_batch_orders import inspect_buyer_offer
from solslot_puzzles.generation_batch_settlement import PrimaryBatchSettlement
from solslot_puzzles.generation_transactions import NativeOperation
from .generation_context import generation_bytes
from .generation_storage import connect_generation_sqlite, generation_path, admit_retained_bytes
from .generation_operations import canonical, submit_saved_operation

MAX_ORDERS = 512
MAX_RETAINED_BYTES = 128 * 1024 * 1024


def external_inputs(offer):
    bundle = offer._bundle
    children = {c.name() for s in bundle.coin_spends for c in
        compute_additions(s)}
    return tuple(c for c in bundle.removals() if c.name() not in children)


TESTNET11_SIGNATURE_DATA=bytes.fromhex('37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615')


def verify_order_signature(offer,*,additional_data=TESTNET11_SIGNATURE_DATA):
    public, messages = [], []
    for spend in offer._bundle.coin_spends:
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 100_000_000)
        for key, message in pkm_pairs_for_conditions_dict(conditions, spend.coin, additional_data):
            public.append(key); messages.append(message)
    # EVM authorization is verified inside its exact native puzzle. It may
    # emit no BLS conditions, but must then carry the canonical empty aggregate.
    if ((public and not AugSchemeMPL.aggregate_verify(public,messages,offer._bundle.aggregated_signature))
            or (not public and offer._bundle.aggregated_signature!=G2Element())):
        raise ValueError('ORDER_SIGNATURE_INVALID')


class GenerationSolsOrderBook:
    def __init__(self, path, generation_id, sols_asset, approved_assets=frozenset(),*,signature_data=TESTNET11_SIGNATURE_DATA):
        self.generation_id = '0x' + generation_bytes(generation_id).hex()
        self.generation = bytes32(generation_bytes(generation_id))
        self.sols_asset = sols_asset
        self.approved_assets = frozenset(approved_assets)
        self.signature_data=signature_data
        self.path = generation_path(path, self.generation_id)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600); os.close(fd)
        with self.db() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS sols_orders (
                order_id TEXT PRIMARY KEY, original_offer BLOB NOT NULL,
                asset TEXT, destination TEXT NOT NULL, payment TEXT NOT NULL,
                sols TEXT NOT NULL, input_ids TEXT NOT NULL, expires_at INTEGER,
                received_at INTEGER NOT NULL, stage TEXT NOT NULL,
                operation_id TEXT, error_code TEXT, last_checked_at INTEGER);
              CREATE TABLE IF NOT EXISTS sols_order_inputs (
                coin_id TEXT PRIMARY KEY, order_id TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS sols_order_receipt_claims (
                order_id TEXT PRIMARY KEY, claim_hash TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS sols_batch_catalog (
                id INTEGER PRIMARY KEY CHECK(id=1), document TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS sols_order_settlement_history (
                order_id TEXT NOT NULL, operation_id TEXT NOT NULL,
                PRIMARY KEY(order_id,operation_id));
              CREATE TABLE IF NOT EXISTS sols_order_completions (
                order_id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, confirmed_height INTEGER NOT NULL);
              CREATE TABLE IF NOT EXISTS sols_order_timelocks (
                order_id TEXT PRIMARY KEY, document TEXT NOT NULL);
            ''')

    @contextmanager
    def db(self, write=False):
        db = connect_generation_sqlite(self.path, generation_id=self.generation_id, isolation_level=None, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL')
            if write: db.execute('BEGIN IMMEDIATE')
            yield db
            if write: db.execute('COMMIT')
        except BaseException:
            if db.in_transaction: db.execute('ROLLBACK')
            raise
        finally: db.close()

    def place(self, offer, *, payment_asset, destination, now,receipt_key=None):
        from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver
        if type(now) is not int or now <= 0: raise ValueError('ORDER_TIME_INVALID')
        order = inspect_buyer_offer(offer, generation=self.generation, sols_asset=self.sols_asset,
            sols_driver=chia_cat_driver(self.sols_asset), payment_asset=payment_asset,
            destination_inner_hash=destination, approved_payment_assets=self.approved_assets)
        offer = order.offer(); verify_order_signature(offer,additional_data=self.signature_data)
        inputs = external_inputs(offer)
        if not inputs: raise ValueError('ORDER_EXTERNAL_INPUTS_MISSING')
        # Reuse Chia's typed offer timelocks. Height and time are distinct;
        # relative-timelocked offers are unsupported by the standard wallet.
        times=offer.absolute_valid_times_ban_relatives()
        expiry=int(times.max_time) if times.max_time is not None else None
        if expiry is not None and expiry <= now: raise ValueError('ORDER_EXPIRED')
        identity = '0x' + order.order_id.hex()
        ids = sorted('0x' + c.name().hex() for c in inputs)
        with self.db(write=True) as db:
            existing = db.execute('SELECT original_offer FROM sols_orders WHERE order_id=?', (identity,)).fetchone()
            if existing:
                if bytes(existing[0]) != order.offer_bytes: raise ValueError('ORDER_RECEIPT_CHANGED')
            else:
                if db.execute('SELECT COUNT(*) FROM sols_orders').fetchone()[0] >= MAX_ORDERS:
                    raise ValueError('ORDER_RECEIPT_CAPACITY_FULL')
                retained = int(db.execute('SELECT COALESCE(SUM(LENGTH(original_offer)+16384),0) FROM sols_orders').fetchone()[0])
                admit_retained_bytes(db, retained, len(order.offer_bytes) + 16384, MAX_RETAINED_BYTES)
                if any(db.execute('SELECT 1 FROM sols_order_inputs WHERE coin_id=?', (i,)).fetchone() for i in ids):
                    raise ValueError('ORDER_INPUT_ALREADY_LISTED')
                db.execute('INSERT INTO sols_orders VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (identity, order.offer_bytes, '0x' + payment_asset.hex() if payment_asset else None,
                     '0x' + destination.hex(), str(order.payment_amount), str(order.sols_amount), canonical(ids),
                     expiry, now, 'WAITING_FOR_MATCH', None, None, None))
                db.executemany('INSERT INTO sols_order_inputs VALUES (?,?)', [(i, identity) for i in ids])
                db.execute('INSERT INTO sols_order_timelocks VALUES (?,?)',(identity,canonical(times.to_json_dict())))
            if receipt_key is not None:
                claim=sha256(bytes.fromhex(receipt_key.removeprefix('0x'))).hexdigest()
                prior=db.execute('SELECT claim_hash FROM sols_order_receipt_claims WHERE order_id=?',(identity,)).fetchone()
                if prior and prior[0]!=claim:raise ValueError('ORDER_RECEIPT_ALREADY_CLAIMED')
                db.execute('INSERT OR IGNORE INTO sols_order_receipt_claims VALUES (?,?)',(identity,claim))
        return self.status(identity)

    def existing_receipt(self,offer,receipt_key):
        import hmac
        raw=bytes(offer);identity='0x'+sha256(bytes(self.generation)+raw).hexdigest()
        with self.db() as db:
            row=db.execute('SELECT original_offer FROM sols_orders WHERE order_id=?',(identity,)).fetchone()
            claim=db.execute('SELECT claim_hash FROM sols_order_receipt_claims WHERE order_id=?',(identity,)).fetchone()
        if row is None:return None
        if bytes(row[0])!=raw or claim is None or not hmac.compare_digest(claim[0],sha256(bytes.fromhex(receipt_key.removeprefix('0x'))).hexdigest()):
            raise ValueError('ORDER_RECEIPT_ACCESS_REQUIRED')
        return self.status(identity)

    def authorize_receipt(self,identity,receipt_key):
        import hmac
        with self.db() as db:
            claim=db.execute('SELECT claim_hash FROM sols_order_receipt_claims WHERE order_id=?',(identity,)).fetchone()
        if claim is None or not hmac.compare_digest(claim[0],sha256(bytes.fromhex(receipt_key.removeprefix('0x'))).hexdigest()):
            raise ValueError('ORDER_RECEIPT_ACCESS_REQUIRED')

    def status(self, identity):
        with self.db() as db:
            row = db.execute('SELECT * FROM sols_orders WHERE order_id=?', (identity,)).fetchone()
            completion=db.execute('SELECT transaction_id,confirmed_height FROM sols_order_completions WHERE order_id=?',(identity,)).fetchone()
        if row is None: raise ValueError('ORDER_NOT_FOUND')
        return {'generationId': self.generation_id, 'orderId': identity, 'stage': row['stage'],
            'paymentAsset': row['asset'], 'paymentAmount': row['payment'], 'solsAmount': row['sols'],
            'destinationInnerHash': row['destination'], 'expiresAt': row['expires_at'],
            'operationId': row['operation_id'], 'errorCode': row['error_code'],
            'transactionId':completion['transaction_id'] if completion else None,
            'confirmedHeight':completion['confirmed_height'] if completion else None,
            'lastCheckedAt': row['last_checked_at'], 'pollAfterSeconds': 5 if row['operation_id'] and row['stage']!='FILLED' else 30,
            'nextAction': ('Your Sols were delivered in the confirmed settlement. Keep this receipt.' if row['stage']=='FILLED' else
                'Cancel the original offer in your wallet. Removing it here does not cancel it on chain.'
                if row['stage'] == 'REMOVED_FROM_MATCHING' else
                'Waiting for a whole SmartDeed and matching signed orders.' if row['stage'] == 'WAITING_FOR_MATCH' else
                'Checking the saved settlement; do not create a replacement offer.' if row['operation_id'] else
                'Review the original offer inputs and your wallet history.')}

    def original(self, identity):
        from chia.wallet.trading.offer import Offer
        with self.db() as db:
            row = db.execute('SELECT original_offer FROM sols_orders WHERE order_id=?', (identity,)).fetchone()
        if row is None: raise ValueError('ORDER_NOT_FOUND')
        return Offer.from_bytes(row[0])

    def waiting(self,limit=32):
        if type(limit) is not int or not 1<=limit<=512:raise ValueError('ORDER_LIST_LIMIT_INVALID')
        with self.db() as db:
            rows=db.execute("SELECT order_id FROM sols_orders WHERE stage='WAITING_FOR_MATCH' AND operation_id IS NULL ORDER BY received_at,order_id LIMIT ?",(limit,)).fetchall()
        return tuple(self.status(row[0]) for row in rows)

    def linked_operation(self,identities,journal):
        """Recover saved execution before any pricing, building or signing."""
        self.repair_saved_links(journal)
        statuses=tuple(self.status(identity) for identity in identities)
        links={row['operationId'] for row in statuses}
        if links=={None}:return None
        if len(links)!=1 or None in links:raise ValueError('ORDER_ALREADY_BOUND_TO_ANOTHER_SETTLEMENT')
        saved=journal.status(next(iter(links)))
        if saved['kind']!='PRIMARY_SOLS_BATCH' or saved['review']['orderIds']!=list(identities):
            raise ValueError('ORDER_SETTLEMENT_REVIEW_CHANGED')
        return saved

    def repair_saved_links(self,journal):
        """Idempotent redo of the journal-first cross-database commit.

        Called by explicit preparation/reconciliation and the observer, never
        by cached GETs. The immutable buyer review recovers missing links
        without pricing, constructing a bundle, or requesting a signature.
        """
        operations=journal.batch_operations()
        with self.db(write=True) as db:
            for operation in operations:
                review=operation['review'];identity=operation['operationId']
                for buyer in review['buyers']:
                    row=db.execute('SELECT * FROM sols_orders WHERE order_id=?',(buyer['orderId'],)).fetchone()
                    if row is None:continue  # Older backup: retain operation, require original receipt recovery.
                    if (row['destination']!=buyer['destinationInnerHash'] or row['payment']!=buyer['paymentAmount']
                            or row['sols']!=buyer['minimumSolsAmount']
                            or '0x'+sha256(bytes(self.generation)+bytes(row['original_offer'])).hexdigest()!=buyer['orderId']):
                        raise ValueError('SAVED_ORDER_REVIEW_CHANGED')
                    db.execute('INSERT OR IGNORE INTO sols_order_settlement_history VALUES (?,?)',(buyer['orderId'],identity))
                    if operation['stage']=='EXPIRED_RECONCILED':
                        if journal.expiry_proof(identity) is None:raise ValueError('SAVED_EXPIRY_EVIDENCE_MISSING')
                        # Retain the attempt forever; the exact original offer
                        # becomes matchable only after authoritative expiry.
                        db.execute("UPDATE sols_orders SET operation_id=NULL,stage='WAITING_FOR_MATCH',error_code=NULL WHERE order_id=? AND operation_id=? AND stage!='FILLED'",(buyer['orderId'],identity))
                        continue
                    # A later expired-safe match may already own the order.
                    if row['operation_id'] not in (None,identity):
                        raise ValueError('ORDER_ALREADY_BOUND_TO_ANOTHER_SETTLEMENT')
                    db.execute("UPDATE sols_orders SET operation_id=?,stage='READY_TO_SETTLE',error_code=NULL WHERE order_id=? AND stage!='FILLED'",(identity,buyer['orderId']))

    def remove_from_matching(self, identity,*,receipt_key=None):
        with self.db(write=True) as db:
            if receipt_key is not None:
                import hmac
                claim=sha256(bytes.fromhex(receipt_key.removeprefix('0x'))).hexdigest()
                prior=db.execute('SELECT claim_hash FROM sols_order_receipt_claims WHERE order_id=?',(identity,)).fetchone()
                if prior is None or not hmac.compare_digest(prior[0],claim):raise ValueError('ORDER_RECEIPT_ACCESS_REQUIRED')
            row = db.execute('SELECT stage,operation_id FROM sols_orders WHERE order_id=?', (identity,)).fetchone()
            if row is None: raise ValueError('ORDER_NOT_FOUND')
            if row['operation_id']: raise ValueError('SETTLEMENT_ALREADY_SAVED_CHECK_WALLET')
            db.execute("UPDATE sols_orders SET stage='REMOVED_FROM_MATCHING' WHERE order_id=?", (identity,))
        return self.status(identity)

    def catalog(self):
        with self.db() as db:row=db.execute('SELECT document FROM sols_batch_catalog WHERE id=1').fetchone()
        return json.loads(row[0]) if row else None

    def save_catalog(self,document):
        if document.get('generationId')!=self.generation_id:raise ValueError('BATCH_CATALOG_GENERATION_CHANGED')
        raw=canonical(document)
        if len(raw.encode())>131072:raise ValueError('BATCH_CATALOG_TOO_LARGE')
        with self.db(write=True) as db:db.execute('INSERT INTO sols_batch_catalog VALUES (1,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document',(raw,))

    async def check_inputs(self, identity, *, provider, journal, now):
        saved = self.status(identity)
        # An authoritative confirmed exact bundle wins over a competing wallet
        # cancellation. A generic spent flag is never proof of a successful fill.
        operation=journal.status(saved['operationId']) if saved['operationId'] else None
        if operation and operation['stage'] == 'CONFIRMED':
            stage, error = 'FILLED', None
        else:
            stage, error = saved['stage'], saved['errorCode']
            if stage=='INPUT_UNAVAILABLE':
                stage,error=('READY_TO_SETTLE',None) if saved['operationId'] else ('WAITING_FOR_MATCH',None)
            for coin in external_inputs(self.original(identity)):
                response = await provider.get_coin_record_by_name_primary('0x' + coin.name().hex())
                record = response.get('coin_record',response) if isinstance(response, dict) else None
                if record is None: stage, error = 'INPUT_UNAVAILABLE', 'ORDER_INPUT_UNKNOWN'; break
                from .generation_coin_evidence import read_confirmed_coin
                evidence=read_confirmed_coin(record,coin.name())
                if evidence.coin!=coin:raise ValueError('ORDER_INPUT_EVIDENCE_CHANGED')
                if evidence.spent_height:
                    stage, error = ('SETTLEMENT_RECONCILING', None) if saved['operationId'] else ('INPUT_SPENT', 'ORDER_INPUT_SPENT')
                    break
            if stage == 'WAITING_FOR_MATCH' and saved['expiresAt'] is not None and saved['expiresAt'] <= now:
                stage, error = 'EXPIRED', 'ORDER_EXPIRED'
        with self.db(write=True) as db:
            # FILLED is monotonic, and a concurrently saved operation must not
            # be erased by a stale read or network response.
            db.execute('UPDATE sols_orders SET stage=?,error_code=?,last_checked_at=? WHERE order_id=? '
                "AND stage!='FILLED' AND operation_id IS ?", (stage, error, now, identity, saved['operationId']))
            if stage=='FILLED' and operation:
                if not operation.get('transactionId') or not operation.get('confirmedHeight'):
                    raise ValueError('ORDER_CONFIRMATION_EVIDENCE_MISSING')
                db.execute('INSERT OR IGNORE INTO sols_order_completions VALUES (?,?,?)',
                    (identity,operation['transactionId'],operation['confirmedHeight']))
        return self.status(identity)

    def reconcile_timelocks(self, *, height, chain_time, now):
        """Observer-only use of a fresh, synced primary chain clock."""
        if type(height) is not int or height<=0 or type(chain_time) is not int or chain_time<=0:
            raise ValueError('ORDER_CHAIN_CLOCK_INVALID')
        with self.db(write=True) as db:
            for row in db.execute("SELECT o.order_id,t.document FROM sols_orders o JOIN sols_order_timelocks t USING(order_id) WHERE o.operation_id IS NULL AND o.stage IN ('WAITING_FOR_MATCH','INPUT_UNAVAILABLE')").fetchall():
                times=json.loads(row['document'])
                if ((times['max_time'] is not None and chain_time>=int(times['max_time']))
                        or (times['max_height'] is not None and height>=int(times['max_height']))):
                    db.execute("UPDATE sols_orders SET stage='EXPIRED',error_code='ORDER_EXPIRED',last_checked_at=? WHERE order_id=?",(now,row['order_id']))

    def retain_settlement(self, settlement, *, journal, pool_tip, statutes_tip, registry_tip, fee_cap, now):
        if not isinstance(settlement, PrimaryBatchSettlement) or settlement.generation != self.generation:
            raise ValueError('SETTLEMENT_GENERATION_CHANGED')
        identities = ['0x' + order.order_id.hex() for order in settlement.batch.orders]
        source_args=Program.from_bytes(bytes(settlement.source_spend.solution)).at('rrf').at('rf')
        expires_at=source_args.at('r'*12+'f').as_int()
        price_round=source_args.at('r'*9+'f').as_atom()
        request_key='sols-batch:'+sha256(bytes(settlement.batch.commitment)+b''.join(bytes(s.coin.name()) for s in settlement.primary_spends)
            +bytes(price_round)+expires_at.to_bytes(8,'big')).hexdigest()
        native=NativeOperation(self.generation,'PRIMARY_SOLS_BATCH',tuple(settlement.bundle.coin_spends),
            settlement.successors,settlement.backing_coins,settlement.bundle.aggregated_signature)
        document={'generationId':self.generation_id,'kind':native.kind,'requestKey':request_key,
            'feeCapMojos':fee_cap,'batchCommitment':'0x'+settlement.batch.commitment.hex(),
            'primaryCoinId':'0x'+settlement.source_spend.coin.name().hex(),
            'primaryCoinIds':['0x'+s.coin.name().hex() for s in settlement.primary_spends],
            'orderIds':identities,'backingCoinId':'0x'+settlement.backing_coin.name().hex(),
            'backingCoinIds':['0x'+c.name().hex() for c in settlement.backing_coins],
            'paymentAmount':str(settlement.batch.payment_amount),'expiresAt':expires_at,'priceRoundHash':'0x'+price_round.hex(),
            'buyers':[{'orderId':'0x'+o.order_id.hex(),'destinationInnerHash':'0x'+o.destination_inner_hash.hex(),
                'paymentAmount':str(o.payment_amount),'minimumSolsAmount':str(o.sols_amount)} for o in settlement.batch.orders],
            'issuanceBackingMojos':str(sum(r.deed_to_sols_quote.fresh_sols_mojos_minted for r in settlement.receipts)),
            'feeAllocations':[str(sum(r.allocations()[i] for r in settlement.routings)) for i in range(3)]}
        digest='0x'+sha256(canonical(document).encode()).hexdigest()
        # Hold the order-book write claim through the local journal commit.
        # A concurrent matcher cannot prepare another operation for these
        # orders. A crash between databases is repaired by the exact review.
        with self.db(write=True) as db:
            operation=journal.reviewed_request(request_key,digest)
            for identity,order in zip(identities,settlement.batch.orders,strict=True):
                row=db.execute('SELECT original_offer,stage,operation_id FROM sols_orders WHERE order_id=?',(identity,)).fetchone()
                if (row is None or bytes(row['original_offer'])!=order.offer_bytes
                        or row['operation_id'] not in (None,operation['operationId'] if operation else None)
                        or (not operation and row['stage']!='WAITING_FOR_MATCH')):
                    raise ValueError('ORDER_CHANGED_BEFORE_SETTLEMENT')
            if operation is None:
                identity=journal.prepare(native,request_key,fee_cap,now,request_digest=digest,request_document=document)
                operation=journal.status(identity)
            elif operation['intentHash']!='0x'+native.commitment.hex():
                raise ValueError('SAVED_SETTLEMENT_BYTES_CHANGED')
            for identity in identities:
                db.execute('INSERT OR IGNORE INTO sols_order_settlement_history VALUES (?,?)',(identity,operation['operationId']))
                db.execute("UPDATE sols_orders SET operation_id=?,stage='READY_TO_SETTLE' WHERE order_id=? AND stage!='FILLED'",
                    (operation['operationId'],identity))
        return operation

    async def submit(self, identity, *, journal, submitter, clock):
        saved = self.status(identity)
        if not saved['operationId']: raise ValueError('SETTLEMENT_NOT_PREPARED')
        # Reuses the exact funded dispatch document and native admission in the
        # existing journal. It never adjusts the buyer amount or reviewed fee.
        return await submit_saved_operation(journal, saved['operationId'], submitter, clock=clock)


def parse_signed_order(encoded):
    """Reuse legacy bounded compression before any submitted puzzle executes."""
    import zlib
    from chia.util.bech32m import bech32_decode,convertbits
    from chia.wallet.util.puzzle_compression import LATEST_VERSION,zdict_for_version
    from chia.wallet.wallet_spend_bundle import WalletSpendBundle
    from chia.wallet.trading.offer import Offer
    from solslot_puzzles.generation_batch_orders import MAX_ORDER_BYTES
    if not isinstance(encoded,str) or not 16<=len(encoded)<=2_000_000:raise ValueError('SOLS_OFFER_SIZE_INVALID')
    prefix,data=bech32_decode(encoded,max_length=2_000_000)
    if prefix!='offer' or data is None:raise ValueError('SOLS_OFFER_ENCODING_INVALID')
    converted=convertbits(data,5,8,False)
    if converted is None:raise ValueError('SOLS_OFFER_PADDING_INVALID')
    wire=bytes(converted)
    if len(wire)<4:raise ValueError('SOLS_OFFER_ENCODING_INVALID')
    version=int.from_bytes(wire[:2],'big');count=int.from_bytes(wire[:4],'big')
    if version==0 and 1<count<=65:raw=wire
    else:
        if version>LATEST_VERSION:raise ValueError('SOLS_OFFER_COMPRESSION_UNSUPPORTED')
        try:
            decoder=zlib.decompressobj(zdict=zdict_for_version(version))
            raw=decoder.decompress(wire[2:],MAX_ORDER_BYTES+1)
        except zlib.error as exc:raise ValueError('SOLS_OFFER_COMPRESSION_INVALID') from exc
        if len(raw)>MAX_ORDER_BYTES or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('SOLS_OFFER_COMPRESSION_LIMIT')
    if not 4<=len(raw)<=MAX_ORDER_BYTES or not 1<int.from_bytes(raw[:4],'big')<=65:
        raise ValueError('SOLS_OFFER_SPEND_LIMIT')
    bundle=WalletSpendBundle.from_bytes(raw)
    if bytes(bundle)!=raw:raise ValueError('SOLS_OFFER_SERIALIZATION_CHANGED')
    dummy=[spend for spend in bundle.coin_spends if spend.coin.parent_coin_info==bytes32.zeros]
    if len(dummy)!=1 or dummy[0].coin.amount!=0:raise ValueError('SOLS_OFFER_REQUEST_CARRIER_INVALID')
    return Offer.from_bytes(raw)
