"""Bound new work by a server-confirmed person, not a caller-selected wallet.

Unsigned quote slots expire. Once private reservation signing can have begun,
only verified inventory expiry/release closes the slot; payment timeouts cannot
silently free it. Limits are part of the reviewed v2 hold capability.
"""
import hashlib
import re

from .inventory_extension_store import canonical, conflict

ADMISSION_POLICY=dict(purchaseAdmissionPolicy='one-pending-identity-v1',
    checkoutOwnerPolicy='authenticated-current-vault-owner-v1',
    maxSoftQuoteSeconds=900,maxPendingPurchasesPerIdentity=1,maxReservedDeedsPerIdentity=1,maxNewQuotesPerIdentityHour=6,maxNewQuotesPerMinute=60,maxPendingPurchases=128)


def migrate_purchase_admission(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS payment_purchase_admission (
            purchase_intent_id TEXT PRIMARY KEY, subject_hash TEXT NOT NULL,
            vault_launcher_id TEXT NOT NULL, binding_json TEXT NOT NULL,
            owner_auth_type INTEGER NOT NULL, owner_key TEXT NOT NULL,
            purchase_id TEXT UNIQUE, state TEXT NOT NULL DEFAULT 'QUOTING',
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS purchase_admission_subject ON payment_purchase_admission(subject_hash,created_at);
        CREATE INDEX IF NOT EXISTS purchase_admission_vault ON payment_purchase_admission(vault_launcher_id,state);
        CREATE INDEX IF NOT EXISTS purchase_admission_created ON payment_purchase_admission(created_at);
    ''')


def admission_subject(receipt):
    # Only pass the current server-confirmed enrollment receipt, never request
    # JSON. Root/vault rotation must not create a new per-person quota bucket.
    values={k:receipt.get(k) for k in ('scopedNullifier','nullifierType','serviceScopeHash','serviceSubscopeHash','network')}
    if (values['network']!='testnet11' or type(values['nullifierType']) is not int
            or values['nullifierType']<0 or any(not isinstance(values[k],str)
            or not re.fullmatch(r'0x[0-9a-f]{64}',values[k]) for k in ('scopedNullifier','serviceScopeHash','serviceSubscopeHash'))
            or values['scopedNullifier']=='0x'+'0'*64):
        raise conflict('new checkout requires the server-confirmed scoped identity quota')
    return hashlib.sha256(('solslot.purchase-admission.v1:'+canonical(values)).encode()).hexdigest()


class PurchaseAdmissionStoreMixin:
    def admit_purchase(self,*,purchase_intent_id,receipt,activation,now,owner_auth_type,owner_key):
        subject=admission_subject(receipt);vault=receipt['vaultLauncherId'];binding=canonical(activation)
        if any(activation.get(k)!=v or type(activation.get(k)) is not type(v) for k,v in ADMISSION_POLICY.items()):
            raise conflict('reviewed purchase admission limits are incomplete')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT * FROM payment_purchase_admission WHERE purchase_intent_id=?',(purchase_intent_id,)).fetchone()
            if old:
                if (old['subject_hash']!=subject or old['vault_launcher_id']!=vault or old['binding_json']!=binding
                        or old['owner_auth_type']!=owner_auth_type or old['owner_key']!=owner_key
                        or old['state']!='QUOTING' or old['expires_at']<=now):
                    raise conflict('purchase admission cannot be replaced or reopened')
                db.execute('COMMIT');return
            active="(state='SIGNING' OR (state='QUOTING' AND expires_at>?))"
            if db.execute(f'SELECT 1 FROM payment_purchase_admission WHERE {active} AND (subject_hash=? OR vault_launcher_id=?)',
                          (now,subject,vault)).fetchone():
                raise conflict('finish or recover the existing checkout before reserving another property')
            if (db.execute('SELECT count(*) FROM payment_purchase_admission WHERE subject_hash=? AND created_at>?',(subject,now-3600)).fetchone()[0]
                    >=activation['maxNewQuotesPerIdentityHour']
                or db.execute('SELECT count(*) FROM payment_purchase_admission WHERE created_at>?',(now-60,)).fetchone()[0]
                    >=activation['maxNewQuotesPerMinute']
                or db.execute(f'SELECT count(*) FROM payment_purchase_admission WHERE {active}',(now,)).fetchone()[0]
                    >=activation['maxPendingPurchases']):
                raise conflict('new checkout capacity is limited; existing purchase recovery remains available')
            db.execute('INSERT INTO payment_purchase_admission(purchase_intent_id,subject_hash,vault_launcher_id,binding_json,owner_auth_type,owner_key,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)',
                       (purchase_intent_id,subject,vault,binding,owner_auth_type,owner_key,now,now+activation['maxSoftQuoteSeconds']))
            db.execute('COMMIT')

    def begin_admitted_reservation(self,*,stored,receipt,activation,now,owner_auth_type,owner_key):
        subject=admission_subject(receipt)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM payment_purchase_admission WHERE purchase_intent_id=?',(stored.purchase_intent_id,)).fetchone()
            if (row is None or row['subject_hash']!=subject or row['vault_launcher_id']!=receipt['vaultLauncherId']
                    or row['owner_auth_type']!=owner_auth_type or row['owner_key']!=owner_key
                    or row['binding_json']!=canonical(activation) or row['state']=='CLOSED'
                    or (row['state']=='QUOTING' and row['expires_at']<=now)
                    or row['purchase_id'] not in (None,stored.purchase_id)):
                raise conflict('private reservation requires its retained identity admission')
            db.execute("UPDATE payment_purchase_admission SET state='SIGNING',purchase_id=? WHERE purchase_intent_id=?",
                       (stored.purchase_id,stored.purchase_intent_id))
            db.execute('COMMIT')


def require_admitted_checkout(db,purchase_id,activation):
    row=db.execute('SELECT * FROM payment_purchase_admission WHERE purchase_id=?',(purchase_id,)).fetchone()
    if row is None or row['state']!='SIGNING' or row['binding_json']!=canonical(activation):
        raise conflict('prepayment hold requires its durable identity admission before private signing')


def close_inventory_admission(db,purchase_id):
    db.execute("UPDATE payment_purchase_admission SET state='CLOSED' WHERE purchase_id=?",(purchase_id,))


def require_admission_owner(vault_launcher_id,owner_auth_type,owner_key):
    from chia_rs.sized_bytes import bytes32
    from .state import get_registry
    record=get_registry().get(bytes32.fromhex(vault_launcher_id[2:]))
    if (record is None or type(owner_auth_type) is not int or owner_auth_type not in (1,2,3)
            or not isinstance(owner_key,str) or record.auth_type!=owner_auth_type
            or owner_key!='0x'+bytes(record.owner_pubkey).hex()):
        raise conflict('checkout session does not control the current approved vault')


def recheck_admitted_owner(store,purchase_id):
    with store._connect() as db:
        row=db.execute('SELECT * FROM payment_purchase_admission WHERE purchase_id=?',(purchase_id,)).fetchone()
    if row is None:raise conflict('checkout admission is missing')
    require_admission_owner(row['vault_launcher_id'],row['owner_auth_type'],row['owner_key'])
