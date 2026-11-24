"""Immutable vault-owned card orders and durable Stripe idempotency."""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing,contextmanager
from dataclasses import asdict,dataclass,replace
from .generation_storage import connect_generation_sqlite
from solslot_puzzles.payment_artifacts_v3 import purchase_batch_from_json,purchase_batch_to_json

def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),allow_nan=False)
def h(value):return "0x"+value.hex()


@dataclass(frozen=True)
class VaultCardRecord:
    purchase_id:str
    batch_hash:str
    generation_id:str
    collection_id:str
    vault_launcher_id:str
    destination_puzzle_hash:str
    deed_launcher_ids:tuple[str,...]
    reserved_coin_ids:tuple[str,...]
    network:str
    mode:str
    account_id:str
    amount_minor:int
    currency:str
    expires_at:int
    batch:dict
    release_id:str
    original_coin_ids:tuple[str,...]
    vault_coin_id:str
    credential_root:str
    owner_key:str
    owner_auth_type:int
    policy_version:int
    bridge_policy_hash:str
    generation_anchor_hash:str
    technology_fee_puzzle_hash:str
    primary_proceeds_puzzle_hash:str
    maximum_fee_per_stage_mojos:int=400_000_000
    maximum_total_fee_mojos:int=2_000_000_000
    session_id:str|None=None
    payment_intent_id:str|None=None
    session_expires_at:int|None=None

    @property
    def genesis_artifact_hash(self):
        # Compatibility for older private diagnostic readers only. Never serialized.
        return self.generation_anchor_hash

    def check(self):
        batch=purchase_batch_from_json(self.batch)
        if (purchase_batch_to_json(batch)!=self.batch or self.purchase_id!=h(batch.purchase_id) or self.batch_hash!=h(batch.batch_hash)
            or self.network!=batch.network or (self.network,self.mode) not in {("mainnet","live"),("testnet11","test")}
            or not re.fullmatch("acct_[A-Za-z0-9]+",self.account_id) or self.currency!="usd"
            or self.vault_launcher_id!=h(batch.vault_launcher_id) or self.destination_puzzle_hash!=h(batch.vault_p2_puzzle_hash)
            or self.amount_minor!=batch.total_rail_amount or type(self.amount_minor) is not int or not 0<self.amount_minor<=99999999
            or self.expires_at!=batch.quote_expires_at or self.credential_root!=h(batch.zkpassport_root)
            or self.deed_launcher_ids!=tuple(h(a.deed_launcher_id) for a in batch.artifacts)
            or type(self.maximum_fee_per_stage_mojos) is not int or type(self.maximum_total_fee_mojos) is not int
            or not 0 < self.maximum_fee_per_stage_mojos*5 <= self.maximum_total_fee_mojos
            or self.owner_auth_type not in (1,3) or self.policy_version < 2
            or not re.fullmatch(r"0x[0-9a-f]+",self.owner_key)
            or not re.fullmatch(r"(?:0x|sha256:)[0-9a-f]{64}",self.generation_anchor_hash)
            or not re.fullmatch(r"0x[0-9a-f]{64}",self.bridge_policy_hash) or batch.quantity!=2 or len(self.original_coin_ids)!=batch.quantity or len(set(self.original_coin_ids))!=batch.quantity
            or len(self.reserved_coin_ids)!=batch.quantity or len(set(self.reserved_coin_ids))!=batch.quantity
            or any(not re.fullmatch("0x[0-9a-f]{64}",x) or int(x,16)==0 for x in (self.generation_id,self.release_id,self.generation_anchor_hash,self.technology_fee_puzzle_hash,self.primary_proceeds_puzzle_hash,self.vault_coin_id,*self.reserved_coin_ids,*self.original_coin_ids))
            or any(h(a.protocol_treasury_puzzle_hash)!=self.technology_fee_puzzle_hash or a.rail.name!="STRIPE" or a.purchase_kind.name!="DIRECT" or a.delivery_kind.name!="SMARTDEED" or h(a.collection_id)!=self.collection_id for a in batch.artifacts)):
            raise ValueError("Card order differs from its original purchase batch")
        return self


class VaultCardStore:
    def __init__(self,path):
        self.path=str(path)
        with self.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS vault_card_orders (
                purchase_id TEXT PRIMARY KEY,release_id TEXT NOT NULL UNIQUE,document TEXT NOT NULL,
                session_id TEXT UNIQUE,payment_intent_id TEXT UNIQUE,first_dispatch INTEGER,session_expires_at INTEGER,request_json TEXT)''')

            db.execute("CREATE TABLE IF NOT EXISTS vault_card_fences (purchase_id TEXT PRIMARY KEY, closed_at INTEGER NOT NULL)")

    @contextmanager
    def db(self):
        with closing(connect_generation_sqlite(self.path,timeout=10)) as db,db:
            db.row_factory=sqlite3.Row
            yield db

    @staticmethod
    def _doc(row):
        doc=json.loads(row["document"])
        for field in ("deed_launcher_ids","reserved_coin_ids","original_coin_ids"):doc[field]=tuple(doc[field])
        return VaultCardRecord(**doc,session_id=row["session_id"],payment_intent_id=row["payment_intent_id"],
                              session_expires_at=row["session_expires_at"]).check()

    def _one(self,field,value):
        with self.db() as db:
            row=db.execute("SELECT * FROM vault_card_orders WHERE "+field+"=?",(value,)).fetchone()
        return self._doc(row) if row else None

    def get(self,purchase_id):return self._one("purchase_id",purchase_id)
    def by_session(self,session_id):return self._one("session_id",session_id)
    def by_release(self,release_id):return self._one("release_id",release_id)
    def by_payment_intent(self,payment_intent_id):return self._one("payment_intent_id",payment_intent_id)

    def save(self,order):
        order.check()
        doc=asdict(order)
        for field in ("session_id","payment_intent_id","session_expires_at"):doc.pop(field)
        raw=canonical(doc)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT document FROM vault_card_orders WHERE purchase_id=? OR release_id=?",(order.purchase_id,order.release_id)).fetchone()
            if row is not None:
                if raw!=row[0]:raise ValueError("A different original order is already retained")
            else:db.execute("INSERT INTO vault_card_orders(purchase_id,release_id,document) VALUES(?,?,?)",(order.purchase_id,order.release_id,raw))
        return self.get(order.purchase_id)

    def begin_dispatch(self,order,params,*,now):
        # Commit the exact body before any external call. Stripe retains request keys
        # for at least 24 hours; an uncertain older request is for reconciliation only.
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT * FROM vault_card_orders WHERE purchase_id=?",(order.purchase_id,)).fetchone()
            if row is None or self._doc(row).batch_hash!=order.batch_hash:raise ValueError("Original purchase missing")
            if db.execute("SELECT 1 FROM vault_card_fences WHERE purchase_id=?",(order.purchase_id,)).fetchone():
                raise ValueError("Card order closed before dispatch")
            if row["session_id"]:return None
            if row["first_dispatch"] is not None:
                if not row["first_dispatch"]<=now<min(row["first_dispatch"]+23*3600,row["session_expires_at"]):
                    raise ValueError("Original Checkout Session requires reconciliation")
                return json.loads(row["request_json"])
            expiry=int(params["expires_at"])
            if not now+1800<=expiry<=min(now+86400,order.expires_at-120):raise ValueError("Checkout window insufficient")
            db.execute("UPDATE vault_card_orders SET first_dispatch=?,session_expires_at=?,request_json=? WHERE purchase_id=?",
                       (now,expiry,canonical(params),order.purchase_id))
            return json.loads(canonical(params))

    def bind_session(self,purchase_id,session_id,payment_intent_id=None):
        if not re.fullmatch(r"cs_(?:test_|live_)?[a-zA-Z0-9]+",session_id or ""):raise ValueError("Invalid Checkout Session")
        if payment_intent_id is not None and not re.fullmatch(r"pi_[A-Za-z0-9]+",payment_intent_id):raise ValueError("Invalid PaymentIntent")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT * FROM vault_card_orders WHERE purchase_id=?",(purchase_id,)).fetchone()
            if row is None or not session_id.startswith("cs_"+self._doc(row).mode+"_") or row["first_dispatch"] is None or row["session_id"] not in (None,session_id) or (
                payment_intent_id and row["payment_intent_id"] not in (None,payment_intent_id)):
                raise ValueError("Original Checkout Session binding differs")
            db.execute("UPDATE vault_card_orders SET session_id=?,payment_intent_id=coalesce(payment_intent_id,?) WHERE purchase_id=?",
                       (session_id,payment_intent_id,purchase_id))
        return self.get(purchase_id)

    def bind_payment_intent(self,purchase_id,session_id,payment_intent_id):
        if not payment_intent_id:raise ValueError("Original PaymentIntent required")
        return self.bind_session(purchase_id,session_id,payment_intent_id)

    def expiring(self,now):
        with self.db() as db:
            rows=db.execute("SELECT * FROM vault_card_orders WHERE session_expires_at<=? OR CAST(json_extract(document,'$.expires_at') AS INTEGER)<=?",(now,now)).fetchall()
        return tuple(self._doc(row) for row in rows)

    def dispatch(self,purchase_id):
        with self.db() as db:
            row=db.execute("SELECT first_dispatch,session_expires_at,request_json FROM vault_card_orders WHERE purchase_id=?",(purchase_id,)).fetchone()
        if row is None or row["first_dispatch"] is None:
            return None
        return dict(first_dispatch=row[0],session_expires_at=row[1],params=json.loads(row[2]))

    def fence_undispatched_order(self,purchase_id,*,now):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT * FROM vault_card_orders WHERE purchase_id=?",(purchase_id,)).fetchone()
            if row is None or row["first_dispatch"] is not None or row["session_id"] or self._doc(row).expires_at>now:
                return False
            db.execute("INSERT OR IGNORE INTO vault_card_fences VALUES(?,?)",(purchase_id,now))
            return True
