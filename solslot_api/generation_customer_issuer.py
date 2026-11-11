"""Finite Testnet compatibility authorization for wallet-bound old inventory.

The original proceeds destination is immutable. This guard authorizes only
the newly created proceeds coin of a reviewed purchase, routed atomically to
the existing principal/fee custody. It cannot sign wallet withdrawals, create
funding, select keys or broadcast. New mints should bind contract splitting at
issuance instead of granting this compatibility permission.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import threading

from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia_rs import AugSchemeMPL,G1Element,G2Element,SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.testnet_primary_forwarding import build_testnet_primary_forwarding
from solslot_puzzles.generation_revenue import PrimaryFeeSplitter
from .faucet import AGG_SIG_ME_DATA
from .generation_storage import connect_generation_sqlite


def h(value):return '0x'+bytes(value).hex()


@dataclass(frozen=True)
class TestnetIssuerPolicy:
    generation:bytes32
    collection:bytes32
    edition:bytes32
    metadata_root:bytes32
    proceeds_puzzle:bytes32
    fee_puzzle:bytes32
    issuer_public_key:bytes
    deed_launchers:frozenset[bytes32]
    buyer_vault:bytes32
    maximum_gross_mojos:int
    maximum_purchases:int
    issued_at:int
    expires_at:int
    # A finite, explicitly approved Testnet conversion; never a market feed.
    test_usd_minor_per_txch:int|None=None

    def public(self):
        value={'schema':'solslot.testnet-issuer-forwarding-policy.v1','network':'testnet11',
            'generationId':h(self.generation),'collectionHash':h(self.collection),'editionHash':h(self.edition),
            'metadataRoot':h(self.metadata_root),'proceedsPuzzleHash':h(self.proceeds_puzzle),
            'feePuzzleHash':h(self.fee_puzzle),'issuerPublicKey':h(self.issuer_public_key),
            'deedLauncherIds':sorted(h(value) for value in self.deed_launchers),
            'buyerVaultLauncherId':h(self.buyer_vault),'maximumGrossMojos':str(self.maximum_gross_mojos),
            'maximumPurchases':self.maximum_purchases,'issuedAt':self.issued_at,'expiresAt':self.expires_at,
            'technologyFeeBps':100,'companyShareOfFeeBps':7000,'sgtShareOfFeeBps':3000,
            'scope':'NEW_EPHEMERAL_PRIMARY_PROCEEDS_ONLY','masterKeyExportAuthorized':False}
        if self.test_usd_minor_per_txch is not None:
            value.update(schema='solslot.testnet-issuer-forwarding-policy.v2',
                pricing={'mode':'FIXED_TESTNET_CONVERSION','usdMinorPerTxch':str(self.test_usd_minor_per_txch)})
        return value

    def validate(self):
        fields=(self.generation,self.collection,self.edition,self.metadata_root,self.proceeds_puzzle,
            self.fee_puzzle,self.buyer_vault,*self.deed_launchers)
        if (any(not isinstance(v,bytes32) or v==bytes32.zeros for v in fields)
                or not isinstance(self.deed_launchers,frozenset) or not 1<=len(self.deed_launchers)<=25
                or type(self.maximum_purchases)is not int or not 1<=self.maximum_purchases<=len(self.deed_launchers)
                or type(self.maximum_gross_mojos)is not int or not 1<self.maximum_gross_mojos<2**64
                or type(self.issued_at)is not int or type(self.expires_at)is not int
                or not 0<self.issued_at<self.expires_at<=self.issued_at+172800
                or not isinstance(self.issuer_public_key,bytes) or len(self.issuer_public_key)!=48
                or (self.test_usd_minor_per_txch is not None and
                    (type(self.test_usd_minor_per_txch)is not int or not 1<=self.test_usd_minor_per_txch<=10**15))
                or G1Element.from_bytes(self.issuer_public_key)==G1Element()):
            raise ValueError('CURRENT_ISSUER_POLICY_INVALID')
        return self

    @property
    def commitment(self):
        self.validate()
        return '0x'+sha256(json.dumps(self.public(),sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def require_terms(self,terms,*,now):
        self.validate()
        if type(now)is not int or not self.issued_at<=now<self.expires_at:
            raise ValueError('CURRENT_ISSUER_POLICY_EXPIRED')
        from chia.types.blockchain_format.program import Program
        bindings=list(Program.from_bytes(terms.generation_batch_bindings).as_iter())
        if (terms.network!='testnet11' or terms.inventory_version!=4 or len(bindings)!=8
                or bindings[0].as_atom()!=bytes(self.generation)
                or terms.collection_id!=self.collection or terms.metadata_anchor_id!=self.edition
                or terms.metadata_root!=self.metadata_root or terms.deed_launcher_id not in self.deed_launchers
                or terms.protocol_puzhash!=self.proceeds_puzzle
                or terms.protocol_treasury_puzzle_hash!=self.fee_puzzle or terms.technology_fee_bps!=100):
            raise ValueError('CURRENT_ISSUER_POLICY_TERMS_CHANGED')


class TestnetIssuerJournal:
    """One finite policy, saved before signing; a retry returns the same result.

    A failed/uncertain signer call retains its slot. It can resume only the
    same spend. Expiry cannot reset the grant or admit a different payout.
    """
    def __init__(self,path,policy,*,cutover_hash=None):
        self.policy=policy.validate()
        self.cutover_hash=cutover_hash
        self._lock=threading.RLock()
        self.path=str(path)
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        self.db=connect_generation_sqlite(self.path,generation_id=h(policy.generation),
            generation_network='testnet11',isolation_level=None,check_same_thread=False)
        self._shared=False
        self._bind_policy()

    @classmethod
    def in_validator_journal(cls,ledger,policy,*,cutover_hash=None):
        """Add issuer checkpoints to the already recovered signer journal.

        No generation rebinding, credential copying or new backup database.
        The caller holds the validator lock for synchronous authorization.
        """
        from .validator_ledger import ValidatorLedger
        if not isinstance(ledger,ValidatorLedger) or ledger.path==':memory:':
            raise ValueError('CURRENT_ISSUER_DURABLE_VALIDATOR_JOURNAL_REQUIRED')
        value=cls.__new__(cls);value.policy=policy.validate();value.cutover_hash=cutover_hash;value.path=ledger.path
        value.db=ledger._conn;value._shared=True
        value._lock=ledger._lock
        with ledger._lock:value._bind_policy()
        return value

    def _bind_policy(self):
        policy=self.policy
        self.db.row_factory=sqlite3.Row
        self.db.execute('CREATE TABLE IF NOT EXISTS issuer_policy (id INTEGER PRIMARY KEY CHECK(id=1), commitment TEXT NOT NULL)')
        self.db.execute('''CREATE TABLE IF NOT EXISTS issuer_forwarding (
            artifact_hash TEXT PRIMARY KEY,deed_id TEXT NOT NULL UNIQUE,gross_coin_id TEXT NOT NULL UNIQUE,
            purchase_bundle_hash TEXT NOT NULL,spend_hash TEXT NOT NULL,message TEXT NOT NULL,
            signature TEXT,created_at INTEGER NOT NULL)''')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT commitment FROM issuer_policy WHERE id=1').fetchone()
            if row is not None and row['commitment']!=policy.commitment:
                raise ValueError('CURRENT_ISSUER_JOURNAL_POLICY_CHANGED')
            from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
            if isinstance(policy,TestnetCollectionIssuerPolicy):
                if row is None or not self.cutover_hash:
                    raise ValueError('CURRENT_ISSUER_ACTIVE_LINEAGE_REQUIRED')
                active=self.db.execute("SELECT next_commitment,closure_hash FROM issuer_collection_activation WHERE singleton=1").fetchone()
                if active is None or tuple(active)!=(policy.commitment,self.cutover_hash):
                    raise ValueError('CURRENT_ISSUER_ACTIVE_LINEAGE_REQUIRED')
            else:
                self.db.execute('INSERT OR IGNORE INTO issuer_policy(id,commitment) VALUES(1,?)',(policy.commitment,))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            if not self._shared:self.db.close()
            raise

    def _require_binding(self):
        row=self.db.execute('SELECT commitment FROM issuer_policy WHERE id=1').fetchone()
        if row is None or row[0]!=self.policy.commitment:
            raise ValueError('CURRENT_ISSUER_JOURNAL_POLICY_CHANGED')
        from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
        if isinstance(self.policy,TestnetCollectionIssuerPolicy):
            active=self.db.execute('SELECT next_commitment,closure_hash,state FROM issuer_collection_activation WHERE singleton=1').fetchone()
            if active is None or tuple(active)!=(self.policy.commitment,self.cutover_hash,'ACTIVE'):
                raise ValueError('CURRENT_ISSUER_ACTIVE_LINEAGE_REQUIRED')

    def authorize(self,*,bundle,artifact,terms,fees,now,sign_message):
        with self._lock:
            self._require_binding()
            return self._authorize(bundle=bundle,artifact=artifact,terms=terms,fees=fees,now=now,sign_message=sign_message)

    def authorize_batch(self,*,bundle,artifacts,terms,fees,now,sign_message):
        """Reserve all original deed-budget slots before any key callback.

        Reuses the original per-deed append-only rows, so a mixed single/batch
        sequence, partial signer failure or restart cannot reset capacity.
        """
        if not 2<=len(artifacts)<=25 or len(artifacts)!=len(terms):
            raise ValueError('CURRENT_ISSUER_BATCH_BOUNDS_INVALID')
        with self._lock:
            self._require_binding()
            reviews=[self._review(bundle=bundle,artifact=a,terms=t,fees=fees,now=now)
                for a,t in zip(artifacts,terms,strict=True)]
            if len({r[2]for r in reviews})!=len(reviews):raise ValueError('CURRENT_ISSUER_BATCH_REPEATED_ARTIFACT')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                missing=[]
                for companion,pair,identity,expected in reviews:
                    row=self.db.execute('SELECT * FROM issuer_forwarding WHERE artifact_hash=?',(identity,)).fetchone()
                    if row is None:missing.append((identity,expected))
                    elif any(row[k]!=v for k,v in expected.items()):raise ValueError('CURRENT_ISSUER_SAVED_PURCHASE_CHANGED')
                used=self.db.execute('SELECT COUNT(*) FROM issuer_forwarding').fetchone()[0]
                if hasattr(self.policy,'maximum_purchases') and used+len(missing)>self.policy.maximum_purchases:raise ValueError('CURRENT_ISSUER_PURCHASE_BUDGET_EXHAUSTED')
                for identity,expected in missing:
                    self.db.execute('''INSERT INTO issuer_forwarding
                        (artifact_hash,deed_id,gross_coin_id,purchase_bundle_hash,spend_hash,message,created_at)
                        VALUES(?,?,?,?,?,?,?)''',(identity,*expected.values(),now))
                self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
            for a,t in zip(artifacts,terms,strict=True):
                self._authorize(bundle=bundle,artifact=a,terms=t,fees=fees,now=now,sign_message=sign_message)
            signatures=[G2Element.from_bytes(bytes.fromhex(self.db.execute(
                'SELECT signature FROM issuer_forwarding WHERE artifact_hash=?',(identity,)).fetchone()[0][2:]))for _,_,identity,_ in reviews]
            return SpendBundle([*bundle.coin_spends,*[spend for companion,_,_,_ in reviews for spend in companion.operation.spends]],
                AugSchemeMPL.aggregate([bundle.aggregated_signature,*signatures]))

    def _review(self,*,bundle,artifact,terms,fees,now):
        """Sign only one native-derived AGG_SIG_ME message; never arbitrary RPC.

        Caller first independently proves the buyer's current identity, signed
        price, original offer and native delivery. The scoped callback receives
        only this exact ephemeral-coin message. No key material enters a record.
        """
        policy=self.policy
        policy.require_terms(terms,now=now)
        if ((isinstance(policy,TestnetIssuerPolicy) and artifact.vault_launcher_id!=policy.buyer_vault)
                or not 1<int(artifact.rail_amount)<=policy.maximum_gross_mojos
                or not now<artifact.quote_expires_at<=artifact.authorization_expires_at
                or (isinstance(policy,TestnetIssuerPolicy) and artifact.authorization_expires_at>policy.expires_at)
                or not isinstance(fees,PrimaryFeeSplitter) or fees.bindings.generation!=policy.generation
                or fees.inner().get_tree_hash()!=policy.fee_puzzle):
            raise ValueError('CURRENT_ISSUER_PURCHASE_SCOPE_CHANGED')
        companion=build_testnet_primary_forwarding(bundle=bundle,artifact=artifact,terms=terms,
            issuer_public_key=policy.issuer_public_key,fees=fees)
        spend=companion.issuer_signature_spend
        conditions=conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000)
        pairs=pkm_pairs_for_conditions_dict(conditions,spend.coin,AGG_SIG_ME_DATA['testnet11'])
        if len(pairs)!=1 or bytes(pairs[0][0])!=policy.issuer_public_key:
            raise ValueError('CURRENT_ISSUER_SIGNATURE_SCOPE_CHANGED')
        public,message=pairs[0]
        identity=h(artifact.artifact_hash)
        expected={'deed_id':h(terms.deed_launcher_id),'gross_coin_id':h(companion.gross_coin.name()),
            'purchase_bundle_hash':'0x'+sha256(bytes(bundle)).hexdigest(),
            'spend_hash':'0x'+sha256(bytes(spend)).hexdigest(),'message':h(message)}
        return companion,(public,message),identity,expected

    def _authorize(self,*,bundle,artifact,terms,fees,now,sign_message):
        policy=self.policy
        companion,(public,message),identity,expected=self._review(bundle=bundle,artifact=artifact,terms=terms,fees=fees,now=now)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT * FROM issuer_forwarding WHERE artifact_hash=?',(identity,)).fetchone()
            if row is not None:
                if any(row[key]!=value for key,value in expected.items()):
                    raise ValueError('CURRENT_ISSUER_SAVED_PURCHASE_CHANGED')
            else:
                if hasattr(policy,'maximum_purchases') and self.db.execute('SELECT COUNT(*) FROM issuer_forwarding').fetchone()[0]>=policy.maximum_purchases:
                    raise ValueError('CURRENT_ISSUER_PURCHASE_BUDGET_EXHAUSTED')
                self.db.execute('''INSERT INTO issuer_forwarding
                    (artifact_hash,deed_id,gross_coin_id,purchase_bundle_hash,spend_hash,message,created_at) VALUES(?,?,?,?,?,?,?)''',
                    (identity,*expected.values(),now))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
        signature=G2Element.from_bytes(bytes.fromhex(row['signature'][2:])) if row is not None and row['signature'] else None
        if signature is None:
            signature=G2Element.from_bytes(bytes(sign_message(bytes(message))))
            if not AugSchemeMPL.verify(public,bytes(message),signature):
                raise ValueError('CURRENT_ISSUER_SIGNATURE_INVALID')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('UPDATE issuer_forwarding SET signature=? WHERE artifact_hash=? AND signature IS NULL',
                    (h(signature),identity))
                saved=self.db.execute('SELECT signature FROM issuer_forwarding WHERE artifact_hash=?',(identity,)).fetchone()[0]
                if saved!=h(signature):raise ValueError('CURRENT_ISSUER_SAVED_SIGNATURE_CHANGED')
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK');raise
        if not AugSchemeMPL.verify(public,bytes(message),signature):
            raise ValueError('CURRENT_ISSUER_SAVED_SIGNATURE_INVALID')
        return SpendBundle([*bundle.coin_spends,*companion.operation.spends],
            AugSchemeMPL.aggregate([bundle.aggregated_signature,signature]))

    def close(self):
        if not self._shared:self.db.close()
