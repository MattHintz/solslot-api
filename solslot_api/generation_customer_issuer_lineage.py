"""Stage a forward-only issuer-journal transition without enabling signing.

A staged record is not closure proof and cannot activate a new policy. It
preserves and fingerprints all old forwarding rows in the same transaction.
Runtime activation requires separately verified all-role fencing, primary chain
reconciliation and durable fee/worker lineage; none is implied by this module.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_purchase_fee_lineage import FeeLineageBalance

_HASH=re.compile(r'^0x[0-9a-f]{64}$')
_COLUMNS=('artifact_hash','deed_id','gross_coin_id','purchase_bundle_hash','spend_hash','message','signature','created_at')


@dataclass(frozen=True)
class StagedIssuerLineage:
    prior_commitment:str
    next_commitment:str
    prior_rows_hash:str
    prior_rows:int
    fee_limit_mojos:int
    fee_committed_mojos:int
    state:str='STAGED'


def issuer_rows_snapshot(db):
    """Fingerprint exact immutable issuer rows, including reserved null signatures."""
    rows=db.execute('SELECT '+','.join(_COLUMNS)+' FROM issuer_forwarding ORDER BY artifact_hash').fetchall()
    canonical=json.dumps([list(row) for row in rows],separators=(',',':'),ensure_ascii=True).encode()
    return '0x'+sha256(canonical).hexdigest(),len(rows)


def stage_collection_issuer_lineage(db,*,prior_policy,next_policy,expected_rows_hash,fee_balance):
    """Atomically stage exactly one successor against the existing issuer DB.

    This refuses incomplete old issuer signatures, stale snapshots, divergent
    successors and changed fee evidence. It never updates issuer_policy or
    issuer_forwarding and does not make the new policy usable by a signer.
    """
    return _bind_collection_issuer_lineage(db, prior_policy=prior_policy, next_policy=next_policy,
        expected_rows_hash=expected_rows_hash, fee_balance=fee_balance)


def _bind_collection_issuer_lineage(db, *, prior_policy, next_policy, expected_rows_hash, fee_balance,
                                    closure_hash=None):
    if (not isinstance(prior_policy,TestnetIssuerPolicy)
            or not isinstance(next_policy,TestnetCollectionIssuerPolicy)
            or not isinstance(expected_rows_hash,str) or not _HASH.fullmatch(expected_rows_hash)
            or not isinstance(fee_balance,FeeLineageBalance)
            or type(fee_balance.limit_mojos)is not int or type(fee_balance.committed_mojos)is not int
            or not 0<=fee_balance.committed_mojos<=fee_balance.limit_mojos<2**63
            or fee_balance.remaining_mojos!=fee_balance.limit_mojos-fee_balance.committed_mojos):
        raise ValueError('CURRENT_ISSUER_LINEAGE_ARGUMENT_INVALID')
    prior_commitment=prior_policy.commitment
    next_commitment=next_policy.commitment
    unchanged=('generation','collection','edition','metadata_root','proceeds_puzzle','fee_puzzle',
        'issuer_public_key','maximum_gross_mojos','test_usd_minor_per_txch')
    if (any(getattr(prior_policy,k)!=getattr(next_policy,k) for k in unchanged)
            or not prior_policy.deed_launchers.issubset(next_policy.deed_launchers)):
        raise ValueError('CURRENT_ISSUER_LINEAGE_SCOPE_CHANGED')
    if next_commitment==prior_commitment:raise ValueError('CURRENT_ISSUER_LINEAGE_SUCCESSOR_INVALID')
    db.execute('BEGIN IMMEDIATE')
    try:
        bound=db.execute('SELECT commitment FROM issuer_policy WHERE id=1').fetchone()
        activation = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='issuer_collection_activation'").fetchone()
        if activation is not None:
            active = db.execute('SELECT prior_commitment,next_commitment,prior_rows_hash,fee_limit_mojos,'
                'fee_committed_mojos,closure_hash,state FROM issuer_collection_activation WHERE singleton=1').fetchone()
            expected = (prior_commitment, next_commitment, expected_rows_hash, fee_balance.limit_mojos,
                        fee_balance.committed_mojos, closure_hash, 'ACTIVE')
            if closure_hash is None or active is None or tuple(active) != expected or bound is None or bound[0] != next_commitment:
                raise ValueError('CURRENT_ISSUER_LINEAGE_ALREADY_ACTIVATED')
            db.execute('COMMIT')
            return None
        if bound is None or bound[0]!=prior_commitment:
            raise ValueError('CURRENT_ISSUER_LINEAGE_PRIOR_CHANGED')
        digest,count=issuer_rows_snapshot(db)
        if digest!=expected_rows_hash:raise ValueError('CURRENT_ISSUER_LINEAGE_SNAPSHOT_CHANGED')
        if db.execute('SELECT 1 FROM issuer_forwarding WHERE signature IS NULL LIMIT 1').fetchone():
            raise ValueError('CURRENT_ISSUER_LINEAGE_UNCERTAIN_SIGNATURE')
        db.execute('''CREATE TABLE IF NOT EXISTS issuer_collection_lineage (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), prior_commitment TEXT NOT NULL,
            next_commitment TEXT NOT NULL, prior_rows_hash TEXT NOT NULL, prior_rows INTEGER NOT NULL,
            fee_limit_mojos INTEGER NOT NULL, fee_committed_mojos INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state='STAGED'))''')
        values=(prior_commitment,next_commitment,digest,count,fee_balance.limit_mojos,fee_balance.committed_mojos,'STAGED')
        old=db.execute('SELECT prior_commitment,next_commitment,prior_rows_hash,prior_rows,fee_limit_mojos,fee_committed_mojos,state FROM issuer_collection_lineage WHERE singleton=1').fetchone()
        if old is not None and tuple(old)!=values:raise ValueError('CURRENT_ISSUER_LINEAGE_ALREADY_STAGED')
        if old is None:db.execute('INSERT INTO issuer_collection_lineage VALUES (1,?,?,?,?,?,?,?)',values)
        if closure_hash is not None:
            db.execute('''CREATE TABLE issuer_collection_activation (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), prior_commitment TEXT NOT NULL,
                next_commitment TEXT NOT NULL, prior_rows_hash TEXT NOT NULL, prior_rows INTEGER NOT NULL,
                fee_limit_mojos INTEGER NOT NULL, fee_committed_mojos INTEGER NOT NULL,
                closure_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state='ACTIVE'))''')
            db.execute('INSERT INTO issuer_collection_activation VALUES (1,?,?,?,?,?,?,?,?)',
                (*values[:-1], closure_hash, 'ACTIVE'))
            changed = db.execute('UPDATE issuer_policy SET commitment=? WHERE id=1 AND commitment=?',
                (next_commitment, prior_commitment)).rowcount
            if changed != 1:
                raise ValueError('CURRENT_ISSUER_LINEAGE_PRIOR_CHANGED')
        db.execute('COMMIT')
    except BaseException:
        db.execute('ROLLBACK');raise
    return StagedIssuerLineage(*values) if closure_hash is None else None


def activate_collection_issuer_lineage(db, *, prior_policy, next_policy, expected_rows_hash, fee_balance, closure_hash):
    """Offline only: record a reviewed closure and switch the existing binding.

    The caller must independently stop and fence every old role and validate the
    primary-chain and fee evidence represented by closure_hash. A hash alone
    does not establish those facts or prevent an old process or backup restart.
    """
    if not isinstance(closure_hash,str) or not _HASH.fullmatch(closure_hash) or closure_hash=='0x'+'00'*32:
        raise ValueError('CURRENT_ISSUER_CLOSURE_HASH_REQUIRED')
    _bind_collection_issuer_lineage(db, prior_policy=prior_policy, next_policy=next_policy,
        expected_rows_hash=expected_rows_hash, fee_balance=fee_balance, closure_hash=closure_hash)
