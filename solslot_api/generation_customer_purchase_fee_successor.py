"""Install a finite additional Testnet checkout fee grant against reconciled journals."""
from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import sqlite3
from typing import Literal

from pydantic import Field, StrictInt, TypeAdapter

from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
from .generation_customer_purchase_cutover_evidence import (
    _confirmed_execution, _open_read_only, _primary_peak, _stored_bundle, checkout_journal_snapshots,
)
from .generation_customer_purchase_fees import CurrentPurchaseFeeAuthority
from .generation_execution import Hash
from .generation_index import _bounded_file
from .generation_preparation import PreparationModel


class PurchaseFeeSuccessor(PreparationModel):
    schema_version: Literal['solslot.testnet-checkout-fee-successor.v1'] = Field(alias='schema')
    renewal_hash: Hash = Field(alias='renewalHash')
    cutover_hash: Hash = Field(alias='cutoverHash')
    purchase_snapshot: Hash = Field(alias='purchaseJournalSnapshot')
    funding_snapshot: Hash = Field(alias='fundingJournalSnapshot')
    prior_commitment: StrictInt = Field(alias='priorFeeExposureMojos', ge=0)
    authority: CurrentPurchaseFeeAuthority


class RenewedPurchaseFeeSuccessor(PurchaseFeeSuccessor):
    schema_version: Literal['solslot.testnet-checkout-fee-successor.v2'] = Field(alias='schema')
    previous_successor_hash: Hash = Field(alias='previousSuccessorHash')


def read_fee_successor(settings, policy, cutover, original, renewal):
    raw = _bounded_file(settings.generation_customer_purchase_fee_successor_path, 16384)
    if '0x' + sha256(raw).hexdigest() != settings.generation_customer_purchase_fee_successor_hash:
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_CHANGED')
    grant = TypeAdapter(PurchaseFeeSuccessor | RenewedPurchaseFeeSuccessor).validate_json(raw)
    authority = grant.authority.require_policy(policy)
    if (not isinstance(policy, TestnetCollectionIssuerPolicy) or cutover is None
            or grant.renewal_hash != settings.generation_customer_purchase_fee_renewal_hash
            or grant.cutover_hash != settings.generation_customer_purchase_cutover_hash
            or authority.funding_puzzle_hash != renewal.funding_puzzle_hash
            or authority.maximum_fee_parent_mojos != renewal.maximum_fee_parent_mojos
            or not renewal.issued_at <= authority.issued_at < authority.expires_at <= renewal.expires_at
            or len(authority.fee_coin_ids) != 2 or set(authority.fee_coin_ids).intersection(original.fee_coin_ids)
            or authority.maximum_stage_fee_mojos != renewal.maximum_stage_fee_mojos
            or authority.maximum_stage_fee_mojos > 900_000_000
            or authority.maximum_total_fee_mojos != 2 * authority.maximum_stage_fee_mojos
            or grant.prior_commitment < cutover.inherited_fee_mojos
            or grant.prior_commitment + authority.maximum_total_fee_mojos > cutover.fee_limit_mojos):
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_SCOPE_CHANGED')
    return grant


def _binding(db, generation):
    if [tuple(row) for row in db.execute('SELECT generation_id,network FROM deployment_generation_binding')] != [
            (generation, 'testnet11')]:
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_JOURNAL_CHANGED')


def _stored_grant(db):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='current_purchase_fee_successor'").fetchone():
        return None
    row = db.execute('SELECT grant_hash FROM current_purchase_fee_successor WHERE id=1').fetchone()
    if row is None:
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_BINDING_MISSING')
    return row[0]


def require_fee_successor(db, generation, digest):
    _binding(db, generation)
    if _stored_grant(db) != digest:
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_BINDING_MISSING')


def claim_fee_successor_intent(store, digest, intent, phase, issued_at):
    """Keep both sponsored stages with the first eligible customer's saved order."""
    with store._connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT grant_hash,intent_id FROM current_purchase_fee_successor WHERE id=1').fetchone()
        requested = db.execute('SELECT requested_at FROM current_customer_reservation_requests WHERE intent_id=?',
                               (intent,)).fetchone()
        if (row is None or row['grant_hash'] != digest or requested is None or requested[0] < issued_at
                or row['intent_id'] not in (None, intent) or row['intent_id'] is None and phase != 'RESERVATION'):
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_ORDER_CHANGED')
        if row['intent_id'] is None:
            db.execute('UPDATE current_purchase_fee_successor SET intent_id=? WHERE id=1', (intent,))
        db.commit()


async def reconcile_fee_successor(purchase, funding, *, submitter, node, cutover, original, renewal, next_ids, previous=None):
    """Collect a stable snapshot and verify confirmed fees against the primary Chia node."""
    for db in (purchase, funding):
        _binding(db, cutover.generation_id)
    snapshots = checkout_journal_snapshots(purchase, funding)
    expected = (cutover.collection_policy, renewal.maximum_stage_fee_mojos)
    row = purchase.execute('SELECT policy_hash,fee_cap FROM current_purchase_collection_execution WHERE id=1').fetchone()
    if row is None or tuple(row) != expected:
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_POLICY_CHANGED')
    pending = purchase.execute("""SELECT 1 FROM current_customer_reservation_requests r
        LEFT JOIN current_purchase_worker_jobs j USING(intent_id)
        WHERE j.state IS NULL OR j.state NOT IN ('RELEASED','COMPLETE','CLOSED')
           OR (j.state='CLOSED' AND j.expiry_document IS NULL) OR j.lease_token IS NOT NULL LIMIT 1""").fetchone()
    if pending:
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_UNSETTLED_CHECKOUT')

    _, peak, _ = await _primary_peak(submitter, node)
    exposure = cutover.inherited_fee_mojos
    previous_ids = () if previous is None else previous.authority.fee_coin_ids
    if set(next_ids).intersection(previous_ids):
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_INPUT_USED')
    previous_stages = []
    for coin in (*original.fee_coin_ids, *previous_ids, *next_ids):
        rows = funding.execute('SELECT original_id FROM funded_protocol_input_history WHERE network=? AND coin_id=?',
                               ('testnet11', coin)).fetchall()
        if coin in next_ids:
            if rows:
                raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_INPUT_USED')
            continue
        if coin in previous_ids and len(rows) != 1:
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_PREVIOUS_INPUT_UNSETTLED')
        if not rows and coin in renewal.fee_coin_ids:
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_PRIOR_GRANT_OPEN')
        for (identity,) in rows:
            row = purchase.execute('SELECT * FROM current_purchase_executions WHERE original_id=?', (identity,)).fetchone()
            if row is None:
                raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_ORPHAN_FUNDING')
            exact = await _confirmed_execution(funding, submitter, row, _stored_bundle(row), peak)
            exposure += exact.maximum_mojos
            if coin in previous_ids:
                previous_stages.append((row['intent_id'], row['phase']))
    if previous_ids:
        intents = {intent for intent, _ in previous_stages}
        phases = {phase for _, phase in previous_stages}
        if len(intents) != 1 or phases not in ({'RESERVATION', 'RELEASE'}, {'RESERVATION', 'DELIVERY'}):
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_PREVIOUS_ORDER_CHANGED')
        _require_previous_order(purchase, previous, intents.pop())
    return {'purchaseJournalSnapshot': snapshots[0], 'fundingJournalSnapshot': snapshots[1],
            'priorFeeExposureMojos': exposure}


@dataclass(frozen=True)
class PreviousFeeGrant:
    digest: str
    authority: CurrentPurchaseFeeAuthority

    @classmethod
    def from_bytes(cls, raw, *, digest, renewal_hash, cutover_hash):
        if not raw or '0x' + sha256(raw).hexdigest() != digest:
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_PREVIOUS_BYTES_CHANGED')
        grant = PurchaseFeeSuccessor.model_validate_json(raw)
        if grant.renewal_hash != renewal_hash or grant.cutover_hash != cutover_hash:
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_PREVIOUS_SCOPE_CHANGED')
        return cls(digest, grant.authority)


def _require_previous_order(db, previous, intent):
    digest = previous.digest
    row = db.execute('SELECT intent_id FROM current_purchase_fee_successor WHERE id=1 AND grant_hash=?',
                     (digest,)).fetchone()
    if row is None and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='current_purchase_fee_grant_history'").fetchone():
        row = db.execute('SELECT intent_id FROM current_purchase_fee_grant_history WHERE grant_hash=?',
                         (digest,)).fetchone()
    if row is None or row[0] != intent:
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_PREVIOUS_ORDER_CHANGED')


def replace_consumed_grant(db, bound, digest):
    row = db.execute('SELECT intent_id FROM current_purchase_fee_successor WHERE id=1 AND grant_hash=?', (bound,)).fetchone()
    if row is None:
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_ALREADY_BOUND')
    db.execute('CREATE TABLE IF NOT EXISTS current_purchase_fee_grant_history (grant_hash TEXT PRIMARY KEY, intent_id TEXT, next_hash TEXT NOT NULL UNIQUE)')
    db.execute('INSERT INTO current_purchase_fee_grant_history VALUES (?,?,?)', (bound, row[0], digest))
    db.execute('UPDATE current_purchase_fee_successor SET grant_hash=?,intent_id=NULL WHERE id=1 AND grant_hash=?', (digest,bound))


async def install_fee_successor(settings, purchase_path, funding_path, *, policy, cutover, original, renewal,
                                submitter, node, now, previous_bytes=None):
    """Offline installation. A partial installation can retry with the same pinned grant."""
    grant = read_fee_successor(settings, policy, cutover, original, renewal)
    grant.authority.require_live(policy, now)
    digest = settings.generation_customer_purchase_fee_successor_hash
    previous = None
    if isinstance(grant, RenewedPurchaseFeeSuccessor):
        previous = PreviousFeeGrant.from_bytes(previous_bytes, digest=grant.previous_successor_hash,
            renewal_hash=grant.renewal_hash, cutover_hash=grant.cutover_hash)
        if previous.digest == digest or previous.authority.issued_at >= grant.authority.issued_at:
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_PREVIOUS_SCOPE_CHANGED')
    allowed = (None, digest) if previous is None else (previous.digest, digest)
    paths = [Path(purchase_path), Path(funding_path)]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_JOURNALS_REQUIRED')
    with closing(_open_read_only(paths[0])) as purchase, closing(_open_read_only(paths[1])) as funding:
        for db in (purchase, funding):
            _binding(db, cutover.generation_id)
        bindings = [_stored_grant(db) for db in (purchase, funding)]
        if any(binding not in allowed for binding in bindings):
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_ALREADY_BOUND')
        if bindings == [digest, digest]:
            return grant
        evidence = await reconcile_fee_successor(purchase, funding, submitter=submitter, node=node, cutover=cutover,
                                                 original=original, renewal=renewal, next_ids=grant.authority.fee_coin_ids, previous=previous)
        if evidence != {key: grant.model_dump(by_alias=True)[key] for key in evidence}:
            raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_EVIDENCE_CHANGED')

    with closing(sqlite3.connect(paths[0].absolute().as_uri() + '?mode=rw', uri=True)) as purchase, \
            closing(sqlite3.connect(paths[1].absolute().as_uri() + '?mode=rw', uri=True)) as funding:
        with purchase, funding:
            for db in (purchase, funding):
                db.execute('BEGIN IMMEDIATE')
                _binding(db, cutover.generation_id)
            row = purchase.execute('SELECT cutover_hash FROM current_purchase_collection_execution WHERE id=1').fetchone()
            if row != (grant.cutover_hash,) or checkout_journal_snapshots(purchase, funding) != (
                    grant.purchase_snapshot, grant.funding_snapshot):
                raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_EVIDENCE_CHANGED')
            for db in (purchase, funding):
                bound = _stored_grant(db)
                if bound not in allowed:
                    raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_ALREADY_BOUND')
                if previous is not None and bound == previous.digest:
                    replace_consumed_grant(db, bound, digest)
                elif bound is None:
                    db.execute('CREATE TABLE current_purchase_fee_successor (id INTEGER PRIMARY KEY CHECK(id=1), grant_hash TEXT NOT NULL, intent_id TEXT)')
                    db.execute('INSERT INTO current_purchase_fee_successor (id,grant_hash) VALUES (1,?)', (digest,))
                elif bound != digest:
                    raise ValueError('CURRENT_PURCHASE_FEE_SUCCESSOR_ALREADY_BOUND')
    return grant
