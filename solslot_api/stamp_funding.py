"""Durable fee sponsorship for an already authorized identity stamp.

The original claim and two signed protocol spends are immutable. A sponsored
submission is a separate, append-only record. Only the legacy z puzzle's
unsigned clock may advance, after primary-chain reconciliation; the protocol
inputs, outputs, owner authorization and validator signature never change.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import os
import time
from dataclasses import replace

from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.program import Program, INFINITE_COST
from chia.types.coin_spend import make_spend
from chia.types.condition_opcodes import ConditionOpcode
from chia_rs import Coin, SpendBundle
from chia.wallet.wallet_spend_bundle import WalletSpendBundle

from .chia_provider import ChiaProviderError, _mempool_item_matches_bundle
from .chia_snapshot import PrimaryReadSnapshot
from .protocol_submission import ProtocolBundleSubmitter, ProtocolSubmissionError

logger = logging.getLogger(__name__)
TIME_OPS = {ConditionOpcode.ASSERT_SECONDS_ABSOLUTE, ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE}

def hx(value):
    return '0x' + bytes(value).hex()


def stamp_timestamp(bundle, vault_coin_id):
    from solslot_puzzles.vault_driver import VAULT_INNER_MOD
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
    matches = [s for s in bundle.coin_spends if hx(s.coin.name()) == vault_coin_id]
    if len(bundle.coin_spends) != 2 or len(matches) != 1:
        raise ValueError('Identity stamp requires its two original inputs')
    spend = matches[0]
    puzzle = Program.from_bytes(bytes(spend.puzzle_reveal))
    outer, args = puzzle.uncurry(); args = list(args.as_iter())
    if (puzzle.get_tree_hash() != spend.coin.puzzle_hash or spend.coin.amount != 1
            or outer != SINGLETON_MOD or len(args) != 2
            or args[1].uncurry()[0] != VAULT_INNER_MOD):
        raise ValueError('Identity stamp does not use the pinned vault puzzle')
    top = list(Program.from_bytes(bytes(spend.solution)).as_iter())
    inner = list(top[2].as_iter()) if len(top) == 3 else []
    action = list(inner[4].as_iter()) if len(inner) == 5 else []
    if len(action) != 6 or inner[3].as_atom() != b'z':
        raise ValueError('Only the identity-stamp clock can be continued')
    timestamp = action[4].as_int()
    if not 0 < timestamp < 2**63 or Program.to(timestamp) != action[4]:
        raise ValueError('Identity stamp clock is invalid')
    return timestamp


def continue_stamp(bundle, vault_coin_id, timestamp):
    original_time = stamp_timestamp(bundle, vault_coin_id)
    if type(timestamp) is not int or not original_time <= timestamp < 2**63:
        raise ValueError('Identity stamp clock cannot move backwards')
    spends = []
    for spend in bundle.coin_spends:
        if hx(spend.coin.name()) != vault_coin_id:
            spends.append(spend); continue
        top = list(Program.from_bytes(bytes(spend.solution)).as_iter())
        inner = list(top[2].as_iter()); action = list(inner[4].as_iter())
        action[4] = Program.to(timestamp); inner[4] = Program.to(action); top[2] = Program.to(inner)
        changed = make_spend(spend.coin, Program.from_bytes(bytes(spend.puzzle_reveal)), Program.to(top))
        def effects(s):
            conditions = conditions_dict_for_solution(s.puzzle_reveal, s.solution, INFINITE_COST)
            return {op: [(c.opcode, c.vars) for c in values] for op, values in conditions.items() if op not in TIME_OPS}
        if effects(spend) != effects(changed):
            raise ValueError('Identity continuation changed authorized conditions')
        spends.append(changed)
    result = SpendBundle(spends, bundle.aggregated_signature)
    if result.additions() != bundle.additions() or result.removals() != bundle.removals():
        raise ValueError('Identity continuation changed authorized effects')
    from .sols_swaps import _verify_aggregate_signature
    _verify_aggregate_signature(WalletSpendBundle.from_json_dict(result.to_json_dict()), 'testnet11')
    return result


class StampFundingStore:
    """Separate journal; rolling back code never requires rewriting credentials."""
    def __init__(self, path):
        self.path = str(path)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        if self.path != ":memory:":os.chmod(self.path,0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS stamp_submissions (
                id INTEGER PRIMARY KEY, vault TEXT NOT NULL, original_id TEXT NOT NULL,
                bundle_id TEXT NOT NULL UNIQUE, document TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'prepared', created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS stamp_submission_events (
                id INTEGER PRIMARY KEY, bundle_id TEXT NOT NULL, event TEXT NOT NULL,
                error_code TEXT, created_at INTEGER NOT NULL);
        ''')

    def latest(self, vault):
        with self.lock:
            row = self.db.execute('SELECT * FROM stamp_submissions WHERE vault=? ORDER BY id DESC LIMIT 1', (vault,)).fetchone()
        return dict(row) if row else None

    def reserve(self, vault, original_id, document, expected_previous):
        encoded = json.dumps(document, sort_keys=True, separators=(',', ':'))
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                previous = self.latest(vault)
                if (previous['bundle_id'] if previous else None) != expected_previous:
                    raise ValueError('Another stamp submission already reserved funding')
                self.db.execute('INSERT INTO stamp_submissions(vault,original_id,bundle_id,document,created_at) VALUES(?,?,?,?,?)',
                    (vault, original_id, document['spendBundleId'], encoded, int(time.time())))
                if previous:
                    self.db.execute("UPDATE stamp_submissions SET status='superseded' WHERE bundle_id=?", (previous['bundle_id'],))
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK'); raise

    def event(self, bundle_id, event, error_code=None):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO stamp_submission_events(bundle_id,event,error_code,created_at) VALUES(?,?,?,?)',
                    (bundle_id, event, error_code, int(time.time())))
                self.db.execute('UPDATE stamp_submissions SET status=? WHERE bundle_id=?', (event,bundle_id))
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK'); raise
        logger.info('stamp_submission bundle_id=%s event=%s error_code=%s', bundle_id, event, error_code)

    def reserved_coin_ids(self):
        with self.lock:
            rows = self.db.execute("SELECT document FROM stamp_submissions WHERE status NOT IN ('confirmed','superseded')").fetchall()
        return {json.loads(r[0])['feeCoinId'] for r in rows}


def bind_store(submitter, store):
    submitter.add_fee_coin_reservation_source(store.reserved_coin_ids)
    submitter.faucet.add_coin_reservation_source(store.reserved_coin_ids)


async def _observe(submitter, document, expected_coin):
    """Observe before every resend; a timeout never authorizes replacement."""
    node = submitter.provider
    if node.primary is None or not await node._primary_available():
        raise ChiaProviderError('Primary Chia node is unavailable; saved stamp retained')
    output = await node.get_coin_record_by_name_primary(hx(expected_coin.name()))
    if output and output.get('confirmed_block_index', 0) > 0:
        if Coin.from_json_dict(output['coin']) != expected_coin:
            raise ValueError('Stamp receipt does not match the authorized successor')
        return 'confirmed'
    bundle = SpendBundle.from_json_dict(document['spendBundle'])
    for coin in bundle.removals():
        record = await node.get_coin_record_by_name_primary(hx(coin.name()))
        if not record or Coin.from_json_dict(record['coin']) != coin or record.get('spent_block_index'):
            raise ValueError('Stamp input changed; preserve the saved transaction for reconciliation')
        items = await node.primary.get_mempool_items_by_coin_name(hx(coin.name()))
        if any(_mempool_item_matches_bundle(item, document['spendBundleId']) for item in items):
            return 'mempool'
        if items:
            raise ValueError('Stamp input has a different pending transaction; no replacement authorized')
    return 'clear'


async def submit_funded_stamp(*, submitter, store, ledger, key, original, expected_coin):
    if (not isinstance(submitter, ProtocolBundleSubmitter) or not submitter.policy.enabled
            or submitter.faucet.network != 'testnet11'):
        raise ProtocolSubmissionError('Identity stamp fee sponsorship is unavailable')
    bind_store(submitter, store)
    saved = ledger.get_stamp_attempt(key)
    if not saved or saved['bundle_hex'] != bytes(original).hex():
        raise ValueError('Identity sponsorship requires the original durable signed stamp')
    claim = json.loads(saved['claim_json']); vault_id = claim['current_vault_coin_id']
    original_time = stamp_timestamp(original, vault_id)
    if original_time != claim['current_timestamp']:
        raise ValueError('Saved stamp clock does not match the frozen claim')
    async with submitter.funding_guard:
        prior = store.latest(key)
        if prior:
            document = json.loads(prior['document'])
            observed = await _observe(submitter, document, expected_coin)
            if observed != 'clear':
                store.event(document['spendBundleId'], observed)
                return document
        else:
            original_document = {'spendBundleId':hx(original.name()), 'spendBundle':original.to_json_dict()}
            observed = await _observe(submitter, original_document, expected_coin)
            if observed != 'clear':
                return original_document
        if not prior or int(time.time()) >= document['expiresAt'] - 20:
            # The node's transaction-block clock must also prove expiry. No
            # pending original or funded attempt can be silently superseded.
            async with PrimaryReadSnapshot(submitter.provider, 'testnet11') as snapshot:
                if prior and snapshot.transaction_time < document['expiresAt']:
                    raise ProtocolSubmissionError('Saved stamp is still live on the chain clock; retry shortly')
                if not prior and saved['dispatch_count'] and snapshot.transaction_time < original_time + 120:
                    raise ProtocolSubmissionError('Original stamp is still live; its receipt must be reconciled first')
            now = max(int(time.time()), original_time)
            protocol = continue_stamp(original, vault_id, now)
            fee = sum(int(c.amount) for c in protocol.removals()) - sum(int(c.amount) for c in protocol.additions())
            if fee != 1:
                raise ValueError('Identity stamp must have its exact one-mojo bridge receipt burn')
            # Share the same funding lock/reservations, with a target shorter
            # than the pinned vault's 120-second transaction deadline.
            fast = ProtocolBundleSubmitter(provider=submitter.provider, faucet=submitter.faucet,
                policy=replace(submitter.policy, target_seconds=60))
            fast._fee_coin_reservation_sources = submitter._fee_coin_reservation_sources
            prepared = await fast._prepare_locked(protocol.to_json_dict(), expected_protocol_fee_mojos=1,
                bind_protocol=True, sponsor_deadline=now+120)
            if time.time() >= now+90:
                raise ProtocolSubmissionError('Fee preparation exceeded the stamp window; nothing was submitted')
            document = {**prepared.to_json(), 'timestamp':now, 'expiresAt':now+120,
                'originalBundleId':hx(original.name()), 'claimHash':saved['claim_hash']}
            store.reserve(key,hx(original.name()),document,prior['bundle_id'] if prior else None)
        # The append-only journal is committed before a single network write.
        observed = await _observe(submitter, document, expected_coin)
        if observed != 'clear':
            store.event(document['spendBundleId'], observed); return document
        if time.time() >= document['expiresAt']-15:
            raise ProtocolSubmissionError('Saved stamp window ended; check status before resuming')
        store.event(document['spendBundleId'], 'dispatching')
        try:
            await submitter.provider.push_tx_confirmed_in_primary_mempool(document['spendBundle'],
                required_coin_id=document['feeCoinId'], required_spend_bundle_id=document['spendBundleId'],
                timeout_seconds=min(8,submitter.policy.mempool_timeout_seconds),
                poll_seconds=submitter.policy.mempool_poll_seconds)
            store.event(document['spendBundleId'], 'mempool'); return document
        except ChiaProviderError as exc:
            from .submission_errors import error_code
            code = error_code(exc)
            store.event(document['spendBundleId'], 'uncertain' if code == 'TRANSPORT_OR_TIMEOUT' else 'rejected', code)
            if code != 'TRANSPORT_OR_TIMEOUT':
                raise ProtocolSubmissionError(f'Chia rejected the saved stamp ({code}); authorization and receipt are retained', submission_attempted=True) from exc
            raise ProtocolSubmissionError('Chia confirmation is delayed; the saved transaction will be checked before retrying', submission_attempted=True) from exc
