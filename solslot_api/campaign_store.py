"""Immutable campaign intents and executions, alongside current voucher journals."""
from __future__ import annotations

import json
import asyncio
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


class CampaignStore:
    def _create_campaign_schema(self):
        self.campaign_funding_guard = asyncio.Lock()
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS campaign_operations (
              terms_hash TEXT NOT NULL REFERENCES presale_series_v2(terms_hash),
              kind TEXT NOT NULL CHECK(kind IN ('creation','phase')),
              intent_json TEXT NOT NULL, context_json TEXT NOT NULL,
              preparation_json TEXT NOT NULL, execution_json TEXT,
              confirmed_height INTEGER, PRIMARY KEY(terms_hash,kind));
            CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_unfinished
              ON campaign_operations(terms_hash) WHERE confirmed_height IS NULL;
            CREATE TABLE IF NOT EXISTS campaign_funding_inputs (
              coin_id TEXT PRIMARY KEY, terms_hash TEXT NOT NULL,
              kind TEXT NOT NULL, confirmed INTEGER NOT NULL DEFAULT 0,
              FOREIGN KEY(terms_hash,kind) REFERENCES campaign_operations(terms_hash,kind));
            CREATE TABLE IF NOT EXISTS campaign_phase_history (
              attempt_hash TEXT PRIMARY KEY, terms_hash TEXT NOT NULL,
              operation_json TEXT NOT NULL, expiry_proof_json TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_campaign_history_terms ON campaign_phase_history(terms_hash);
        """)

    def campaign_operation(self, terms, kind):
        row = self._conn.execute('SELECT * FROM campaign_operations WHERE terms_hash=? AND kind=?',
                                 (terms.lower(), kind)).fetchone()
        if row is None:
            return None
        return dict(kind=row['kind'], intent=json.loads(row['intent_json']),
                    context=json.loads(row['context_json']), preparation=json.loads(row['preparation_json']),
                    execution=json.loads(row['execution_json']) if row['execution_json'] else None,
                    confirmedHeight=row['confirmed_height'])

    def pending_campaign_operation(self, terms):
        rows = self._conn.execute('SELECT kind FROM campaign_operations WHERE terms_hash=? AND confirmed_height IS NULL',
                                  (terms.lower(),)).fetchall()
        if len(rows) > 1:
            raise ValueError('Campaign has conflicting unfinished operations')
        return self.campaign_operation(terms, rows[0]['kind']) if rows else None

    def _insert_campaign_operation(self, cur, terms, operation):
        cur.execute('INSERT INTO campaign_operations(terms_hash,kind,intent_json,context_json,preparation_json) VALUES (?,?,?,?,?)',
                    (terms.lower(), operation['kind'], canonical(operation['intent']),
                     canonical(operation['context']), canonical(operation['preparation'])))
        if operation.get('execution') is not None:
            self._retain_campaign_execution(cur, terms, operation['kind'], operation['execution'])

    def retain_campaign_phase(self, terms, operation, expected_chain):
        """Reserve the singleton before quorum, atomically with worker exclusions."""
        if operation['kind'] != 'phase':
            raise ValueError('Expected a phase operation')
        with self.txn() as cur:
            old = self.campaign_operation(terms, 'phase')
            if old:
                if any(old[k] != operation[k] for k in ('intent', 'context', 'preparation')):
                    raise ValueError('Original campaign phase intent cannot be replaced')
                return old
            row = cur.execute('SELECT * FROM presale_series_v2 WHERE terms_hash=?', (terms.lower(),)).fetchone()
            if row is None or row['state'] != 'PRESALE' or row['phase_bundle_id'] is not None:
                raise ValueError('Campaign phase is unavailable or already submitted')
            if self._render_series(row)['chainState'] != expected_chain:
                raise ValueError('Campaign singleton state changed during phase preparation')
            if cur.execute('SELECT 1 FROM campaign_operations WHERE terms_hash=? AND confirmed_height IS NULL', (terms.lower(),)).fetchone():
                raise ValueError('Campaign creation is not yet confirmed')
            lease = cur.execute('SELECT lease_until FROM voucher_worker_series WHERE terms_hash=?', (terms.lower(),)).fetchone()
            pending = cur.execute('SELECT 1 FROM voucher_worker_executions WHERE terms_hash=? AND confirmed=0 LIMIT 1', (terms.lower(),)).fetchone()
            pinned = cur.execute("""SELECT 1 FROM voucher_records_v2 WHERE terms_hash=? AND
                (state IN ('PENDING_ISSUANCE','ISSUANCE_SUBMITTED') OR
                 (issuance_bundle_id IS NOT NULL AND issuance_confirmed_height IS NULL) OR
                 ((redemption_bundle_id IS NOT NULL OR refund_bundle_id IS NOT NULL OR terminal_exact_execution_json IS NOT NULL)
                  AND redemption_confirmed_height IS NULL AND refund_confirmed_height IS NULL)) LIMIT 1""", (terms.lower(),)).fetchone()
            if pending or pinned or (lease and lease['lease_until'] > time.time()):
                raise ValueError('Campaign singleton has unfinished voucher work')
            self._insert_campaign_operation(cur, terms, operation)
        return self.campaign_operation(terms, 'phase')

    def _retain_campaign_execution(self, cur, terms, kind, execution):
        from chia_rs import SpendBundle
        bundle = SpendBundle.from_json_dict(execution['spendBundle'])
        if execution['spendBundleId'] != '0x' + bundle.name().hex():
            raise ValueError('Campaign execution bundle identity changed')
        encoded = canonical(execution)
        row = cur.execute('SELECT execution_json FROM campaign_operations WHERE terms_hash=? AND kind=?',
                          (terms.lower(), kind)).fetchone()
        if row is None:
            raise ValueError('Campaign intent must be retained before its execution')
        if row['execution_json'] is not None and row['execution_json'] != encoded:
            raise ValueError('Original signed campaign execution cannot be replaced')
        voucher_inputs = self.pending_voucher_funding_coin_ids()
        # Include all removals, not just a designated fee coin. Historical inputs
        # stay pinned to their original operation after confirmation.
        for coin in bundle.removals():
            name = '0x' + coin.name().hex()
            if name in voucher_inputs:
                raise ValueError('Campaign input is retained for voucher funding')
            previous = cur.execute('SELECT terms_hash,kind FROM campaign_funding_inputs WHERE coin_id=?', (name,)).fetchone()
            if previous and (previous['terms_hash'], previous['kind']) != (terms.lower(), kind):
                raise ValueError('Campaign execution input already belongs to another operation')
            cur.execute('INSERT OR IGNORE INTO campaign_funding_inputs(coin_id,terms_hash,kind) VALUES (?,?,?)',
                        (name, terms.lower(), kind))
        cur.execute('UPDATE campaign_operations SET execution_json=? WHERE terms_hash=? AND kind=?',
                    (encoded, terms.lower(), kind))

    def retain_campaign_execution(self, terms, kind, execution, *, expected_operation=None):
        with self.txn() as cur:
            if expected_operation is not None and self.campaign_operation(terms, kind) != expected_operation:
                raise ValueError('Campaign attempt changed while its quorum was in flight')
            self._retain_campaign_execution(cur, terms, kind, execution)

    def confirm_campaign_operation(self, terms, kind, height):
        with self.txn() as cur:
            self._confirm_campaign_operation(cur, terms, kind, height)

    def _confirm_campaign_operation(self, cur, terms, kind, height):
        if isinstance(height, bool) or not isinstance(height, int) or height <= 0:
            raise ValueError('Campaign confirmation height is invalid')
        row = cur.execute('SELECT execution_json,confirmed_height FROM campaign_operations WHERE terms_hash=? AND kind=?',
                              (terms.lower(), kind)).fetchone()
        if row is None or row['execution_json'] is None:
            raise ValueError('Campaign confirmation has no retained execution')
        if row['confirmed_height'] not in (None, height):
            raise ValueError('Original campaign confirmation cannot be replaced')
        cur.execute('UPDATE campaign_operations SET confirmed_height=? WHERE terms_hash=? AND kind=?',
                        (height, terms.lower(), kind))
        cur.execute('UPDATE campaign_funding_inputs SET confirmed=1 WHERE terms_hash=? AND kind=?', (terms.lower(), kind))

    def pending_campaign_funding_coin_ids(self):
        return {row['coin_id'] for row in self._conn.execute('SELECT coin_id FROM campaign_funding_inputs WHERE confirmed=0')}

    def archive_expired_campaign_phase(self, terms, operation, proof):
        """Preserve the whole original attempt; release only a proven expired input."""
        import hashlib
        encoded = canonical(operation)
        if (operation['kind'] != 'phase' or operation['confirmedHeight'] is not None
                or proof['coinId'] != operation['preparation']['claim']['series_coin_id']
                or proof['timestamp'] < proof['consensusDeadline']):
            raise ValueError('Campaign expiry does not bind its original attempt')
        with self.txn() as cur:
            if self.campaign_operation(terms, 'phase') != operation:
                raise ValueError('Campaign attempt changed during expiry observation')
            row = cur.execute('SELECT state,current_coin_id,phase_confirmed_height FROM presale_series_v2 WHERE terms_hash=?', (terms,)).fetchone()
            if row['state'] != 'PRESALE' or row['current_coin_id'] != proof['coinId'] or row['phase_confirmed_height'] is not None:
                raise ValueError('Campaign series changed during expiry observation')
            cur.execute('INSERT INTO campaign_phase_history VALUES (?,?,?,?)',
                (hashlib.sha256(encoded.encode()).hexdigest(), terms, encoded, canonical(proof)))
            cur.execute("DELETE FROM campaign_funding_inputs WHERE terms_hash=? AND kind='phase'", (terms,))
            cur.execute("DELETE FROM campaign_operations WHERE terms_hash=? AND kind='phase'", (terms,))
            cur.execute('''UPDATE presale_series_v2 SET phase_target_state=NULL,phase_bundle_id=NULL,
                phase_input_coin_id=NULL,phase_output_coin_id=NULL,phase_output_inner_puzzle_hash=NULL,
                phase_launch_anchor=NULL,phase_governance_execution_ids_json=NULL,phase_submitted_at=NULL
                WHERE terms_hash=?''', (terms,))
