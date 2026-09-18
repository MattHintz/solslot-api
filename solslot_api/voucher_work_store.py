"""Bounded current-voucher scheduling; cursors and retries survive restart.

Candidate indexes intentionally exclude the series join. Each scan reads at most
64 candidates, including those whose series is not yet eligible. Fee reservation
evidence is a complete exclusion set and is never paginated with this work queue.
"""
from __future__ import annotations

import json
from typing import Any

LANES = {
    "campaign": "confirmed_height IS NULL",
    "retained": "confirmed=0",
    "issuance": "state IN ('PENDING_ISSUANCE','ISSUANCE_SUBMITTED')",
    "stripe_terminal": "payment_rail='STRIPE_USD' AND terminal_exact_execution_json IS NOT NULL AND refund_bundle_id IS NULL AND redemption_bundle_id IS NULL",
    "native_refund": "payment_rail='CHIA_XCH' AND state='REFUNDING' AND refund_bundle_id IS NOT NULL",
    "base_refund": "payment_rail='BASE_SEPOLIA_USDC' AND state='REFUNDING' AND refund_bundle_id IS NOT NULL",
    "stripe_refund": "payment_rail='STRIPE_USD' AND state='REFUNDING' AND refund_bundle_id IS NOT NULL",
    "native_redemption": "payment_rail='CHIA_XCH' AND state='REDEEMING'",
    "base_redemption": "payment_rail='BASE_SEPOLIA_USDC' AND state='REDEEMING'",
    "stripe_redemption": "payment_rail='STRIPE_USD' AND state='REDEEMING'",
    "phase": "state='PRESALE' AND phase_bundle_id IS NOT NULL AND phase_confirmed_height IS NULL",
}
LEASE_SECONDS = 60
SCAN_LIMIT = 64


class VoucherWorkStore:
    def _create_voucher_work_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS voucher_worker_lanes (
              lane TEXT PRIMARY KEY, cursor_terms TEXT NOT NULL DEFAULT '',
              cursor_serial INTEGER NOT NULL DEFAULT -1,
              owner TEXT, lease_until REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS voucher_worker_series (
              terms_hash TEXT PRIMARY KEY, owner TEXT, lease_until REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS voucher_worker_attempts (
              lane TEXT NOT NULL, terms_hash TEXT NOT NULL, serial INTEGER NOT NULL,
              due_at REAL NOT NULL, attempts INTEGER NOT NULL, status TEXT NOT NULL,
              observed_at REAL NOT NULL, PRIMARY KEY(lane,terms_hash,serial));
            CREATE TABLE IF NOT EXISTS voucher_worker_executions (
              terms_hash TEXT NOT NULL, serial INTEGER NOT NULL, kind TEXT NOT NULL,
              execution_json TEXT NOT NULL, confirmed INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(terms_hash,serial,kind));
            CREATE TABLE IF NOT EXISTS voucher_refund_settlements (
              terms_hash TEXT NOT NULL, serial INTEGER NOT NULL, evidence_json TEXT NOT NULL,
              PRIMARY KEY(terms_hash,serial));
            CREATE TABLE IF NOT EXISTS voucher_refund_execution_history (
              terms_hash TEXT NOT NULL, serial INTEGER NOT NULL, bundle_id TEXT NOT NULL,
              execution_json TEXT NOT NULL, observation_json TEXT NOT NULL,
              PRIMARY KEY(terms_hash,serial,bundle_id));
        """)
        for lane, predicate in LANES.items():
            table = "campaign_operations" if lane == "campaign" else "voucher_worker_executions" if lane == "retained" else "presale_series_v2" if lane == "phase" else "voucher_records_v2"
            columns = "terms_hash" if lane in {"phase", "campaign"} else "terms_hash,serial"
            self._conn.execute(f"CREATE INDEX IF NOT EXISTS idx_voucher_work_{lane} ON {table}({columns}) WHERE {predicate}")
        self._conn.execute("""CREATE INDEX IF NOT EXISTS idx_voucher_work_pinned ON voucher_records_v2(terms_hash,serial)
            WHERE (issuance_bundle_id IS NOT NULL AND issuance_confirmed_height IS NULL)
               OR ((redemption_bundle_id IS NOT NULL OR refund_bundle_id IS NOT NULL OR terminal_exact_execution_json IS NOT NULL)
                   AND redemption_confirmed_height IS NULL AND refund_confirmed_height IS NULL)""")

    def claim_voucher_work(self, lane: str, owner: str, now: float, excluded_series: set[str] | None = None) -> dict[str, Any] | None:
        predicate = LANES[lane]  # Only internal, fixed lane names enter SQL.
        phase = lane in {"phase", "campaign"}
        table = "campaign_operations" if lane == "campaign" else "voucher_worker_executions" if lane == "retained" else "presale_series_v2" if phase else "voucher_records_v2"
        key = "terms_hash" if phase else "(terms_hash,serial)"
        columns = "terms_hash,-1 AS serial" if phase else "terms_hash,serial"
        with self.txn() as cur:
            cur.execute("INSERT OR IGNORE INTO voucher_worker_lanes(lane) VALUES (?)", (lane,))
            state = cur.execute("SELECT * FROM voucher_worker_lanes WHERE lane=?", (lane,)).fetchone()
            if state['lease_until'] > now:
                return None
            cursor = (state['cursor_terms'],) if phase else (state['cursor_terms'], state['cursor_serial'])
            placeholders = "?" if phase else "(?,?)"
            query = f"SELECT {columns} FROM {table} INDEXED BY idx_voucher_work_{lane} WHERE {predicate} AND {key}>{placeholders} ORDER BY {key if phase else 'terms_hash,serial'} LIMIT {SCAN_LIMIT}"
            rows = cur.execute(query, cursor).fetchall()
            if not rows:
                rows = cur.execute(query, ("",) if phase else ("", -1)).fetchall()
            for row in rows:
                terms, serial = row['terms_hash'], row['serial']
                cur.execute("UPDATE voucher_worker_lanes SET cursor_terms=?,cursor_serial=? WHERE lane=?", (terms, serial, lane))
                if excluded_series and terms in excluded_series:
                    continue
                retry = cur.execute("SELECT due_at FROM voucher_worker_attempts WHERE lane=? AND terms_hash=? AND serial=?", (lane, terms, serial)).fetchone()
                if retry and retry['due_at'] > now:
                    continue
                series = cur.execute("SELECT state,phase_bundle_id,phase_confirmed_height FROM presale_series_v2 WHERE terms_hash=?", (terms,)).fetchone()
                if lane != 'campaign' and cur.execute('SELECT 1 FROM campaign_operations WHERE terms_hash=? AND confirmed_height IS NULL', (terms,)).fetchone():
                    continue
                if lane == 'issuance' and (series['state'] != 'PRESALE' or series['phase_bundle_id'] is not None):
                    continue
                if lane.endswith('_redemption') and (series['state'] != 'LIVE' or series['phase_confirmed_height'] is None):
                    continue
                if lane not in {'retained', 'phase', 'campaign'}:
                    # Fair retry does not authorize competing singleton spends.
                    pinned = cur.execute("""SELECT serial FROM voucher_records_v2 INDEXED BY idx_voucher_work_pinned WHERE terms_hash=? AND
                        ((issuance_bundle_id IS NOT NULL AND issuance_confirmed_height IS NULL)
                        OR ((redemption_bundle_id IS NOT NULL OR refund_bundle_id IS NOT NULL OR terminal_exact_execution_json IS NOT NULL)
                        AND redemption_confirmed_height IS NULL AND refund_confirmed_height IS NULL)) LIMIT 1""", (terms,)).fetchone()
                    raw = cur.execute("SELECT serial FROM voucher_worker_executions WHERE terms_hash=? AND confirmed=0 LIMIT 1", (terms,)).fetchone()
                    if any(item and item['serial'] != serial for item in (pinned, raw)):
                        continue
                # Durable ownership is shared by ALL lanes for this singleton.
                cur.execute("INSERT OR IGNORE INTO voucher_worker_series VALUES (?,NULL,0)", (terms,))
                acquired = cur.execute("UPDATE voucher_worker_series SET owner=?,lease_until=? WHERE terms_hash=? AND lease_until<=?", (owner, now + LEASE_SECONDS, terms, now)).rowcount
                if not acquired:
                    continue
                cur.execute("UPDATE voucher_worker_lanes SET owner=?,lease_until=? WHERE lane=?", (owner, now + LEASE_SECONDS, lane))
                return dict(lane=lane, termsHash=terms, serial=serial, owner=owner)
        return None

    def finish_voucher_work(self, job: dict[str, Any], now: float, status: str) -> None:
        with self.txn() as cur:
            owned = cur.execute("UPDATE voucher_worker_lanes SET owner=NULL,lease_until=0 WHERE lane=? AND owner=?", (job['lane'], job['owner'])).rowcount
            if not owned:
                return  # A stale completion cannot clear a newer worker's lease.
            cur.execute("UPDATE voucher_worker_series SET owner=NULL,lease_until=0 WHERE terms_hash=? AND owner=?", (job['termsHash'], job['owner']))
            key = (job['lane'], job['termsHash'], job['serial'])
            old = cur.execute("SELECT attempts FROM voucher_worker_attempts WHERE lane=? AND terms_hash=? AND serial=?", key).fetchone()
            failed = status.endswith('_ERROR') or status in {'ERROR', 'TIMED_OUT', 'INTERRUPTED'}
            attempts = min(20, (old['attempts'] if old else 0) + 1) if failed else 0
            due = now + min(240, 15 * 2 ** min(4, attempts - 1)) if failed else now
            cur.execute("INSERT INTO voucher_worker_attempts VALUES (?,?,?,?,?,?,?) ON CONFLICT(lane,terms_hash,serial) DO UPDATE SET due_at=excluded.due_at,attempts=excluded.attempts,status=excluded.status,observed_at=excluded.observed_at", (*key, due, attempts, status, now))

    def claim_direct_voucher_work(self, terms, serial, owner, now):
        """Owner HTTP transactions share the same singleton lease as workers."""
        with self.txn() as cur:
            if self.pending_campaign_operation(terms) is not None:
                raise ValueError('Campaign phase work is awaiting confirmation or proven expiry')
            if cur.execute('SELECT 1 FROM voucher_worker_executions WHERE terms_hash=? AND confirmed=0', (terms,)).fetchone():
                raise ValueError('Original voucher execution is awaiting recovery')
            pinned = cur.execute("""SELECT 1 FROM voucher_records_v2 WHERE terms_hash=? AND
                (state IN ('PENDING_ISSUANCE','ISSUANCE_SUBMITTED') OR
                 (issuance_bundle_id IS NOT NULL AND issuance_confirmed_height IS NULL) OR
                 ((redemption_bundle_id IS NOT NULL OR refund_bundle_id IS NOT NULL OR terminal_exact_execution_json IS NOT NULL)
                  AND redemption_confirmed_height IS NULL AND refund_confirmed_height IS NULL)) LIMIT 1""", (terms,)).fetchone()
            if pinned:
                raise ValueError('Original voucher submission is awaiting recovery')
            cur.execute('INSERT OR IGNORE INTO voucher_worker_series VALUES (?,NULL,0)', (terms,))
            count = cur.execute('UPDATE voucher_worker_series SET owner=?,lease_until=? WHERE terms_hash=? AND lease_until<=?',
                                (owner, now + LEASE_SECONDS, terms, now)).rowcount
            if count != 1:
                raise ValueError('Voucher singleton is busy; retry after the current operation')

    def finish_direct_voucher_work(self, terms, owner):
        with self.txn() as cur:
            cur.execute('UPDATE voucher_worker_series SET owner=NULL,lease_until=0 WHERE terms_hash=? AND owner=?', (terms, owner))

    def retain_voucher_execution(self, terms: str, serial: int, execution: dict[str, Any]) -> None:
        encoded = json.dumps(execution, sort_keys=True, separators=(',', ':'))
        with self.txn() as cur:
            if self.pending_campaign_operation(terms) is not None:
                raise ValueError('Voucher execution cannot compete with retained campaign work')
            if execution['kind'] == 'funding':
                from chia_rs import SpendBundle
                inputs = {'0x' + c.name().hex() for c in SpendBundle.from_json_dict(execution['spendBundle']).removals()}
                if inputs & self.pending_campaign_funding_coin_ids():
                    raise ValueError('Voucher funding input is retained for a campaign')
            cur.execute("INSERT OR IGNORE INTO voucher_worker_executions(terms_hash,serial,kind,execution_json) VALUES (?,?,?,?)", (terms, serial, execution['kind'], encoded))
            row = cur.execute("SELECT execution_json FROM voucher_worker_executions WHERE terms_hash=? AND serial=? AND kind=?", (terms, serial, execution['kind'])).fetchone()
            if row['execution_json'] != encoded:
                raise ValueError('Voucher signed execution cannot be replaced')

    def pending_voucher_execution(self, terms: str, serial: int) -> dict[str, Any] | None:
        rows = self._conn.execute("SELECT execution_json FROM voucher_worker_executions WHERE terms_hash=? AND serial=? AND confirmed=0", (terms, serial)).fetchall()
        if len(rows) > 1:
            raise ValueError('Voucher has conflicting unfinished executions')
        return json.loads(rows[0]['execution_json']) if rows else None

    def native_refund_attempts(self, terms, serial):
        active = self.retained_voucher_execution(terms,serial,'native_refund')
        if active is None:
            return []
        previous = [json.loads(row[0]) for row in self._conn.execute(
            'SELECT execution_json FROM voucher_refund_execution_history WHERE terms_hash=? AND serial=? ORDER BY rowid DESC',
            (terms,serial))]
        return [active,*[e for e in previous if e != active]]

    def stripe_refund_attempts(self, terms, serial):
        active=self.voucher(terms,serial).get('terminalExactExecution')
        if active is None:return []
        previous=[json.loads(row[0]) for row in self._conn.execute(
            'SELECT execution_json FROM voucher_refund_execution_history WHERE terms_hash=? AND serial=? ORDER BY rowid DESC',
            (terms,serial))]
        return [active,*[e for e in previous if e!=active]]

    def refund_settlement(self, terms, serial):
        row=self._conn.execute('SELECT evidence_json FROM voucher_refund_settlements WHERE terms_hash=? AND serial=?',
            (terms,serial)).fetchone()
        return json.loads(row[0]) if row else None

    def record_refund_settlement(self, terms, serial, execution, evidence):
        """Retain actual primary-chain spends separately from signed attempts."""
        from chia_rs import SpendBundle
        from chia.types.coin_spend import CoinSpend
        from .refund_continuation import same_refund_spends
        stripe='prepared' in execution
        bundle=SpendBundle.from_json_dict(execution['prepared']['spendBundle'] if stripe else execution['spendBundle'])
        actual=[CoinSpend.from_json_dict(s) for s in evidence['observedCoinSpends']]
        if (evidence['authorizationBundleId']!='0x'+bundle.name().hex()
                or type(evidence['confirmedHeight']) is not int or evidence['confirmedHeight']<=0
                or evidence['kind']!=('EXACT_RETAINED_SPENDS' if bundle.coin_spends==actual else 'EQUIVALENT_VAULT_TIMESTAMP')
                or not same_refund_spends(bundle,actual)):
            raise ValueError('Refund settlement differs from its retained authorization')
        encoded=json.dumps(evidence,sort_keys=True,separators=(',',':'),allow_nan=False)
        with self.txn() as cur:
            active=(self.voucher(terms,serial).get('terminalExactExecution') if stripe
                else self.retained_voucher_execution(terms,serial,'native_refund'))
            if active!=execution:
                raise ValueError('Refund settlement lost its active-attempt comparison')
            previous=self.refund_settlement(terms,serial)
            if previous:
                # A later observation may have a newer peak. Preserve the first
                # receipt if the actual settlement and authorization are equal.
                if {k:v for k,v in previous.items() if k!='primaryAnchor'}!={k:v for k,v in evidence.items() if k!='primaryAnchor'}:
                    raise ValueError('Refund settlement evidence is immutable')
                return
            cur.execute('INSERT INTO voucher_refund_settlements VALUES (?,?,?)',(terms,serial,encoded))

    def advance_stripe_refund_attempt(self, terms, serial, previous, candidate, observation, *, confirmed=False):
        from .stripe_refund_continuation import same_effects
        encode=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)
        old_id=previous['prepared']['spendBundleId'];new_id=candidate['prepared']['spendBundleId']
        with self.txn() as cur:
            if confirmed:
                known=cur.execute('SELECT execution_json FROM voucher_refund_execution_history WHERE terms_hash=? AND serial=? AND bundle_id=?',
                    (terms,serial,new_id)).fetchone()
                if known is None or known[0]!=encode(candidate):raise ValueError('Confirmed Stripe refund is not retained')
            else:same_effects(previous,candidate)
            row=cur.execute('SELECT * FROM voucher_records_v2 WHERE terms_hash=? AND serial=?',(terms,serial)).fetchone()
            if (row is None or row['payment_rail']!='STRIPE_USD' or row['state'] not in {'ESCROWED','REFUNDING'}
                    or row['terminal_exact_execution_json']!=encode(previous) or row['refund_confirmed_height'] is not None
                    or row['refund_bundle_id'] not in {None,old_id} or row['redemption_bundle_id'] is not None):
                raise ValueError('Stripe refund continuation lost its active-attempt comparison')
            for bundle_id,document in ((old_id,previous),(new_id,candidate)):
                cur.execute('INSERT OR IGNORE INTO voucher_refund_execution_history VALUES (?,?,?,?,?)',
                    (terms,serial,bundle_id,encode(document),encode(observation)))
                stored=cur.execute('SELECT execution_json FROM voucher_refund_execution_history WHERE terms_hash=? AND serial=? AND bundle_id=?',
                    (terms,serial,bundle_id)).fetchone()
                if stored[0]!=encode(document):raise ValueError('Stripe refund history is immutable')
            cur.execute('UPDATE voucher_records_v2 SET terminal_exact_execution_json=?,refund_bundle_id=? WHERE terms_hash=? AND serial=?',
                (encode(candidate),new_id if row['refund_bundle_id'] else None,terms,serial))

    def advance_native_refund_attempt(self, terms, serial, previous, candidate, observation, *, confirmed=False):
        """CAS the active bytes; preserve all input/effect pins and both attempts."""
        from copy import deepcopy
        from chia_rs import SpendBundle
        from .refund_continuation import retime_native_refund, vault_refund_timestamp
        encode = lambda v: json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)
        old = SpendBundle.from_json_dict(previous['spendBundle'])
        new = SpendBundle.from_json_dict(candidate['spendBundle'])
        old_id,new_id = '0x'+old.name().hex(),'0x'+new.name().hex()
        if previous['kind'] != 'native_refund' or previous['bindings']['spend_bundle_id'] != old_id:
            raise ValueError('Refund continuation prior binding changed')
        expected = deepcopy(previous)
        expected['spendBundle'] = new.to_json_dict(); expected['bindings']['spend_bundle_id'] = new_id
        if expected != candidate:
            raise ValueError('Refund continuation changed its immutable bindings')
        with self.txn() as cur:
            if confirmed:
                known = cur.execute('SELECT execution_json FROM voucher_refund_execution_history WHERE terms_hash=? AND serial=? AND bundle_id=?',
                    (terms,serial,new_id)).fetchone()
                if known is None or known[0] != encode(candidate):
                    raise ValueError('Confirmed refund is not a retained attempt')
            else:
                vault_id = previous['bindings']['vault_input_coin_id']
                vault = next(s for s in new.coin_spends if '0x'+s.coin.name().hex() == vault_id)
                if retime_native_refund(old,vault_id,vault_refund_timestamp(vault)) != new:
                    raise ValueError('Refund continuation changed more than its timestamp')
            row = cur.execute("SELECT execution_json,confirmed FROM voucher_worker_executions WHERE terms_hash=? AND serial=? AND kind='native_refund'",
                (terms,serial)).fetchone()
            voucher = cur.execute('SELECT state,refund_bundle_id FROM voucher_records_v2 WHERE terms_hash=? AND serial=?', (terms,serial)).fetchone()
            if (row is None or row['execution_json'] != encode(previous) or row['confirmed']
                    or voucher is None or voucher['state'] != 'REFUNDING' or voucher['refund_bundle_id'] != old_id):
                raise ValueError('Refund continuation lost its active-attempt comparison')
            for bundle_id,document in ((old_id,previous),(new_id,candidate)):
                cur.execute('INSERT OR IGNORE INTO voucher_refund_execution_history VALUES (?,?,?,?,?)',
                    (terms,serial,bundle_id,encode(document),encode(observation)))
                stored = cur.execute('SELECT execution_json FROM voucher_refund_execution_history WHERE terms_hash=? AND serial=? AND bundle_id=?',
                    (terms,serial,bundle_id)).fetchone()
                if stored[0] != encode(document):
                    raise ValueError('Refund attempt history is immutable')
            cur.execute("UPDATE voucher_worker_executions SET execution_json=? WHERE terms_hash=? AND serial=? AND kind='native_refund'",
                (encode(candidate),terms,serial))
            cur.execute('UPDATE voucher_records_v2 SET refund_bundle_id=? WHERE terms_hash=? AND serial=?', (new_id,terms,serial))

    def retained_voucher_execution(self, terms: str, serial: int, kind: str) -> dict[str, Any] | None:
        """Original bytes remain available for independent terminal observation."""
        row = self._conn.execute('SELECT execution_json FROM voucher_worker_executions WHERE terms_hash=? AND serial=? AND kind=?',
            (terms, serial, kind)).fetchone()
        return json.loads(row['execution_json']) if row else None

    def confirm_voucher_execution(self, terms: str, serial: int, kind: str) -> None:
        with self.txn() as cur:
            cur.execute("UPDATE voucher_worker_executions SET confirmed=1 WHERE terms_hash=? AND serial=? AND kind=?", (terms, serial, kind))

    def pending_voucher_funding_coin_ids(self) -> set[str]:
        from chia_rs import SpendBundle
        rows = self._conn.execute("SELECT execution_json FROM voucher_worker_executions WHERE kind='funding' AND confirmed=0").fetchall()
        return {'0x' + coin.name().hex() for row in rows for coin in SpendBundle.from_json_dict(json.loads(row['execution_json'])['spendBundle']).removals()}
