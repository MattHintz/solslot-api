"""Bounded, durable checkout work. No database transaction crosses provider I/O."""
import json

from .inventory_extension_store import canonical, conflict


def migrate_lifecycle(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS payment_start_observations (
            purchase_id TEXT PRIMARY KEY, claim_json TEXT NOT NULL, receipt_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS payment_start_candidates (
            purchase_id TEXT PRIMARY KEY, candidate_json TEXT NOT NULL, binding_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS payment_checkout_jobs (
            purchase_id TEXT NOT NULL, lane TEXT NOT NULL, due_at INTEGER NOT NULL DEFAULT 0,
            done INTEGER NOT NULL DEFAULT 0, owner TEXT, lease_until INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'WAITING', observed_at INTEGER,
            PRIMARY KEY(purchase_id,lane)
        );
        CREATE INDEX IF NOT EXISTS checkout_jobs_due ON payment_checkout_jobs(lane,done,due_at,purchase_id);
        CREATE TABLE IF NOT EXISTS payment_checkout_worker_leases (
            lane TEXT PRIMARY KEY, owner TEXT, lease_until INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS payment_checkout_worker_health (
            lane TEXT PRIMARY KEY, observed_at INTEGER NOT NULL, binding_json TEXT NOT NULL, status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS payment_checkout_backfill (id INTEGER PRIMARY KEY CHECK(id=1), cursor TEXT NOT NULL);
        INSERT OR IGNORE INTO payment_checkout_backfill VALUES (1,'');
        CREATE TRIGGER IF NOT EXISTS checkout_schedule_after_hold AFTER INSERT ON payment_checkout_holds BEGIN
            INSERT OR IGNORE INTO payment_checkout_jobs(purchase_id,lane) VALUES (NEW.purchase_id,'renewal');
            INSERT OR IGNORE INTO payment_checkout_jobs(purchase_id,lane) VALUES (NEW.purchase_id,'terminal');
        END;
    ''')


class CheckoutLifecycleStoreMixin:
    def seed_checkout_jobs(self):
        # Indexed keyset pagination bounds each restart/backfill turn. Concurrent
        # creation is covered by the transaction's trigger, even behind the cursor.
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            cursor = db.execute('SELECT cursor FROM payment_checkout_backfill WHERE id=1').fetchone()[0]
            rows = db.execute('SELECT purchase_id,state FROM payment_checkout_holds WHERE purchase_id>? '
                'ORDER BY purchase_id LIMIT 64', (cursor,)).fetchall()
            for row in rows:
                if row['state'] not in ('RETURNED', 'DELIVERED'):
                    for lane in ('renewal', 'terminal'):
                        db.execute('INSERT OR IGNORE INTO payment_checkout_jobs(purchase_id,lane) VALUES (?,?)', (row['purchase_id'], lane))
            if rows:
                db.execute('UPDATE payment_checkout_backfill SET cursor=? WHERE id=1', (rows[-1]['purchase_id'],))
            db.execute('COMMIT')

    def payment_start(self, purchase_id):
        with self._connect() as db:
            row = db.execute('SELECT * FROM payment_start_observations WHERE purchase_id=?', (purchase_id,)).fetchone()
            return dict(claim=json.loads(row['claim_json']), receipt=json.loads(row['receipt_json'])) if row else None

    def retain_payment_start(self, purchase_id, *, claim, receipt, artifact, snapshot):
        from .payment_start import verify_start_receipt
        from .payment_purchase_store import _record
        verify_start_receipt(claim, receipt, artifact)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            parent = db.execute('SELECT * FROM payment_purchases WHERE purchase_id=?', (purchase_id,)).fetchone()
            hold = db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if parent is None or _record(parent) != snapshot or parent['inventory_state'] != 'CONFIRMED':
                raise conflict('purchase changed before verified payment start was retained')
            if claim.purchase_artifact != snapshot.purchase_artifact:
                raise conflict('payment start changes the retained purchase')
            if hold:
                bound = json.loads(hold['claim_json'])
                if (hold['state'] != 'ARMED' or hold['payment_intent_id'] != claim.payment_intent_id
                        or bound['payment_method'] != claim.payment_method):
                    raise conflict('payment start changes a partial, terminal or different checkout')
            old = db.execute('SELECT * FROM payment_start_observations WHERE purchase_id=?', (purchase_id,)).fetchone()
            encoded = canonical(claim.model_dump(mode='json'))
            if old and old['claim_json'] != encoded:
                raise conflict('verified payment start cannot be replaced')
            db.execute('INSERT OR IGNORE INTO payment_start_observations VALUES (?,?,?)', (purchase_id, encoded, canonical(receipt)))
            db.execute('COMMIT')

    def retain_payment_candidate(self, purchase_id, *, candidate, binding, expected_hold):
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            from .inventory_payment_hold_store import hold_operation
            hold = db.execute('SELECT * FROM payment_checkout_holds WHERE purchase_id=?', (purchase_id,)).fetchone()
            if hold_operation(hold) != expected_hold or hold is None or hold['state'] != 'ARMED':
                raise conflict('candidate needs its original armed checkout')
            if (candidate['payment_intent_id'] != hold['payment_intent_id']
                    or candidate['payment_method'] != json.loads(hold['claim_json'])['payment_method']):
                raise conflict('candidate changes checkout payment identity')
            anchor = db.execute('SELECT claim_json FROM payment_start_observations WHERE purchase_id=?', (purchase_id,)).fetchone()
            if anchor and any(json.loads(anchor[0])[k] != v for k,v in candidate.items()):
                raise conflict('candidate changes independently verified payment start')
            old = db.execute('SELECT binding_json FROM payment_start_candidates WHERE purchase_id=?', (purchase_id,)).fetchone()
            if old and old[0] != canonical(binding):
                raise conflict('candidate cannot migrate between releases')
            # Until quorum verification, a corrected event may replace a bad
            # callback candidate. Replays never reset backoff or create more jobs.
            db.execute('INSERT INTO payment_start_candidates VALUES (?,?,?) ON CONFLICT(purchase_id) '
                'DO UPDATE SET candidate_json=excluded.candidate_json', (purchase_id, canonical(candidate), canonical(binding)))
            db.execute('COMMIT')

    def payment_candidate(self, purchase_id):
        with self._connect() as db:
            row = db.execute('SELECT * FROM payment_start_candidates WHERE purchase_id=?', (purchase_id,)).fetchone()
            return dict(payment=json.loads(row['candidate_json']), binding=json.loads(row['binding_json'])) if row else None

    def claim_checkout_job(self, lane, *, owner, now, lease_seconds=60):
        if lane not in ('renewal', 'terminal'):
            raise ValueError('unknown lifecycle lane')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            busy = db.execute('SELECT lease_until FROM payment_checkout_worker_leases WHERE lane=?', (lane,)).fetchone()
            if busy and busy[0] > now:
                return dict(busy=True)
            row = db.execute('SELECT * FROM payment_checkout_jobs WHERE lane=? AND done=0 AND due_at<=? '
                'AND lease_until<=? ORDER BY due_at,purchase_id LIMIT 1', (lane, now, now)).fetchone()
            if row is None:
                return None
            db.execute('INSERT INTO payment_checkout_worker_leases VALUES (?,?,?) ON CONFLICT(lane) '
                'DO UPDATE SET owner=excluded.owner,lease_until=excluded.lease_until', (lane, owner, now+lease_seconds))
            db.execute('UPDATE payment_checkout_jobs SET owner=?,lease_until=? WHERE purchase_id=? AND lane=?',
                (owner, now+lease_seconds, row['purchase_id'], lane))
            db.execute('COMMIT')
            return dict(row)

    def finish_checkout_job(self, purchase_id, lane, *, owner, now, status, done=False):
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT attempts FROM payment_checkout_jobs WHERE purchase_id=? AND lane=? AND owner=?',
                (purchase_id, lane, owner)).fetchone()
            if row:
                attempts = min(row[0]+1, 10) if status in ('UNAVAILABLE', 'TIMED_OUT', 'INTERRUPTED', 'REVIEW_REQUIRED') else 0
                delay = min(300, 15 * 2**min(attempts, 4))
                db.execute('UPDATE payment_checkout_jobs SET owner=NULL,lease_until=0,due_at=?,attempts=?,status=?,done=?,observed_at=? '
                    'WHERE purchase_id=? AND lane=? AND owner=?', (now+delay, attempts, status, int(done), now, purchase_id, lane, owner))
            db.execute('UPDATE payment_checkout_worker_leases SET owner=NULL,lease_until=0 WHERE lane=? AND owner=?', (lane, owner))
            db.execute('COMMIT')

    def lifecycle_health(self, lane, *, now, binding, status):
        with self._connect() as db:
            db.execute('INSERT INTO payment_checkout_worker_health VALUES (?,?,?,?) ON CONFLICT(lane) '
                'DO UPDATE SET observed_at=excluded.observed_at,binding_json=excluded.binding_json,status=excluded.status',
                (lane, now, canonical(binding), status))

    def lifecycle_health_receipts(self):
        with self._connect() as db:
            return [dict(lane=r['lane'], observedAt=r['observed_at'], binding=json.loads(r['binding_json']), status=r['status'])
                for r in db.execute('SELECT * FROM payment_checkout_worker_health ORDER BY lane')]

    def checkout_job_status(self, purchase_id):
        with self._connect() as db:
            return [dict(lane=r['lane'], status=r['status'], observedAt=r['observed_at'], nextAttemptAt=r['due_at'])
                for r in db.execute('SELECT * FROM payment_checkout_jobs WHERE purchase_id=? ORDER BY lane', (purchase_id,))]
