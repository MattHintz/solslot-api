"""Bounded deposit RPC work, independent of checkout and recovery capacity.

No request waits in an executor queue. Cancellation/deadline cannot release a
worker or its durable per-purchase lease while the synchronous proof still runs.
Leases bound duplicate work across API processes; failed attempts cool down.
They authorize neither a payment nor an inventory hold.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import secrets
import sqlite3
import threading
import time

from .escrow_deposit import EscrowProviderUnavailable

MAX_WORKERS = 4
RESPONSE_DEADLINE_SECONDS = 15.0
LEASE_SECONDS = 120
FAILURE_COOLDOWN_SECONDS = 5
WORKER_CLEANUP_BUSY_TIMEOUT_SECONDS = 1.0
_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="escrow-proof")
_slots = threading.BoundedSemaphore(MAX_WORKERS)


class EscrowVerificationBusy(EscrowProviderUnavailable):
    pass


def migrate_escrow_verifications(db):
    db.execute("""CREATE TABLE IF NOT EXISTS payment_escrow_verification_leases (
        purchase_id TEXT PRIMARY KEY REFERENCES payment_purchases(purchase_id),
        owner TEXT, lease_until REAL NOT NULL, retry_after REAL NOT NULL
    )""")
    db.execute("""CREATE INDEX IF NOT EXISTS payment_escrow_verification_active
        ON payment_escrow_verification_leases(lease_until)""")


def _connect(path, *, busy_timeout_seconds=0.05):
    # Do not allow a contended lease table to stall the event loop. Never hold
    # a database transaction across provider I/O or sleep while holding a lock.
    db = sqlite3.connect(path, timeout=busy_timeout_seconds, isolation_level=None)
    db.execute("PRAGMA foreign_keys=ON")
    return db


def acquire(path, purchase_id, owner, *, now):
    db = _connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT lease_until,retry_after FROM payment_escrow_verification_leases WHERE purchase_id=?",
                         (purchase_id,)).fetchone()
        if row and max(row) > now:
            raise EscrowVerificationBusy("EVM deposit verification is running or cooling down; retry the same payment")
        if db.execute("SELECT count(*) FROM payment_escrow_verification_leases WHERE lease_until>?",
                      (now,)).fetchone()[0] >= MAX_WORKERS:
            raise EscrowVerificationBusy("EVM deposit verification capacity is busy; retry the same payment")
        db.execute("""INSERT INTO payment_escrow_verification_leases VALUES (?,?,?,?)
            ON CONFLICT(purchase_id) DO UPDATE SET owner=excluded.owner,
            lease_until=excluded.lease_until,retry_after=excluded.retry_after""",
                   (purchase_id, owner, now + LEASE_SECONDS, now))
        db.execute("COMMIT")
    except sqlite3.Error as exc:
        raise EscrowVerificationBusy("EVM deposit verification ledger is busy or unavailable") from exc
    finally:
        db.close()


def finish(path, purchase_id, owner, *, now, succeeded, busy_timeout_seconds=0.05):
    db = _connect(path, busy_timeout_seconds=busy_timeout_seconds)
    try:
        db.execute("""UPDATE payment_escrow_verification_leases
            SET owner=NULL,lease_until=0,retry_after=? WHERE purchase_id=? AND owner=?""",
                   (now + (0 if succeeded else FAILURE_COOLDOWN_SECONDS), purchase_id, owner))
    except sqlite3.Error:
        # An unreleased lease fails closed until expiry; never mask the proof's
        # result or release somebody else's lease after a restart.
        pass
    finally:
        db.close()


async def run_deposit_verification(path, purchase_id, verifier):
    if not _slots.acquire(blocking=False):
        raise EscrowVerificationBusy("EVM deposit verification capacity is busy; retry the same payment")
    owner = secrets.token_hex(16)
    try:
        acquire(path, purchase_id, owner, now=time.time())
    except BaseException:
        _slots.release()
        raise

    def work():
        succeeded = False
        try:
            result = verifier()
            succeeded = True
            return result
        finally:
            try:
                # Cleanup runs in the bounded worker, not the event loop. Give
                # simultaneous completions a bounded opportunity to acquire the
                # writer lock; admission and pre-submit failures remain fast.
                finish(path, purchase_id, owner, now=time.time(), succeeded=succeeded,
                       busy_timeout_seconds=WORKER_CLEANUP_BUSY_TIMEOUT_SECONDS)
            finally:
                _slots.release()

    try:
        future = _executor.submit(work)
    except BaseException:
        finish(path, purchase_id, owner, now=time.time(), succeeded=False)
        _slots.release()
        raise
    wrapped = asyncio.wrap_future(future)
    # Retrieve late failures even when the HTTP caller has gone away. Only the
    # worker's finally block releases its capacity; shield prevents cancellation
    # from recycling a slot for an overlapping copy of the same RPC work.
    wrapped.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
    try:
        return await asyncio.wait_for(asyncio.shield(wrapped), RESPONSE_DEADLINE_SECONDS)
    except TimeoutError as exc:
        raise EscrowProviderUnavailable("EVM deposit verification timed out; retry the same payment") from exc
