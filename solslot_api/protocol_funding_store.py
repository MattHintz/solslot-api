"""Write-once fee reservations for ordinary protocol submissions.

This runtime journal is separate from signed launch evidence. A timeout, process
restart or changed quote never authorizes a second funded transaction. Retained
input reservations are conservative: even rejected attempts need reconciliation
before their coins can be reused. No private transaction bytes enter log output.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import threading
import time

from chia_rs import SpendBundle


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class ProtocolFundingStore:
    def __init__(self, path: str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Refuse a symlink and create with private permissions before SQLite
            # opens it, so a new journal never has a world-readable interval.
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.fchmod(fd, 0o600)
            os.close(fd)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS funded_protocol_bundles (
                network TEXT NOT NULL, original_id TEXT NOT NULL,
                context TEXT NOT NULL, document TEXT NOT NULL, created_at INTEGER NOT NULL,
                PRIMARY KEY(network, original_id));
            CREATE TABLE IF NOT EXISTS funded_protocol_inputs (
                network TEXT NOT NULL, coin_id TEXT NOT NULL, original_id TEXT NOT NULL,
                PRIMARY KEY(network, coin_id));
            CREATE TABLE IF NOT EXISTS funded_protocol_events (
                id INTEGER PRIMARY KEY, network TEXT NOT NULL, original_id TEXT NOT NULL,
                event TEXT NOT NULL, error_code TEXT, recorded_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS funded_protocol_completions (
                network TEXT NOT NULL, original_id TEXT NOT NULL,
                payload TEXT NOT NULL, created_at INTEGER NOT NULL,
                completed_at INTEGER,
                PRIMARY KEY(network, original_id));
        ''')

    def lookup(self, network, original_id, context):
        with self.lock:
            row = self.db.execute(
                "SELECT context,document FROM funded_protocol_bundles WHERE network=? AND original_id=?",
                (network, original_id),
            ).fetchone()
        if row is None:
            return None
        if row["context"] != canonical(context):
            raise ValueError("Saved protocol funding belongs to a different funding context")
        document = json.loads(row["document"])
        bundle = SpendBundle.from_json_dict(document["spendBundle"])
        if document["spendBundleId"] != "0x" + bundle.name().hex():
            raise ValueError("Saved protocol funding bundle does not match its identifier")
        return document

    def reserve(self, network, original_id, context, document):
        bundle = SpendBundle.from_json_dict(document["spendBundle"])
        if document["spendBundleId"] != "0x" + bundle.name().hex():
            raise ValueError("Protocol funding bundle does not match its identifier")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                prior = self.lookup(network, original_id, context)
                if prior is not None:
                    if canonical(prior) != canonical(document):
                        raise ValueError("Original protocol bundle already has exact funding")
                    self.db.execute("COMMIT")
                    return
                self.db.execute("INSERT INTO funded_protocol_bundles VALUES(?,?,?,?,?)",
                    (network, original_id, canonical(context), canonical(document), int(time.time())))
                # Reserve every input, not only the fee. A second request with
                # changed protocol bytes cannot sponsor the same spend again.
                self.db.executemany("INSERT INTO funded_protocol_inputs VALUES(?,?,?)", [
                    (network, "0x" + coin.name().hex(), original_id) for coin in bundle.removals()])
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def reserved_coin_ids(self):
        with self.lock:
            return {row[0] for row in self.db.execute("SELECT coin_id FROM funded_protocol_inputs")}

    def event(self, network, original_id, event, code=None):
        with self.lock:
            self.db.execute("INSERT INTO funded_protocol_events(network,original_id,event,error_code,recorded_at) VALUES(?,?,?,?,?)",
                (network, original_id, event, code, int(time.time())))

    def save_completion(self, network, original_id, payload):
        """Persist validated application recording instructions before RPC.

        Payloads are private runtime records, not release evidence. Only the
        trusted MINT endpoint can create them after semantic authorization.
        """
        encoded = canonical(payload)
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                reservation = self.db.execute(
                    "SELECT document FROM funded_protocol_bundles WHERE network=? AND original_id=?",
                    (network, original_id)).fetchone()
                if reservation is None:
                    raise ValueError("Completion requires a durable funded bundle")
                document = json.loads(reservation[0])
                if payload.get("bundleId") != document["spendBundleId"]:
                    raise ValueError("Completion belongs to a different funded bundle")
                prior = self.db.execute(
                    "SELECT payload FROM funded_protocol_completions WHERE network=? AND original_id=?",
                    (network, original_id)).fetchone()
                if prior is not None and prior[0] != encoded:
                    raise ValueError("Completion instructions are immutable")
                self.db.execute("INSERT OR IGNORE INTO funded_protocol_completions VALUES(?,?,?,?,NULL)",
                    (network, original_id, encoded, int(time.time())))
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def pending_completions(self, network, *, limit=50, after=""):
        with self.lock:
            rows = self.db.execute('''SELECT c.original_id,c.payload,b.document
                FROM funded_protocol_completions c JOIN funded_protocol_bundles b
                ON c.network=b.network AND c.original_id=b.original_id
                WHERE c.network=? AND c.completed_at IS NULL AND c.original_id>?
                ORDER BY c.original_id LIMIT ?''', (network, after, limit)).fetchall()
        return [dict(row) for row in rows]

    def complete(self, network, original_id):
        with self.lock:
            self.db.execute("UPDATE funded_protocol_completions SET completed_at=COALESCE(completed_at,?) WHERE network=? AND original_id=?",
                (int(time.time()), network, original_id))

    def close(self):
        with self.lock:
            self.db.close()
