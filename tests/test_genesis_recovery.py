"""Synthetic SQLite migration and recovery rehearsal; never opens runtime data."""
from __future__ import annotations

import hashlib
import sqlite3

import pytest

import solslot_api.genesis_store as genesis
from tests.launch_authority_fixtures import bootstrap_settings
from tests.test_genesis_store import CEREMONY, _enroll


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def backup(source, destination):
    # SQLite's backup API includes committed WAL pages; copying only the main
    # database file while it is live is not a valid recovery method.
    with sqlite3.connect(source) as current, sqlite3.connect(destination) as copy:
        current.backup(copy)
        assert copy.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert copy.execute("PRAGMA foreign_key_check").fetchall() == []


def rows(path):
    with sqlite3.connect(path) as connection:
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )]
        return {table: connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
                for table in tables}


def test_schema12_backup_migration_restore_preserves_consumed_invitations(tmp_path, monkeypatch):
    source, prior, migrated, restored = [tmp_path / name for name in
        ("synthetic.db", "schema12-backup.db", "schema13-backup.db", "restored.db")]
    store = genesis.GenesisStore(source)
    store.create_draft(CEREMONY, {"sourceShas": {}}, now=100)
    store.consume_owner_claim(CEREMONY, token_hash="synthetic-owner-claim", now=101)
    _enroll(store, 1, now=110)
    store.upsert_gate(CEREMONY, gate_name="purchases", opens_at=120, closes_at=300,
                      payload_hash="0x" + "aa" * 32, state="open", now=120)
    # Produce the exact prior schema from the additive 12 -> 13 migration.
    with sqlite3.connect(source) as connection:
        connection.execute("ALTER TABLE launch_gates DROP COLUMN approval_snapshot_json")
        connection.execute("PRAGMA user_version=12")
    backup(source, prior)
    prior_hash, prior_rows = digest(prior), rows(prior)

    migrated_store = genesis.GenesisStore(source)
    with sqlite3.connect(source) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 13
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # Retained unsigned legacy gate rows cannot acquire permission by migration.
    with pytest.raises(genesis.GenesisConflict, match="activation proof"):
        migrated_store.authorized_gate(bootstrap_settings(migrated_store), CEREMONY, "purchases", now=130)
    expected = rows(source)
    assert {name: value for name, value in expected.items() if name != "launch_gates"} == {
        name: value for name, value in prior_rows.items() if name != "launch_gates"}
    assert [row[:-1] for row in expected["launch_gates"]] == prior_rows["launch_gates"]

    # Keep a WAL connection alive with an uncheckpointed committed update.
    with sqlite3.connect(source) as writer:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("UPDATE ceremonies SET updated_at=131 WHERE ceremony_id=?", (CEREMONY,))
        writer.commit()
        expected = rows(source)
        backup(source, migrated)
    assert rows(migrated) == expected
    migrated_hash = digest(migrated)
    backup(migrated, restored)
    reopened = genesis.GenesisStore(restored)
    assert rows(restored) == expected
    assert reopened.owner_claim_used("synthetic-owner-claim")
    with pytest.raises(genesis.GenesisConflict, match="already consumed"):
        reopened.consume_owner_claim(CEREMONY, token_hash="synthetic-owner-claim", now=132)
    with pytest.raises(genesis.GenesisConflict):
        reopened.consume_invitation(token_hash="token-1", wallet_address="0x"+"01"*20,
            compressed_pubkey="0x"+"01"*33, signature="0x"+"01"*65, now=132)

    # Reuse the actual store guard with the preceding binary's supported version.
    monkeypatch.setattr(genesis, "SCHEMA_VERSION", 12)
    with pytest.raises(RuntimeError, match="newer than supported 12"):
        genesis.GenesisStore(restored)
    assert digest(prior) == prior_hash and digest(migrated) == migrated_hash
    assert rows(prior) == prior_rows
