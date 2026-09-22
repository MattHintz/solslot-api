from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sqlite3

import pytest

from solslot_api.genesis_store import GenesisStore, canonical_json
from tests.test_launch_control import _client

spec = importlib.util.spec_from_file_location(
    "align_genesis_sources", Path(__file__).parents[1] / "scripts/align_genesis_sources.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

CID = "0x" + "a1" * 32
AE = "AE-SOLSLOT-TEST-ALIGNMENT"


@pytest.fixture
def prepared(tmp_path):
    _, store, settings = _client(tmp_path)
    evidence = Path(settings.launch_source_evidence_path)
    raw = json.loads(evidence.read_text())
    sources = raw["sourceManifest"]["sourceShas"]
    metadata = tmp_path / "release.json"
    metadata.write_text(json.dumps({"schemaVersion": 2, "protocolVersion": "solslot-v2", "api_commit": sources["api"],
        "protocol_commit": sources["protocol"], "built_at_utc": "2026-09-22T00:00:00Z"}))
    release = tool.target_release(evidence, tool.hashlib.sha256(evidence.read_bytes()).hexdigest(),
                                  settings.launch_release_tag, metadata)
    old = {"schemaVersion": 2, "sourceManifestVersion": 4, "network": "testnet11",
           "evmChainId": 11155111, "reviewClass": "independent-release-review",
           "releaseTag": "previous-release", "releaseEvidenceHash": "0x" + "11" * 32,
           "sourceShas": {**sources, "protocol": "a" * 40}}
    store.create_draft(CID, old, now=100)
    database = Path(store.path)
    with sqlite3.connect(database) as db:
        db.execute("UPDATE ceremonies SET state='roster_open' WHERE ceremony_id=?", (CID,))
        for slot in (1, 2, 3):
            db.execute("INSERT INTO invitations VALUES(?,?,?,?,?,?,?,?,?,?)",
                (CID, slot, f"token-{slot}", f"nonce-{slot}", 1000, 200,
                 "0x" + str(slot) * 40, "pubkey-" + str(slot), "signature-" + str(slot), 100))
        for slot in (1, 2):
            db.execute("INSERT INTO admin_recovery_kits VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (CID, slot, 1, "guardian", "public-bls", "commitment", "drill-hash", 201,
                 1, 1, "NOT_CONFIGURED", None, None, None, 201, 201))
        db.execute("INSERT INTO genesis_funding_receipts VALUES(?,?,?,?,?,?,?,?)",
                   (CID, '{}', 'funding-plan', 'funding-bundle', '{}', 'confirmed', 202, 202))
    return database, release, old, evidence, metadata, settings


def get_preview(database, release):
    db = tool.connect(database)
    try:
        return tool.preview(db, CID, release, AE)
    finally:
        db.close()


def test_preview_read_only_then_apply_preserves_enrollment_recovery_funding(prepared, tmp_path):
    database, release, old, *_ = prepared
    plan = get_preview(database, release)
    with tool.connect(database) as db:
        assert json.loads(db.execute("SELECT draft_json FROM ceremonies").fetchone()[0]) == old
        before_events = db.execute("SELECT count(*) FROM audit_events").fetchone()[0]
    backup = tmp_path / 'before.db'
    result = tool.apply(database, release, CID, AE, plan['alignmentHash'], backup)
    assert result['enrollmentsPreserved'] and not result['planCreated']
    assert backup.stat().st_mode & 0o777 == 0o600
    with tool.connect(database) as db, tool.connect(backup) as prior:
        row = db.execute("SELECT * FROM ceremonies").fetchone()
        assert row['state'] == 'roster_open' and row['plan_hash'] is None
        assert json.loads(row['draft_json']) == plan['afterDraft']
        assert json.loads(prior.execute("SELECT draft_json FROM ceremonies").fetchone()[0]) == old
        assert tool.related_records(db, CID) == tool.related_records(prior, CID) == plan['preservedRecords']
        assert db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == before_events + 1
        event = json.loads(db.execute("SELECT event_json FROM audit_events WHERE event_type='source_release_aligned'").fetchone()[0])
        assert event['beforeDraft'] == old and event['alignmentHash'] == plan['alignmentHash']
    with pytest.raises(ValueError, match='already selects'):
        get_preview(database, release)


@pytest.mark.parametrize('mutation,params,error', [
    ("UPDATE ceremonies SET state='roster_frozen'", (), 'unfrozen'),
    ("UPDATE ceremonies SET plan_hash='has-plan'", (), 'planning'),
    ("INSERT INTO plan_signatures VALUES(?,?,?,?,?,?)", (CID, 1, 'hash', 'key', 'signature', 123), 'plan_signatures'),
])
def test_refuses_advanced_ceremony(prepared, mutation, params, error):
    database, release, *_ = prepared
    with sqlite3.connect(database) as db:
        db.execute(mutation, params)
    with pytest.raises(ValueError, match=error):
        get_preview(database, release)


def test_stale_preview_cannot_overwrite_concurrent_recovery(prepared, tmp_path):
    database, release, *_ = prepared
    plan = get_preview(database, release)
    with sqlite3.connect(database) as db:
        db.execute('UPDATE admin_recovery_kits SET revision=2 WHERE slot=2')
    with pytest.raises(ValueError, match='stale'):
        tool.apply(database, release, CID, AE, plan['alignmentHash'], tmp_path / 'before.db')
    assert not (tmp_path / 'before.db').exists()


def test_rejects_chain_change_selected_activation_and_existing_backup(prepared, tmp_path):
    database, release, old, *_ = prepared
    for draft in ({**old, 'evmChainId': 8453}, {**old, 'enrollmentActivation': None}):
        with sqlite3.connect(database) as db:
            db.execute('UPDATE ceremonies SET draft_json=?', (canonical_json(draft),))
        with pytest.raises(ValueError, match='legacy'):
            get_preview(database, release)
    with sqlite3.connect(database) as db:
        db.execute('UPDATE ceremonies SET draft_json=?', (canonical_json(old),))
    backup = tmp_path / 'exists.db'
    backup.write_text('preserved')
    with pytest.raises(ValueError, match='overwrite'):
        tool.apply(database, release, CID, AE, get_preview(database, release)['alignmentHash'], backup)
    assert backup.read_text() == 'preserved'


def test_target_requires_exact_evidence_and_installed_sources(prepared):
    _, _, _, evidence, metadata, settings = prepared
    with pytest.raises(Exception, match='checksum'):
        tool.target_release(evidence, '0' * 64, settings.launch_release_tag, metadata)
    data = json.loads(metadata.read_text()); data['protocol_commit'] = 'b' * 40
    metadata.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='installed'):
        tool.target_release(evidence, tool.hashlib.sha256(evidence.read_bytes()).hexdigest(),
                            settings.launch_release_tag, metadata)


def test_unexpired_action_approval_blocks_alignment(prepared):
    database, release, *_ = prepared
    with sqlite3.connect(database) as db:
        db.execute('INSERT INTO launch_action_approvals VALUES(?,?,?,?,?,?,?,?,?)',
                   (CID, 'action', 'funding', 'hash', 1, 'address', 'signature', 100, 9999999999))
    with pytest.raises(ValueError, match='approvals'):
        get_preview(database, release)


def test_audit_failure_rolls_back_draft_and_retains_backup(prepared, tmp_path):
    database, release, old, *_ = prepared
    plan = get_preview(database, release)
    with sqlite3.connect(database) as db:
        db.execute("CREATE TRIGGER fail_alignment BEFORE INSERT ON audit_events "
                   "WHEN NEW.event_type='source_release_aligned' "
                   "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
    backup = tmp_path / 'before-failure.db'
    with pytest.raises(sqlite3.IntegrityError, match='audit unavailable'):
        tool.apply(database, release, CID, AE, plan['alignmentHash'], backup)
    with tool.connect(database) as db:
        assert json.loads(db.execute('SELECT draft_json FROM ceremonies').fetchone()[0]) == old
        assert tool.related_records(db, CID) == plan['preservedRecords']
    assert backup.exists()
