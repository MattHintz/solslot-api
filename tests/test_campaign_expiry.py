"""Canonical time and input evidence required before releasing a launch claim."""
from copy import deepcopy

import pytest
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from solslot_api.campaign_expiry import expiry_requests
from solslot_api.validator_ledger import ValidatorLedger


def digest(number):
    return '0x' + number.to_bytes(32, 'big').hex()


def drive(*, fault=None, clock=102, mutate=None):
    coin = Coin(bytes32.from_hexstr(digest(1)), bytes32.from_hexstr(digest(2)), 1)
    responses = 0
    proof = expiry_requests('testnet11', coin, 100)
    method, args = next(proof)
    while True:
        if method == 'get_network_info':
            result = dict(success=True, network_name='mainnet' if fault == 'network' else 'testnet11')
        elif method == 'get_blockchain_state':
            responses += 1
            result = dict(success=True, blockchain_state=dict(
                sync=dict(synced=fault != 'unsynced', sync_mode=fault == 'syncing'),
                peak=dict(height=200, header_hash=digest(201 if fault == 'reorg' and responses == 2 else 200))))
        elif method == 'get_block_record':
            height = int(args['header_hash'], 16)
            timestamp = clock - (200-height)
            if fault == 'no_clock':
                timestamp = None
            elif fault == 'invalid_clock':
                timestamp = True
            result = dict(success=True, block_record=dict(height=height,
                header_hash=digest(height+1 if fault == 'ancestor' else height),
                prev_hash=digest(height-1), timestamp=timestamp))
        else:
            result = dict(coin=coin.to_json_dict(), confirmed_block_index=199 if fault == 'immature' else 10,
                spent=fault == 'spent', spent_block_index=20 if fault == 'spent' else 0)
            if fault == 'coin':
                result['coin']['amount'] = 2
        if mutate:
            result = mutate(method, deepcopy(result))
        try:
            method, args = proof.send(result)
        except StopIteration as done:
            return done.value


def test_expiry_requires_three_confirmations_of_the_actual_deadline():
    assert drive(clock=101) is None
    proof = drive(clock=102)
    assert proof['timestamp'] == proof['consensusDeadline'] == 100
    assert proof['clockHeight'] == proof['peakHeight'] - 2


@pytest.mark.parametrize('fault', ['network', 'unsynced', 'syncing', 'reorg',
    'ancestor', 'no_clock', 'invalid_clock', 'immature', 'spent', 'coin'])
def test_conflicting_or_incomplete_expiry_evidence_cannot_release_input(fault):
    with pytest.raises(ValueError):
        drive(fault=fault)


def test_v15_signature_history_survives_additive_migration_and_exact_recovery(tmp_path):
    path = tmp_path / 'private-signer.sqlite'
    old = ValidatorLedger(path)
    claim = dict(claim_hash=digest(1), canonical_claim='{"original":"claim"}',
                 series_coin_id=digest(2), transition=1, signature='original-private-signature')
    old.record_voucher_series_phase_or_recover(**claim)
    original = tuple(old._conn.execute('SELECT * FROM voucher_series_phase_signatures').fetchone())
    # Synthetic V15 state: the original signature tables remain, and the
    # additive V16-only tables do not exist. No live ledger is opened here.
    old._conn.executescript('DROP TABLE voucher_series_phase_retry_signatures; '
        'DROP TABLE voucher_phase_expiry_observations; PRAGMA user_version=15;')
    old.close()
    migrated = ValidatorLedger(path)
    try:
        assert migrated._conn.execute('PRAGMA user_version').fetchone()[0] == 16
        assert tuple(migrated._conn.execute('SELECT * FROM voucher_series_phase_signatures').fetchone()) == original
        assert migrated.recover_voucher_series_phase(claim['claim_hash'], claim['canonical_claim']) == claim['signature']
        assert migrated._conn.execute('SELECT COUNT(*) FROM voucher_series_phase_retry_signatures').fetchone()[0] == 0
        assert migrated.healthcheck()
    finally:
        migrated.close()
