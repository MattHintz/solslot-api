from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import shutil
import sqlite3

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32

from solslot_api.generation_customer_store import (
    GenerationCustomerStore, CustomerRegistrationConflict, read_consent,
)
from solslot_api.generation_storage import GenerationStorageError, GenerationRetentionFull, generation_path
from tests.test_generation_customer_launch import fixture, sign


def store(tmp_path, consent):
    return GenerationCustomerStore(str(tmp_path / 'registrations.sqlite'),
        '0x' + consent.bindings.generation.hex())


@pytest.mark.parametrize('auth', ['evm', 'chia_bls'])
def test_duplicate_clicks_restart_and_expired_poll_preserve_signed_work(tmp_path, auth):
    data = fixture(auth)
    consent = data[3]
    saved = store(tmp_path, consent)
    first = saved.reserve(consent, now=1000)
    assert saved.reserve(consent, now=1001) == first
    signature = sign(consent, data[4])
    authorized = saved.accept_signature(first['registrationId'], signature, now=1001)
    restarted = store(tmp_path, consent)
    assert restarted.accept_signature(first['registrationId'], signature, now=5000) == authorized
    assert restarted.status(first['registrationId'], now=5001) == authorized
    assert authorized['stage'] == 'AUTHORIZED'
    assert authorized['authorizationSavedAt'] == 1001
    assert authorized['identityVerified'] is False
    assert authorized['registrationConfirmed'] is False
    assert authorized['transactionId'] is None
    assert 'signature' not in authorized


def test_status_is_read_only_and_expiry_does_not_rebuild_or_release_funding(tmp_path):
    consent = fixture()[3]
    saved = store(tmp_path, consent)
    first = saved.reserve(consent, now=1000)
    before = sha256(Path(saved.path).read_bytes()).digest()
    expired = saved.status(first['registrationId'], now=1200)
    assert expired['stage'] == 'CONSENT_EXPIRED'
    assert saved.held_funding_ids() == frozenset([consent.message()['fundingCoinId']])
    assert sha256(Path(saved.path).read_bytes()).digest() == before
    with pytest.raises(ValueError, match='expired'):
        saved.accept_signature(first['registrationId'], sign(consent, fixture()[4]), now=1200)
    assert saved.status(first['registrationId'], now=1200) == expired


def test_new_challenge_or_destination_cannot_overwrite_existing_review(tmp_path):
    consent = fixture()[3]
    saved = store(tmp_path, consent)
    first = saved.reserve(consent, now=1000)
    with pytest.raises(CustomerRegistrationConflict, match='resumed or reconciled'):
        saved.reserve(replace(consent, nonce=bytes32(b'x' * 32)), now=1000)
    assert saved.status(first['registrationId'], now=1000) == first


def test_unsigned_expiry_releases_only_temporary_hold_and_preserves_prior_review(tmp_path):
    data = fixture()
    consent = data[3]
    saved = store(tmp_path, consent)
    first = saved.reserve(consent, now=1000)
    assert saved.expire_unsigned(now=1200) == 1
    assert not saved.held_funding_ids()
    assert saved.status(first['registrationId'], now=1200)['stage'] == 'EXPIRED_UNSIGNED'
    newer = replace(consent, nonce=bytes32(b'x' * 32), expires_at=1400)
    second = saved.reserve(newer, now=1200)
    assert second['registrationId'] != first['registrationId']
    with pytest.raises(CustomerRegistrationConflict, match='expired'):
        saved.accept_signature(first['registrationId'], sign(consent, data[4]), now=1200)
    signed = saved.accept_signature(second['registrationId'], sign(newer, data[4]), now=1201)
    assert saved.expire_unsigned(now=2000) == 0
    assert saved.status(second['registrationId'], now=2000) == signed
    assert len(saved.held_funding_ids()) == 1


def test_two_owners_cannot_reserve_same_parent_and_concurrent_retries_remain_one_review(tmp_path):
    consent = fixture()[3]
    saved = store(tmp_path, consent)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: saved.reserve(consent, now=1000), range(2)))
    assert results[0] == results[1]
    other = replace(consent, nonce=bytes32(b'x' * 32),
        owner='0x' + bytes(AugSchemeMPL.key_gen(b'different synthetic owner seed!!').get_g1()).hex())
    with pytest.raises(CustomerRegistrationConflict, match='already held'):
        saved.reserve(other, now=1000)
    assert len(saved.held_funding_ids()) == 1


def test_wrong_signature_leaves_original_review_unchanged(tmp_path):
    data = fixture()
    saved = store(tmp_path, data[3])
    first = saved.reserve(data[3], now=1000)
    wrong = sign(data[3], AugSchemeMPL.key_gen(b'wrong synthetic owner seed only!'))
    with pytest.raises(ValueError, match='another owner'):
        saved.accept_signature(first['registrationId'], wrong, now=1001)
    assert saved.status(first['registrationId'], now=1001) == first


def test_foreign_generation_database_cannot_be_imported_or_retagged(tmp_path):
    consent = fixture()[3]
    saved = store(tmp_path, consent)
    saved.reserve(consent, now=1000)
    another = '0x' + 'ab' * 32
    foreign_path = Path(generation_path(str(tmp_path / 'registrations.sqlite'), another))
    foreign_path.parent.mkdir(parents=True)
    shutil.copyfile(saved.path, foreign_path)
    before = foreign_path.read_bytes()
    with pytest.raises(GenerationStorageError, match='another deployment generation'):
        GenerationCustomerStore(str(foreign_path), another)
    assert foreign_path.read_bytes() == before


def test_tampered_signature_is_not_a_saved_authorization(tmp_path):
    data = fixture()
    saved = store(tmp_path, data[3])
    first = saved.reserve(data[3], now=1000)
    saved.accept_signature(first['registrationId'], sign(data[3], data[4]), now=1001)
    with sqlite3.connect(saved.path) as db:
        db.execute('UPDATE customer_registration_consents SET signature=?', ('0x' + '00' * 96,))
    with pytest.raises(ValueError):
        saved.status(first['registrationId'], now=1002)


def test_retention_limit_fails_before_inserting_or_deleting_evidence(tmp_path):
    consent = fixture()[3]
    saved = store(tmp_path, consent)
    saved.MAX_RETAINED_BYTES = 0
    with pytest.raises(GenerationRetentionFull):
        saved.reserve(consent, now=1000)
    assert not saved.held_funding_ids()


@pytest.mark.parametrize('mutation', ['history', 'network', 'generation', 'unknown'])
def test_receipt_like_or_noncanonical_documents_cannot_become_registration(mutation):
    consent = fixture()[3]
    document = consent.message()
    if mutation == 'history':
        document['purpose'] = 'IMPORT_EARLIER_VAULT'
    elif mutation == 'network':
        document['network'] = 'mainnet'
    elif mutation == 'generation':
        document['generationId'] = '0x' + 'AB' * 32
    else:
        document['idVerified'] = True
    with pytest.raises(ValueError):
        read_consent(document)
