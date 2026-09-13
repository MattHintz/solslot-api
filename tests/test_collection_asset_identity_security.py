from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from botocore.auth import S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

import pytest

from solslot_api.collection_media import CollectionMediaPipeline
from solslot_api.collection_store import CollectionConflict, CollectionNotFound, CollectionStore
from tests.test_collection_media import _settings


@pytest.mark.parametrize('first,second', [
    (('COL', 'report', 'report.pdf'), ('COL', 'rep/ort', 'report.pdf')),
    (('COL', 'report', 'report.pdf'), ('COL', 'rep ort', 'report.pdf')),
    (('COL', 'report', 'report.pdf'), ('COL', 'rep%ort', 'report.pdf')),
    (('COL', 'report', 'report.pdf'), ('COL', 'rep\\ort', 'report.pdf')),
    (('COL', 'report', 'report.pdf'), ('COL', 're\u0301port', 'report.pdf')),
    (('COL', 'report', 'report.pdf'), ('C/OL', 'report', 'report.pdf')),
    (('COL', 'report', 'report.pdf'), ('COL', 'report.pdf', 'extensionless')),
    (('COL', 'x' * 160 + 'a', 'a.pdf'), ('COL', 'x' * 160 + 'b', 'b.pdf')),
])
def test_distinct_identities_and_attempts_never_share_upload_keys(first, second):
    pipeline = CollectionMediaPipeline(_settings())
    def sign(item):
        return pipeline.presign_upload(collection_id=item[0], asset_id=item[1], filename=item[2])
    one, two = sign(first), sign(second)
    assert one['objectKey'] != two['objectKey']
    assert sign(first)['objectKey'] != one['objectKey']


def test_upload_requires_signed_write_once_condition():
    pipeline = CollectionMediaPipeline(_settings())
    signed = pipeline.presign_upload(collection_id='COL', asset_id='report', filename='report.pdf')
    assert signed['headers'] == {'If-None-Match': '*'}
    query = parse_qs(urlparse(signed['uploadUrl']).query)
    assert query['X-Amz-SignedHeaders'] == ['host;if-none-match']


def test_signature_matches_aws_sdk_and_cannot_drop_write_once_header(monkeypatch):
    pipeline = CollectionMediaPipeline(_settings())
    upload = pipeline.presign_upload(collection_id='COL', asset_id='report', filename='report.pdf')
    parsed = urlparse(upload['uploadUrl'])
    query = parse_qs(parsed.query)
    signed_at = datetime.strptime(query['X-Amz-Date'][0], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    monkeypatch.setattr('botocore.auth.get_current_datetime', lambda: signed_at)
    def sdk_signature(headers):
        request = AWSRequest(method='PUT', url=parsed._replace(query='').geturl(), headers=headers)
        S3SigV4QueryAuth(Credentials('access-key', 'secret-key'), 's3', 'us-east-1',
                        expires=upload['expiresIn']).add_auth(request)
        return parse_qs(urlparse(request.url).query)['X-Amz-Signature'][0]
    signature = query['X-Amz-Signature'][0]
    assert sdk_signature(upload['headers']) == signature
    assert sdk_signature({}) != signature
    assert sdk_signature({'If-None-Match': 'another-value'}) != signature


def create(store, identifier, slug=None):
    return store.create(collection_id=identifier, title=identifier, slug=slug,
                        owner_subject='owner', owner_auth_type='evm')


def declare(store, collection='COL', asset='report', digest='11' * 32):
    return store.declare_asset(collection, asset_id=asset, kind='DOCUMENT',
        expected_sha256=digest, expected_mime_type='application/pdf',
        expected_byte_size=10, actor_subject='reviewer')


def test_object_keys_cannot_be_reassigned_or_shared_across_collections():
    store = CollectionStore(':memory:')
    try:
        create(store, 'COL'); create(store, 'SECOND')
        declare(store); declare(store, 'SECOND')
        store.assign_asset_object_key('COL', 'report', object_key='objects/original', actor_subject='reviewer')
        with pytest.raises(CollectionConflict):
            store.assign_asset_object_key('SECOND', 'report', object_key='objects/original', actor_subject='reviewer')
        with pytest.raises(CollectionConflict):
            store.assign_asset_object_key('COL', 'report', object_key='objects/replacement', actor_subject='reviewer')
        with pytest.raises(CollectionConflict):
            store.mark_asset_uploaded('COL', 'report', object_key='objects/replacement', actor_subject='reviewer')
        assert store.get_asset('COL', 'report')['objectKey'] == 'objects/original'
    finally:
        store.close()


def test_collection_writes_do_not_resolve_a_different_collections_slug():
    store = CollectionStore(':memory:')
    try:
        create(store, 'COL', slug='public-slug')
        assert store.get('public-slug')['id'] == 'COL'
        assert store.readiness('public-slug') == store.readiness('COL')
        with pytest.raises(CollectionNotFound):
            declare(store, 'public-slug')
        with pytest.raises(CollectionConflict):
            create(store, 'public-slug')
    finally:
        store.close()


def test_stale_verification_cannot_change_a_new_upload_attempt():
    store = CollectionStore(':memory:')
    try:
        create(store, 'COL')
        first = declare(store)
        declare(store, digest='22' * 32)
        with pytest.raises(CollectionConflict):
            store.assign_asset_object_key('COL', 'report', object_key='objects/stale',
                actor_subject='reviewer', expected_revision=first['revision'])
        assert store.get_asset('COL', 'report')['objectKey'] is None
    finally:
        store.close()
