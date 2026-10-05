from io import BytesIO
import hashlib
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

import httpx
import pytest

from solslot_api.collection_document_types import XLSX_MIME, is_private_workbook
from solslot_api.collection_local_storage import create_media_app, LocalStorage
from solslot_api.collection_media import CollectionMediaPipeline, MediaVerificationError
from solslot_api.config import Settings, get_settings
from tests.test_collection_endpoints import _client


def workbook(*, macro=False, extra=None, default_type=False):
    out = BytesIO()
    content_type = ('application/vnd.ms-excel.sheet.macroEnabled.main+xml' if macro else
                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml')
    type_declaration = (f'<Default Extension="xml" ContentType="{content_type}"/>' if default_type else f'<Override PartName="/xl/workbook.xml" ContentType="{content_type}"/>')
    with ZipFile(out, 'w', ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', f'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">{type_declaration}</Types>')
        archive.writestr('xl/workbook.xml', '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>')
        if extra:
            archive.writestr(*extra)
    return out.getvalue()


def settings(root):
    root.mkdir(mode=0o700)
    for directory in ('quarantine', 'public'): (root/directory).mkdir(mode=0o700)
    return Settings(runtime_environment='test', collection_storage_backend='filesystem',
                    collection_local_root=str(root), collection_local_base_url='https://files.test/collection-media',
                    collection_asset_max_bytes=8*1024*1024, collection_local_min_free_bytes=0,
                    admin_jwt_secret='synthetic-private-budget-' + 'k'*32,
                    collection_malware_scan_url='https://scanner.test/scan',
                    collection_ipfs_api_url='https://ipfs.test', collection_ipfs_pinning_service_url='https://pin.test',
                    collection_ipfs_pinning_token='synthetic-token', collection_ipfs_gateway_url='https://gateway.test')


@pytest.mark.parametrize('payload', [b'PK\x03\x04not-a-workbook', workbook(macro=True),
    workbook(extra=('../escape', b'x')), workbook(extra=('xl/vbaProject.bin', b'bad')),
    workbook(extra=('xl/large.xml', b'x'*(8*1024*1024+1)))])
def test_private_workbook_rejects_other_archives_macros_and_expansion(payload):
    assert not is_private_workbook(payload)


@pytest.mark.asyncio
async def test_private_workbook_preserves_original_bytes_without_publication(tmp_path):
    payload = workbook()
    config = settings(tmp_path/'storage')
    sha = hashlib.sha256(payload).hexdigest()
    pipeline = CollectionMediaPipeline(config, transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={'status':'CLEAN'})))
    upload = pipeline.presign_upload(collection_id='SYNTHETIC', asset_id='budget', filename='budget.xlsx',
        private=True, expected_sha256=sha, expected_byte_size=len(payload), expected_mime_type=XLSX_MIME)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_media_app(config))) as client:
        assert (await client.put(upload['uploadUrl'], headers=upload['headers'], content=payload)).status_code == 201
        assert (await client.get(upload['uploadUrl'])).status_code == 403
    verified = await pipeline.verify_private_document(object_key=upload['objectKey'],
        expected_sha256=sha, expected_byte_size=len(payload), expected_mime_type=XLSX_MIME)
    assert verified.sha256 == sha and verified.mime_type == XLSX_MIME
    assert verified.availability_status == 'PRIVATE' and verified.malware_status == 'CLEAN'
    assert LocalStorage(config).read(upload['objectKey'], len(payload)) == payload
    assert not list((Path(config.collection_local_root)/'public').iterdir())
    with pytest.raises(MediaVerificationError, match='private originals'):
        await pipeline.verify_and_pin(object_key=upload['objectKey'], expected_sha256=sha,
            expected_byte_size=len(payload), expected_mime_type=XLSX_MIME, asset_name='budget')
    with pytest.raises(MediaVerificationError, match='restricted private'):
        pipeline.presign_upload(collection_id='SYNTHETIC', asset_id='public-budget', filename='budget.xlsx',
            private=False, expected_sha256=sha, expected_byte_size=len(payload), expected_mime_type=XLSX_MIME)


def test_resume_reuses_commitment_and_object_without_erasing_original(tmp_path):
    client, store, app = _client(tmp_path)
    config = settings(tmp_path/'storage')
    app.dependency_overrides[get_settings] = lambda: config.model_copy(update={'collection_metadata_enabled':True})
    try:
        store.create(title='Synthetic retry', owner_subject='0xowner', owner_auth_type='evm', collection_id='SYNTHETIC-RETRY')
        body = {'assetId':'plans', 'kind':'DOCUMENT', 'visibility':'PRIVATE', 'title':'Plans', 'category':'plans',
                'filename':'plans.pdf', 'sha256':'a'*64, 'mimeType':'application/pdf', 'byteSize':10}
        path = '/admin/collections/SYNTHETIC-RETRY/assets/presign'
        first = client.post(path, json=body)
        assert first.status_code == 200, first.text
        previous = first.json()['asset']
        resumed = client.post(path, json=body)
        assert resumed.status_code == 200, resumed.text
        assert resumed.json()['objectKey'] == first.json()['objectKey']
        assert resumed.json()['asset']['revision'] == previous['revision']
        conflict = client.post(path, json={**body, 'sha256':'b'*64})
        assert conflict.status_code == 409
        assert store.get_asset('SYNTHETIC-RETRY', 'plans') == previous
        public_xlsx = client.post(path, json={**body, 'assetId':'public-budget', 'visibility':'PUBLIC', 'mimeType':XLSX_MIME})
        assert public_xlsx.status_code == 422
        assert len(store.get('SYNTHETIC-RETRY')['assets']) == 1
    finally:
        client.close(); store.close()


def test_workbook_accepts_default_content_type_without_accepting_a_macro_default():
    assert is_private_workbook(workbook(default_type=True))
    assert not is_private_workbook(workbook(default_type=True, macro=True))


def test_unsupported_archive_compression_is_rejected_without_an_internal_error():
    payload = bytearray(workbook())
    for signature, offset in ((b'PK\x03\x04', 8), (b'PK\x01\x02', 10)):
        position = payload.find(signature)
        while position >= 0:
            payload[position+offset:position+offset+2] = (99).to_bytes(2, 'little')
            position = payload.find(signature, position+4)
    assert not is_private_workbook(bytes(payload))
