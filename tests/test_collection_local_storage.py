from __future__ import annotations

import hashlib
import time
from pathlib import Path

import httpx
import pytest

from solslot_api.collection_local_storage import LocalStorage, create_media_app
from solslot_api.collection_media import CollectionMediaPipeline, MediaVerificationError
from solslot_api.config import Settings

PNG = b"\x89PNG\r\n\x1a\n" + b"synthetic-AE165"
DIGEST = hashlib.sha256(PNG).hexdigest()


def local_settings(root: Path, **values) -> Settings:
    root.mkdir(mode=0o700)
    for name in ("quarantine", "public"):
        (root / name).mkdir(mode=0o700)
    return Settings(runtime_environment="test", collection_storage_backend="filesystem",
                    collection_local_root=str(root), collection_local_base_url="https://files.test/collection-media",
                    admin_jwt_secret="synthetic-tests-only-" + "k" * 32,
                    collection_asset_max_bytes=1024, collection_local_min_free_bytes=0,
                    **values)


def presign(settings, *, private=False):
    return CollectionMediaPipeline(settings).presign_upload(collection_id="SYNTHETIC-165", asset_id="photo",
        filename="synthetic.png", private=private, expected_sha256=DIGEST,
        expected_byte_size=len(PNG), expected_mime_type="image/png")


@pytest.mark.asyncio
async def test_create_only_scope_and_original_survive_replay(tmp_path):
    settings = local_settings(tmp_path / "store")
    upload = presign(settings)
    storage = LocalStorage(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_media_app(settings))) as client:
        first = await client.put(upload["uploadUrl"], content=PNG, headers=upload["headers"])
        assert first.status_code == 201
        for body in (PNG, PNG[:-1] + b"!"):
            assert (await client.put(upload["uploadUrl"], content=body, headers=upload["headers"])).status_code == 412
        omitted = {k: v for k, v in upload["headers"].items() if k != "If-None-Match"}
        assert (await client.put(upload["uploadUrl"], content=PNG, headers=omitted)).status_code == 403
        changed_key = upload["uploadUrl"].replace("/asset.png", "/asset.pdf")
        assert (await client.put(changed_key, content=PNG, headers=upload["headers"])).status_code == 403
        assert (await client.put(upload["uploadUrl"], content=PNG)).status_code == 403
        assert (await client.get(storage.base_url + "/public/" + storage.object_id(upload["objectKey"]))).status_code == 404
    assert storage.read(upload["objectKey"], len(PNG)) == PNG


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation,expected", [("bytes", 422), ("size", 413), ("type", 422), ("origin", 403), ("condition", 403)])
async def test_bad_upload_never_installs_a_file(tmp_path, mutation, expected):
    settings = local_settings(tmp_path / "store")
    upload = presign(settings)
    headers = dict(upload["headers"])
    payload = PNG
    if mutation == "bytes": payload = PNG[:-1] + b"!"
    if mutation == "size": payload += b"!"
    if mutation == "type": headers["Content-Type"] = "text/html"
    if mutation == "origin": headers["Origin"] = "https://attacker.test"
    if mutation == "condition": headers["If-None-Match"] = "wrong"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_media_app(settings))) as client:
        result = await client.put(upload["uploadUrl"], content=payload, headers=headers)
    assert result.status_code == expected
    assert not list((Path(settings.collection_local_root) / "quarantine").iterdir())


@pytest.mark.asyncio
async def test_quota_fails_closed_without_partial_files(tmp_path):
    settings = local_settings(tmp_path / "store", collection_local_quota_bytes=len(PNG) - 1)
    upload = presign(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_media_app(settings))) as client:
        assert (await client.put(upload["uploadUrl"], content=PNG, headers=upload["headers"])).status_code == 507
    assert not list((Path(settings.collection_local_root) / "quarantine").iterdir())


@pytest.mark.asyncio
async def test_private_download_needs_exact_unexpired_capability_and_cannot_promote(tmp_path, monkeypatch):
    settings = local_settings(tmp_path / "store")
    upload = presign(settings, private=True)
    storage = LocalStorage(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_media_app(settings))) as client:
        assert (await client.put(upload["uploadUrl"], content=PNG, headers=upload["headers"])).status_code == 201
        assert (await client.get(upload["uploadUrl"])).status_code == 403
        url = CollectionMediaPipeline(settings).presign_private_download(object_key=upload["objectKey"])
        downloaded = await client.get(url)
        assert downloaded.status_code == 200 and downloaded.content == PNG
        assert downloaded.headers["cache-control"] == "no-store"
        assert downloaded.headers["content-disposition"] == "attachment"
        monkeypatch.setattr(time, "time", lambda: 200000000000)
        assert (await client.get(url)).status_code == 403
    with pytest.raises(ValueError, match="private originals"):
        storage.promote(upload["objectKey"], DIGEST)


@pytest.mark.asyncio
async def test_verified_public_file_is_readable_and_symlink_is_rejected(tmp_path):
    settings = local_settings(tmp_path / "store")
    upload = presign(settings)
    storage = LocalStorage(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_media_app(settings))) as client:
        assert (await client.put(upload["uploadUrl"], content=PNG, headers=upload["headers"])).status_code == 201
        url = storage.promote(upload["objectKey"], DIGEST)
        assert storage.promote(upload["objectKey"], DIGEST) == url
        response = await client.get(url)
        assert response.content == PNG and response.headers["x-content-type-options"] == "nosniff"
        assert "immutable" in response.headers["cache-control"]
        protected = tmp_path / "outside"
        protected.write_bytes(PNG)
        (Path(settings.collection_local_root) / "public" / ("a" * 64 + ".blob")).symlink_to(protected)
        assert (await client.get(storage.base_url + "/public/" + "a" * 64)).status_code == 503


@pytest.mark.asyncio
async def test_public_pipeline_refuses_private_before_read_or_pin(tmp_path):
    settings = local_settings(tmp_path / "store", collection_ipfs_api_url="http://127.0.0.1:5002",
                            collection_ipfs_pinning_mode="kubo", collection_ipfs_gateway_url="http://127.0.0.1:8082",
                            collection_malware_scan_url="https://scanner.test")
    upload = presign(settings, private=True)
    with pytest.raises(MediaVerificationError, match="private originals"):
        await CollectionMediaPipeline(settings).verify_and_pin(object_key=upload["objectKey"],
            expected_sha256=DIGEST, expected_mime_type="image/png", expected_byte_size=len(PNG), asset_name="photo")


@pytest.mark.asyncio
async def test_capability_dispatch_does_not_bypass_existing_auth_or_chain_boundary(tmp_path):
    from solslot_api.collection_media_runtime import with_local_collection_media
    from starlette.responses import Response
    calls = []

    async def original(scope, receive, send):
        calls.append(scope["path"])
        await Response("existing XSRF boundary", status_code=403)(scope, receive, send)

    settings = local_settings(tmp_path / "store")
    app = with_local_collection_media(original, settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://files.test") as client:
        for path in ("/admin/mint/execute", "/auth/login", "/zkpassport/relay", "/collection-media-evil/objects/x"):
            response = await client.post(path, content=b"{}")
            assert response.status_code == 403 and response.text == "existing XSRF boundary"
        assert len(calls) == 4
        assert (await client.put("/collection-media/objects/bogus", content=b"x")).status_code == 403
        assert len(calls) == 4
