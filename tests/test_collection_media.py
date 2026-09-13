from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from solslot_api.collection_media import (
    CollectionMediaPipeline,
    MediaPipelineUnavailable,
    MediaVerificationError,
)
from solslot_api.config import Settings


PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"verified-solslot-image"
CID = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3w5h5m4rj5zv5q3n5dnm7q6ha"


def _settings() -> Settings:
    return Settings(
        runtime_environment="test",
        collection_s3_endpoint_url="https://s3.example.test",
        collection_s3_region="us-east-1",
        collection_s3_bucket="collections",
        collection_s3_access_key_id="access-key",
        collection_s3_secret_access_key="secret-key",
        collection_s3_public_base_url="https://assets.example.test",
        collection_ipfs_api_url="https://ipfs-api.example.test",
        collection_ipfs_pinning_service_url="https://pins.example.test",
        collection_ipfs_pinning_token="pin-token",
        collection_ipfs_gateway_url="https://gateway.example.test/ipfs/{cid}",
        collection_malware_scan_url="https://scanner.example.test/scan",
    )


def test_presign_is_scoped_and_signed() -> None:
    upload = CollectionMediaPipeline(_settings()).presign_upload(
        collection_id="HARBOR-17",
        asset_id="hero-exterior",
        filename="Front View.PNG",
    )
    assert upload["objectKey"].startswith("collections/v2/")
    assert upload["objectKey"].endswith("/asset.png")
    assert upload["method"] == "PUT"
    assert "X-Amz-Algorithm=AWS4-HMAC-SHA256" in upload["uploadUrl"]
    assert "X-Amz-Signature=" in upload["uploadUrl"]


def test_presign_fails_closed_without_storage() -> None:
    with pytest.raises(MediaPipelineUnavailable, match="not configured"):
        CollectionMediaPipeline(Settings(runtime_environment="test")).presign_upload(
            collection_id="HARBOR-17",
            asset_id="hero",
            filename="hero.png",
        )


@pytest.mark.asyncio
async def test_verify_scan_pin_and_refetch_pipeline() -> None:
    requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, str(request.url)))
        if request.method == "GET" and request.url.host in {
            "s3.example.test",
            "assets.example.test",
            "gateway.example.test",
        }:
            return httpx.Response(200, content=PNG_BYTES, headers={"content-type": "image/png"})
        if request.url.host == "scanner.example.test":
            return httpx.Response(200, json={"status": "CLEAN"})
        if request.url.host == "ipfs-api.example.test":
            return httpx.Response(200, text=json.dumps({"Hash": CID}) + "\n")
        if request.url.host == "pins.example.test":
            return httpx.Response(202, json={"pin": {"cid": CID}})
        return httpx.Response(404)

    pipeline = CollectionMediaPipeline(
        _settings(), transport=httpx.MockTransport(handler)
    )
    digest = hashlib.sha256(PNG_BYTES).hexdigest()
    verified = await pipeline.verify_and_pin(
        object_key="collections/HARBOR-17/hero.png",
        expected_sha256=digest,
        expected_mime_type="image/png",
        expected_byte_size=len(PNG_BYTES),
        asset_name="hero",
    )
    assert verified.sha256 == digest
    assert verified.cid == CID
    assert verified.malware_status == "CLEAN"
    assert verified.availability_status == "HEALTHY"
    assert any(host in url for _method, url in requests for host in ["scanner.example.test"])
    assert sum(1 for method, _url in requests if method == "GET") == 3


@pytest.mark.asyncio
async def test_verify_rejects_altered_bytes_before_pinning() -> None:
    called_hosts: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called_hosts.append(request.url.host)
        return httpx.Response(200, content=PNG_BYTES)

    pipeline = CollectionMediaPipeline(
        _settings(), transport=httpx.MockTransport(handler)
    )
    with pytest.raises(MediaVerificationError, match="SHA-256 mismatch"):
        await pipeline.verify_and_pin(
            object_key="collections/HARBOR-17/hero.png",
            expected_sha256="00" * 32,
            expected_mime_type="image/png",
            expected_byte_size=len(PNG_BYTES),
            asset_name="hero",
        )
    assert called_hosts == ["s3.example.test"]


@pytest.mark.asyncio
async def test_private_document_is_scanned_but_never_pinned_or_published() -> None:
    requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, str(request.url)))
        if request.method == "GET" and request.url.host == "s3.example.test":
            return httpx.Response(200, content=PNG_BYTES)
        if request.url.host == "scanner.example.test":
            return httpx.Response(200, json={"status": "CLEAN"})
        raise AssertionError(f"private verification called public service {request.url}")

    pipeline = CollectionMediaPipeline(
        _settings(), transport=httpx.MockTransport(handler)
    )
    digest = hashlib.sha256(PNG_BYTES).hexdigest()
    verified = await pipeline.verify_private_document(
        object_key="private/collections/HARBOR-17/title.png",
        expected_sha256=digest,
        expected_mime_type="image/png",
        expected_byte_size=len(PNG_BYTES),
    )
    assert verified.availability_status == "PRIVATE"
    assert {httpx.URL(url).host for _method, url in requests} == {
        "s3.example.test",
        "scanner.example.test",
    }


def test_private_presign_uses_segregated_prefix() -> None:
    upload = CollectionMediaPipeline(_settings()).presign_upload(
        collection_id="HARBOR-17",
        asset_id="unredacted-title",
        filename="title.pdf",
        private=True,
    )
    assert upload["objectKey"].startswith("private/collections/v2/")
    assert upload["objectKey"].endswith("/asset.pdf")
