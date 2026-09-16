from __future__ import annotations

import json

import pytest

from solslot_api.release_metadata import load_release_metadata, read_release_metadata


def test_loads_exact_release_commits(tmp_path) -> None:
    path = tmp_path / "release.json"
    path.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "protocolVersion": "solslot-v2",
                "api_commit": "a" * 40,
                "protocol_commit": "b" * 40,
                "built_at_utc": "2026-07-12T00:00:00Z",
                "package_name": "solslot_api",
                "app_module": "solslot_api.app:app",
            }
        ),
        encoding="utf-8",
    )
    metadata = load_release_metadata(str(path))
    assert metadata is not None
    assert metadata.schemaVersion == 2
    assert metadata.protocolVersion == "solslot-v2"
    assert metadata.apiCommit == "a" * 40
    assert metadata.protocolCommit == "b" * 40


def test_rejects_branch_like_release_reference(tmp_path) -> None:
    path = tmp_path / "release.json"
    path.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "protocolVersion": "solslot-v2",
                "api_commit": "staging",
                "protocol_commit": "b" * 40,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exact commit SHA"):
        load_release_metadata(str(path))


def test_authorization_read_observes_replacement_without_changing_cached_callers(tmp_path) -> None:
    path = tmp_path / 'release.json'
    value = dict(schemaVersion=2, protocolVersion='solslot-v2', api_commit='a'*40, protocol_commit='b'*40)
    path.write_text(json.dumps(value))
    cached = load_release_metadata(str(path))
    value['api_commit'] = 'c'*40
    path.write_text(json.dumps(value))
    assert load_release_metadata(str(path)) == cached
    assert read_release_metadata(str(path)).apiCommit == 'c'*40
    value['api_commit'] = 'main'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='exact commit SHA'):
        read_release_metadata(str(path))
