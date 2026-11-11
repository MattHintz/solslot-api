"""Generation-scoped recovery admission for private property preparation.

The existing 21-journal lane includes collections.sqlite and preview/review
records. It does not cover media bytes. Keep those two claims separate.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import time

from fastapi import HTTPException

HEX = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = {
    'schema', 'entity', 'network', 'actionEnvelopeId', 'purpose', 'generationId',
    'sourceHash', 'principalId', 'checkedAt', 'restoredAt', 'containerPrivate',
    'immutabilityVerified', 'createOnly', 'restoreMatches', 'databaseCount',
    'restoredBytes', 'manifest', 'restoreEvidenceSha256', 'inventoryInitialized',
}


def validate_record_receipt(value, generation_id, source_hash, *, now=None):
    now = time.time() if now is None else now
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('COLLECTION_RECOVERY_CONTRACT_DIFFERS')
    expected = {
        'schema': 'solslot.generation-recovery-health.v1', 'entity': 'SOLSLOT',
        'network': 'testnet11', 'actionEnvelopeId': 'AE-SOLSLOT-GENERATION-RECOVERY-20261013-222',
        'purpose': 'LIVE_GENERATION_RECOVERY', 'generationId': generation_id,
        'sourceHash': source_hash, 'principalId': '6b6d66ae-e403-406e-8e2c-0f0b2709f1f4',
    }
    if any(value.get(k) != v for k, v in expected.items()):
        raise ValueError('COLLECTION_RECOVERY_BINDING_DIFFERS')
    for binding in (generation_id, source_hash):
        if not isinstance(binding, str) or not binding.startswith('0x') or not HEX.fullmatch(binding[2:]):
            raise ValueError('COLLECTION_RECOVERY_BINDING_INVALID')
    if any(value[k] is not True for k in ('containerPrivate', 'immutabilityVerified',
                                         'createOnly', 'restoreMatches', 'inventoryInitialized')):
        raise ValueError('COLLECTION_RECOVERY_NOT_HEALTHY')
    if any(type(value[k]) is not int or not now - 600 <= value[k] <= now + 30
           for k in ('checkedAt', 'restoredAt')) or value['restoredAt'] > value['checkedAt'] + 30:
        raise ValueError('COLLECTION_RECOVERY_STALE')
    if (type(value['databaseCount']) is not int or value['databaseCount'] != 21
            or type(value['restoredBytes']) is not int or not 0 < value['restoredBytes'] <= 512 * 1024**2):
        raise ValueError('COLLECTION_RECOVERY_INCOMPLETE')
    record = value['manifest']
    if not isinstance(record, dict) or set(record) != {'blobName', 'sha256', 'bytes', 'etag'}:
        raise ValueError('COLLECTION_RECOVERY_MANIFEST_DIFFERS')
    if (not isinstance(record['sha256'], str) or not HEX.fullmatch(record['sha256'])
            or record['blobName'] != f"generation-journals/{generation_id[2:]}/{record['sha256']}.aesgcm.json"
            or type(record['bytes']) is not int or not 0 < record['bytes'] <= 1024**2
            or not isinstance(record['etag'], str) or not 1 <= len(record['etag']) <= 256
            or not isinstance(value['restoreEvidenceSha256'], str)
            or not HEX.fullmatch(value['restoreEvidenceSha256'])):
        raise ValueError('COLLECTION_RECOVERY_OBJECT_DIFFERS')
    return value


def read_record_receipt(settings, *, now=None):
    path = Path(settings.collection_generation_recovery_path or '')
    if not path.is_absolute() or settings.network != 'testnet11':
        raise ValueError('COLLECTION_RECOVERY_NOT_CONFIGURED')
    for parent in path.parents:
        info = parent.lstat()
        if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('COLLECTION_RECOVERY_NOT_PROTECTED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or info.st_size > 16384):
            raise ValueError('COLLECTION_RECOVERY_NOT_PROTECTED')
        value = json.loads(stream.read(16385))
    return validate_record_receipt(value, settings.deployment_generation_id,
                                   settings.collection_generation_recovery_source_hash, now=now)


def require_record_recovery(settings):
    try:
        return read_record_receipt(settings)
    except (OSError, ValueError, TypeError, KeyError):
        raise HTTPException(503, detail={
            'code': 'COLLECTION_RECOVERY_PENDING',
            'message': 'Your saved property is retained. New changes will resume when this workspace’s backup check is current.',
        }, headers={'Retry-After': '30'}) from None


def require_preparation_step(request, settings):
    if not settings.deployment_generation_id or request.method in ('GET', 'HEAD', 'OPTIONS'):
        return
    require_record_recovery(settings)
    path = request.url.path
    if '/assets/' in path or path.endswith(('/assets', '/seal', '/amendments')):
        from .collection_generation_media_recovery import require_media_recovery
        require_media_recovery(settings, require_current_inventory=path.endswith(('/seal', '/amendments')))
