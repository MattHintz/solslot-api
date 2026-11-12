"""Read protected actual media restore evidence; never substitute record health."""
import json
import os
from pathlib import Path
import stat
import sqlite3
import time
from hashlib import sha256
from fastapi import HTTPException
from .collection_media_recovery_contract import accepted_assets,canonical,validate_receipt


def read_media_receipt(settings, *, now=None):
    path=Path(settings.collection_generation_recovery_path or '')
    if not path.is_absolute() or settings.network!='testnet11':
        raise ValueError('MEDIA_RECOVERY_NOT_CONFIGURED')
    path=path.with_name('media-latest.json')
    for parent in path.parents:
        info=parent.lstat()
        if parent.is_symlink() or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('MEDIA_RECOVERY_NOT_PROTECTED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>16384:
            raise ValueError('MEDIA_RECOVERY_NOT_PROTECTED')
        receipt=json.loads(stream.read(16385))
    return validate_receipt(receipt,settings.deployment_generation_id,settings.collection_generation_recovery_source_hash,
        now=time.time() if now is None else now)


def require_media_recovery(settings, *, require_current_inventory=False):
    try:
        receipt=read_media_receipt(settings)
        if require_current_inventory:
            from .collection_store import get_collection_store
            store=get_collection_store(settings)
            with store._lock:
                raw=store._conn.serialize()
            inventory=accepted_assets(raw,settings.deployment_generation_id)
            if sha256(canonical(inventory)).hexdigest()!=receipt['inventorySha256']:
                raise ValueError('MEDIA_RECOVERY_NEW_ASSETS_PENDING')
        return receipt
    except (OSError,ValueError,TypeError,KeyError,sqlite3.Error):
        raise HTTPException(503,detail={'code':'COLLECTION_MEDIA_RECOVERY_PENDING',
            'message':'Your property is saved. Media backup verification is finishing; uploads and final review resume automatically when it is current.'},
            headers={'Retry-After':'30'}) from None
