"""Public chain status for every SGT holder; cached reads have no side effects."""
import time
import sqlite3
from fastapi import APIRouter, Depends, Request
from .config import Settings, get_settings

router=APIRouter(tags=['generation-governance'])


@router.get('/committee/generation/status')
def generation_status(request:Request,settings:Settings=Depends(get_settings)):
    index=getattr(request.app.state,'generation_index',None)
    if index is None:
        return {'generationId':settings.deployment_generation_id,'network':settings.network,
            'status':'NOT_READY','lastCheckedAt':None,'lastAttemptAt':None,
            'errorCode':'GENERATION_INDEX_NOT_READY','snapshot':None,'pollAfterSeconds':30}
    try:return index.store.status(int(time.time()),verified_in_process=index.verified)
    except (OSError,ValueError,sqlite3.Error):
        return {'generationId':settings.deployment_generation_id,'network':settings.network,
            'status':'ERROR','lastCheckedAt':None,'lastAttemptAt':None,
            'errorCode':'GENERATION_INDEX_STORE_UNAVAILABLE','snapshot':None,'pollAfterSeconds':5}
