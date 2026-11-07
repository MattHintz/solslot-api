"""Current Testnet quote-price status and explicit bounded refresh requests.

Unavailable until a separately configured demand runtime is installed. Reads
never schedule collection. This route does not create quotes or transactions.
"""
from typing import Annotated
import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from .config import Settings, get_settings
from .generation_customer_routes import CurrentGeneration, Identity, _origin
from .generation_customer_identity_routes import owner
from .generation_price_demand import PriceDemandRuntime

router=APIRouter(prefix='/customer/pricing',tags=['current-customer-pricing'])
Configured=Annotated[Settings,Depends(get_settings)]


def runtime(request,settings):
    value=getattr(request.app.state,'generation_price_demand',None)
    if (settings.network!='testnet11' or not isinstance(value,PriceDemandRuntime)
            or value.enabled is not True or value.store.generation_id!=settings.deployment_generation_id):
        raise HTTPException(503,detail={'code':'CURRENT_PRICE_UNAVAILABLE',
            'message':'Testnet pricing is temporarily unavailable. Please try again later.'})
    return value


def unavailable(exc):
    # Do not return provider, storage, credential or socket exception details.
    return HTTPException(503,detail={'code':'CURRENT_PRICE_UNAVAILABLE',
        'message':'Testnet pricing is temporarily unavailable. Please try again later.'})


def require_owner(request,settings,launcher):
    try:return owner(request,settings,launcher)
    except HTTPException:raise
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise unavailable(exc) from exc


def fixed_status(request,settings):
    from .generation_customer_purchase_execution import CurrentNativePurchaseExecution
    from .generation_customer_test_conversion import status
    value=getattr(request.app.state,'generation_customer_purchase',None)
    if (settings.network=='testnet11' and isinstance(value,CurrentNativePurchaseExecution)
            and value.settings is settings and value.policy.test_usd_minor_per_txch is not None):
        return status(value.policy,now=int(value.clock()))
    return None


@router.get('/{launcher}')
async def status(launcher:Identity,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    require_owner(request,settings,launcher)
    fixed=fixed_status(request,settings)
    if fixed is not None:return fixed
    service=runtime(request,settings)
    try:return await service.status()
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise unavailable(exc) from exc


@router.post('/{launcher}/refresh')
async def refresh(launcher:Identity,body:CurrentGeneration,request:Request,response:Response,settings:Configured):
    response.headers['Cache-Control']='no-store'
    _origin(request,settings)
    if body.generation_id!=settings.deployment_generation_id:
        raise HTTPException(409,detail={'code':'CURRENT_PRICE_GENERATION_CHANGED'})
    require_owner(request,settings,launcher)
    fixed=fixed_status(request,settings)
    if fixed is not None:return fixed
    service=runtime(request,settings)
    try:return await service.request()
    except (ValueError,OSError,TimeoutError,RuntimeError,sqlite3.Error) as exc:raise unavailable(exc) from exc
