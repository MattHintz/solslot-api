"""Reuse the existing private mTLS signer lane for one fixed issuer action."""
import asyncio
from chia_rs import G2Element
from .validator_quorum import _private_validator_client


class PrivateCurrentIssuerClient:
    def __init__(self,settings):
        if (settings.network!='testnet11' or not settings.generation_customer_purchase_worker_enabled
                or settings.zkpassport_validator_urls!=['https://10.77.0.10:9544','https://10.77.0.11:9544','https://10.77.0.12:9544']):
            raise ValueError('CURRENT_ISSUER_FIXED_PRIVATE_TOPOLOGY_REQUIRED')
        self.settings=settings

    async def __call__(self,request):
        async with asyncio.timeout(42):
            async with _private_validator_client(self.settings)as client:
                response=await client.post('https://10.77.0.12:9544/v1/generation/purchase/issuer/sign',json=request,timeout=40)
                response.raise_for_status();value=response.json()
        if (not isinstance(value,dict) or set(value)!={'generationId','policyHash','claimHash','signature'}
                or any(value.get(k)!=request[k]for k in ('generationId','policyHash','claimHash'))
                or not isinstance(value.get('signature'),str) or len(value['signature'])!=194
                or not value['signature'].startswith('0x')):
            raise ValueError('CURRENT_ISSUER_PRIVATE_REPLY_CHANGED')
        # The worker independently verifies this against its native message.
        return G2Element.from_bytes(bytes.fromhex(value['signature'][2:]))

    async def status(self,policy,*,now):
        async with asyncio.timeout(8):
            async with _private_validator_client(self.settings)as client:
                response=await client.get('https://10.77.0.12:9544/v1/generation/purchase/issuer/status',timeout=6)
                response.raise_for_status();value=response.json()
        from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
        common={'generationId','policyHash','checkedAt','canSign'}
        collection=isinstance(policy,TestnetCollectionIssuerPolicy)
        expected=common|({'cutoverHash'} if collection else {'expiresAt','remainingPurchases'})
        if (not isinstance(value,dict) or set(value)!=expected
                or value.get('generationId')!='0x'+policy.generation.hex()
                or value.get('policyHash')!=policy.commitment or type(value.get('checkedAt'))is not int
                or abs(now-value['checkedAt'])>10 or type(value.get('canSign'))is not bool):
            raise ValueError('CURRENT_ISSUER_PRIVATE_HEALTH_CHANGED')
        if collection:
            pin=getattr(self.settings,'generation_customer_purchase_cutover_hash',None)
            if not pin or value['cutoverHash']!=pin:raise ValueError('CURRENT_ISSUER_PRIVATE_HEALTH_CHANGED')
        elif (value['expiresAt']!=policy.expires_at or type(value['remainingPurchases'])is not int
                or not 0<=value['remainingPurchases']<=policy.maximum_purchases):
            raise ValueError('CURRENT_ISSUER_PRIVATE_HEALTH_CHANGED')
        return value
