"""Version-pinned Key Vault signing; key material never enters the API.

Only the VM IMDS user-assigned identity flow is supported. All coordinates
come from authenticated activation evidence and matching host settings.
"""
from __future__ import annotations
import base64
import re
from typing import Any, Mapping
import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys.constants import SECPK1_N
from eth_keys.exceptions import BadSignature
from web3 import Web3
from solslot_puzzles.enrollment_activation import activation_context,KEY_REF_PATTERN,IDENTITY_PATTERN
from solslot_puzzles.enrollment_permit import EnrollmentPermit,permit_signing_typed_data


class PermitIssuerUnavailable(RuntimeError):
    """Issuer could not complete; the original permit must remain reserved."""


def verify_permit_signature(wire: Mapping[str,Any], activation: Mapping[str,Any], signature: str) -> str:
    if not isinstance(signature,str) or re.fullmatch(r'0x[0-9a-f]{130}',signature) is None:
        raise ValueError('permit issuer signature must be canonical 65-byte hex')
    raw=bytes.fromhex(signature[2:]);r=int.from_bytes(raw[:32],'big');s=int.from_bytes(raw[32:64],'big')
    if not 0<r<SECPK1_N or not 0<s<=SECPK1_N//2 or raw[64] not in (27,28):
        raise ValueError('permit issuer signature must use canonical low-s ECDSA')
    message=encode_typed_data(full_message=permit_signing_typed_data(EnrollmentPermit.from_wire(wire),activation_context(activation)))
    try:
        recovered=Account.recover_message(message,signature=raw).lower()
    except (BadSignature,ValueError):
        raise ValueError('permit issuer signature cannot be recovered') from None
    if recovered!=activation['issuer']:
        raise ValueError('permit signature does not belong to the reviewed issuer')
    return signature


def _json(client: httpx.Client, method: str, url: str, **kwargs: Any) -> dict[str,Any]:
    # Do not retain provider bodies, bearer tokens or exception request objects.
    with client.stream(method,url,**kwargs) as response:
        if response.status_code!=200:
            raise PermitIssuerUnavailable('Permit issuer service is unavailable.')
        content=bytearray()
        for chunk in response.iter_bytes():
            content.extend(chunk)
            if len(content)>16384:
                raise PermitIssuerUnavailable('Permit issuer response exceeds the limit.')
        import json
        data=json.loads(content)
        if not isinstance(data,dict):raise PermitIssuerUnavailable('Invalid issuer response.')
        return data


def sign_permit_with_key_vault(settings: Any, activation: Mapping[str,Any], wire: Mapping[str,Any]) -> str:
    key=activation['issuerKeyRef'];identity=activation['issuerIdentityClientId']
    if (not isinstance(key,str) or re.fullmatch(KEY_REF_PATTERN,key) is None
            or not isinstance(identity,str) or re.fullmatch(IDENTITY_PATTERN,identity) is None
            or key!=settings.enrollment_permit_issuer_key_ref
            or identity!=settings.enrollment_permit_identity_client_id
            or activation['releaseIdentity']!=settings.enrollment_permit_release_identity
            or activation['environment']!=settings.runtime_environment+'-alpha'
            or settings.network!='testnet11' or settings.zkpassport_evm_chain_id!=84532
            or not settings.alpha_writes_enabled):
        raise PermitIssuerUnavailable('Permit issuer is not configured for this approved deployment.')
    permit=EnrollmentPermit.from_wire(wire)
    message=encode_typed_data(full_message=permit_signing_typed_data(permit,activation_context(activation)))
    digest=bytes(Web3.keccak(b'\x19'+message.version+message.header+message.body))
    try:
        with httpx.Client(timeout=httpx.Timeout(10,connect=2),follow_redirects=False,trust_env=False) as client:
            token=_json(client,'GET','http://169.254.169.254/metadata/identity/oauth2/token',
                params={'api-version':'2018-02-01','resource':'https://vault.azure.net','client_id':identity},
                headers={'Metadata':'true'})
            access=token.get('access_token')
            if (token.get('token_type')!='Bearer' or token.get('resource')!='https://vault.azure.net'
                    or not isinstance(access,str) or not 1<=len(access)<=12000
                    or re.fullmatch(r'[A-Za-z0-9._~-]+',access) is None):
                raise PermitIssuerUnavailable('Invalid issuer identity response.')
            result=_json(client,'POST',key+'/sign',params={'api-version':'2025-07-01'},
                headers={'Authorization':'Bearer '+access},
                json={'alg':'ES256K','value':base64.urlsafe_b64encode(digest).decode().rstrip('=')})
            encoded=result.get('value')
            if result.get('kid')!=key or not isinstance(encoded,str) or re.fullmatch(r'[A-Za-z0-9_-]{86}',encoded) is None:
                raise PermitIssuerUnavailable('Issuer response does not match the reviewed key version.')
            raw=base64.urlsafe_b64decode(encoded+'==')
            r=int.from_bytes(raw[:32],'big');s=int.from_bytes(raw[32:],'big')
            if not 0<r<SECPK1_N or not 0<s<SECPK1_N:raise ValueError('Invalid issuer scalars')
            s=min(s,SECPK1_N-s)
            for v in (27,28):
                signature='0x'+(r.to_bytes(32,'big')+s.to_bytes(32,'big')+bytes([v])).hex()
                try:return verify_permit_signature(wire,activation,signature)
                except ValueError:continue
            raise PermitIssuerUnavailable('Issuer signature does not match the reviewed authorization.')
    except (httpx.HTTPError,ValueError,TypeError,KeyError,OverflowError):
        raise PermitIssuerUnavailable('Permit issuer could not complete; retry the saved reservation.') from None
