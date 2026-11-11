"""Emit synthetic browser vectors from the API's actual credential encoding."""
import json
from solslot_api.config import Settings
from solslot_api.credential_auth import credential_typed_data, credential_bls_message, credential_payload_hash, vault_session_payload
from solslot_api.credential_ledger import OwnerChallenge

generation = '0x'+'ab'*32
settings = Settings(runtime_environment='test', deployment_generation_id=generation)
vault, nonce, now = '0x'+'11'*32, '0x'+'34'*32, 2000000000
vectors = []
for auth, action in [('evm','session_login'), ('chia_bls','session_login'), ('chia_bls','relay')]:
    payload = vault_session_payload(settings) if action == 'session_login' else {'data':'0xdeadbeef'}
    c = OwnerChallenge('synthetic-generation-challenge-00001', vault, action,
                       credential_payload_hash(action, vault, payload), nonce, auth, now+60)
    vectors.append(dict(authType=auth,payload=payload,challenge=dict(challengeId=c.challenge_id,
        vaultLauncherId=vault,action=action,payloadHash=c.payload_hash,nonce=nonce,authType=auth,
        expiresAt=c.expires_at,typedData=credential_typed_data(settings,c) if auth=='evm' else None,
        messageHex='0x'+credential_bls_message(settings,c).hex() if auth=='chia_bls' else None)))
print(json.dumps(dict(purpose='Synthetic API-to-browser deployment generation vectors; no keys or network',
                     generationId=generation,nowSeconds=now,vectors=vectors),indent=2))
