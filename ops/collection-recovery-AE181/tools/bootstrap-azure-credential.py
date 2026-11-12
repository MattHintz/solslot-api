"""Approved AE181 only. Generate/reuse one scoped credential directly in Key Vault."""
import json
import sys
import urllib.error
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_ssh_private_key
from replicate_collection import Azure, SSH_REF
from recovery_health import AE

def main():
    if sys.argv[1:] != ['--approved', AE]:
        raise ValueError('Exact AE181 approval argument required')
    azure=Azure()
    try:
        existing=azure.secret(SSH_REF)
    except urllib.error.HTTPError as exc:
        if exc.code != 404: raise
        key=Ed25519PrivateKey.generate()
        private=key.private_bytes(Encoding.PEM,PrivateFormat.OpenSSH,NoEncryption()).decode()
        value={'purpose':'collection-recovery-read-only-AE181','privateKey':private}
        body=json.dumps({'value':json.dumps(value),'attributes':{'enabled':True},
                         'tags':{'entity':'SOLSLOT','actionEnvelopeId':AE,'purpose':value['purpose']}}).encode()
        azure.call(SSH_REF+'?api-version=7.4',method='PUT',data=body,
                   headers={'Content-Type':'application/json'},limit=65536)
        existing=azure.secret(SSH_REF)
    value=json.loads(existing['value'])
    if value.get('purpose')!='collection-recovery-read-only-AE181':raise ValueError('Existing secret belongs to another purpose')
    key=load_ssh_private_key(value['privateKey'].encode(),password=None)
    if not isinstance(key,Ed25519PrivateKey):raise ValueError('Credential type differs')
    print(json.dumps({'actionEnvelopeId':AE,'secretReference':existing['id'],
                      'publicKey':key.public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH).decode(),
                      'secretValueRecorded':False}))

if __name__=='__main__':
    try:main()
    except Exception:
        print('AE181 credential bootstrap stopped; no secret values logged',file=sys.stderr)
        raise SystemExit(1)
