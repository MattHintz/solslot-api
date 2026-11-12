"""Bounded encrypted recovery on the existing Azure VM; no delete operations."""
import base64
import fcntl
import hashlib
import hmac
import json
import os
import resource
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from collection_snapshot import canonical,protected_read,MAX_WIRE,MAX_OBJECT,MAX_SOURCE,TABLES,HEX
from recovery_health import AE,PRINCIPAL,validate_receipt
from restore_collection import verify_isolated_restore

ROOT=Path('/opt/solslot/collection-recovery-AE181')
RUN=Path('/run/solslot-collection-recovery-ae181')
VAULT='https://kv-sfcog-sols2-856e6.vault.azure.net/secrets/'
STORAGE='https://stsolslotrec5db856e6.blob.core.windows.net/solslot-collection-recovery-ae165'
POLICY=('https://management.azure.com/subscriptions/5db856e6-9fdd-474d-96a4-241e8cb89320/'
        'resourceGroups/rg-sfc-og-solslot-validator-prod/providers/Microsoft.Storage/storageAccounts/'
        'stsolslotrec5db856e6/blobServices/default/containers/solslot-collection-recovery-ae165/'
        'immutabilityPolicies/default?api-version=2023-05-01')
KEY_REF=VAULT+'solslot-collection-backup-key-ae165/90df81b132264ccfb85df1fcff5acf52'
NODE_REF=VAULT+'solslot-collection-ipfs-node-ae165/84694916ebc64c3aa159cea98d669c0a'
SSH_REF=VAULT+'solslot-collection-ssh-ae181'
TOKEN_FILE=RUN/'managed-identity-tokens.json'
TOKEN_RESOURCES={'https://storage.azure.com/','https://management.azure.com/','https://vault.azure.net/'}
# Azure Key Vault can issue a v2 token addressed to its fixed public-cloud
# application ID. Keep that alias restricted to Key Vault; never accept it for
# Storage or ARM. Identity and tenant checks still apply to every token.
TOKEN_AUDIENCES={resource:{resource.rstrip('/')} for resource in TOKEN_RESOURCES}
TOKEN_AUDIENCES['https://vault.azure.net/'].add('cfa8b339-82a2-471a-a3c9-0fc0be7a4093')


def staged_token(resource):
    if resource not in TOKEN_RESOURCES or TOKEN_FILE.parent.is_symlink():
        raise ValueError('Identity resource differs')
    fd=os.open(TOKEN_FILE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o027 or st.st_size>65536:
            raise ValueError('Identity credential is not protected')
        q=json.loads(f.read(65537))
    if set(q)!= {'schema','actionEnvelopeId','principalId','tenantId','tokens'} or (
            q['schema']!='solslot.managed-identity-tokens.v1' or q['actionEnvelopeId']!=AE
            or q['principalId']!=PRINCIPAL or q['tenantId']!='0c1708db-7f87-4fe9-9a96-eac4795c39bd'
            or set(q['tokens'])!=TOKEN_RESOURCES):
        raise ValueError('Staged identity authority differs')
    token=q['tokens'][resource]
    if not isinstance(token,str) or len(token)>16384:raise ValueError('Identity token bounds differ')
    claims=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'=='))
    if (claims.get('oid')!=PRINCIPAL or claims.get('tid')!=q['tenantId']
            or str(claims.get('aud','')).rstrip('/') not in TOKEN_AUDIENCES[resource]
            or int(claims.get('exp',0))<=time.time()+300):
        raise ValueError('Staged identity token is expired or differs')
    return int(claims['exp']),token


class Azure:
    def __init__(self):
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.tokens={}

    def token(self,resource):
        old=self.tokens.get(resource)
        if old and old[0]>time.time()+300:return old[1]
        if os.geteuid()!=0:
            staged=staged_token(resource);self.tokens[resource]=staged;return staged[1]
        url='http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource='+urllib.parse.quote(resource,safe='')
        with self.opener.open(urllib.request.Request(url,headers={'Metadata':'true'}),timeout=15) as r:
            value=json.loads(r.read(65537))['access_token']
        claims=json.loads(base64.urlsafe_b64decode(value.split('.')[1]+'=='))
        if claims.get('oid')!=PRINCIPAL or claims.get('tid')!='0c1708db-7f87-4fe9-9a96-eac4795c39bd':
            raise ValueError('Managed identity differs')
        self.tokens[resource]=(int(claims['exp']),value)
        return value

    def call(self,url,method='GET',data=None,headers=None,limit=32*1024*1024):
        if url.startswith(VAULT):resource='https://vault.azure.net/'
        elif url.startswith(STORAGE):resource='https://storage.azure.com/'
        elif url==POLICY:resource='https://management.azure.com/'
        else:raise ValueError('Recovery destination differs')
        hs={'Authorization':'Bearer '+self.token(resource),'x-ms-version':'2023-11-03'}
        hs.update(headers or {})
        with self.opener.open(urllib.request.Request(url,method=method,data=data,headers=hs),timeout=60) as r:
            content=r.read(limit+1)
            if len(content)>limit:raise ValueError('Recovery response cap exceeded')
            return content,dict(r.headers)

    def secret(self,ref):
        value,_=self.call(ref+'?api-version=7.4',limit=65536)
        return json.loads(value)

    def policy(self):
        value,_=self.call(POLICY,limit=65536)
        policy=json.loads(value)['properties']
        if policy.get('state')!='Locked' or policy.get('immutabilityPeriodSinceCreationInDays')!=30:
            raise ValueError('Existing locked retention policy differs')
        _,headers=self.call(STORAGE+'?restype=container',method='HEAD',limit=0)
        h={k.lower():v for k,v in headers.items()}
        if h.get('x-ms-blob-public-access') is not None or h.get('x-ms-has-immutability-policy')!='true':
            raise ValueError('Recovery container is not private and immutable')


def encrypted(plain,key,key_ref):
    digest=hashlib.sha256(plain).hexdigest()
    aad=canonical({'entity':'SOLSLOT','actionEnvelopeId':AE,'plaintextSha256':digest,'keyReference':key_ref})
    nonce=os.urandom(12)
    return canonical({'algorithm':'AES-256-GCM','nonceB64':base64.b64encode(nonce).decode(),
                      'aadB64':base64.b64encode(aad).decode(),
                      'ciphertextB64':base64.b64encode(AESGCM(key).encrypt(nonce,plain,aad)).decode()})


def restored(package,key,digest):
    q=json.loads(package)
    if set(q)!= {'algorithm','nonceB64','aadB64','ciphertextB64'} or q['algorithm']!='AES-256-GCM':
        raise ValueError('Encrypted recovery format differs')
    aad=base64.b64decode(q['aadB64'],validate=True)
    if json.loads(aad)!= {'entity':'SOLSLOT','actionEnvelopeId':AE,'plaintextSha256':digest,'keyReference':KEY_REF}:
        raise ValueError('Encrypted recovery context differs')
    nonce=base64.b64decode(q['nonceB64'],validate=True)
    if len(nonce)!=12:raise ValueError('Encrypted nonce differs')
    plain=AESGCM(key).decrypt(nonce,base64.b64decode(q['ciphertextB64'],validate=True),aad)
    if not hmac.compare_digest(hashlib.sha256(plain).hexdigest(),digest):
        raise ValueError('Restored bytes differ')
    return plain


def ensure_blob(azure,plain,key):
    digest=hashlib.sha256(plain).hexdigest()
    name='collections/AE181/'+digest+'.aesgcm.json';url=STORAGE+'/'+name
    try:
        azure.call(url,method='PUT',data=encrypted(plain,key,KEY_REF),
                   headers={'x-ms-blob-type':'BlockBlob','Content-Type':'application/octet-stream','If-None-Match':'*'},limit=0)
    except urllib.error.HTTPError as e:
        # Locked WORM containers return 409 before the create-only precondition
        # for an existing blob. Reuse only this exact conflict, and still GET,
        # decrypt and compare the retained bytes below. Other failures close.
        if e.code!=412 and not (e.code==409 and e.headers.get('x-ms-error-code') in {'BlobAlreadyExists','BlobImmutableDueToPolicy'}):raise
    payload,headers=azure.call(url,limit=32*1024*1024)
    if restored(payload,key,digest)!=plain:raise ValueError('Private isolated restore differs')
    return {'blobName':name,'sha256':digest,'bytes':len(plain),'etag':headers.get('ETag') or headers.get('Etag')}


def ssh_request(private_key,request,limit):
    with tempfile.TemporaryDirectory(prefix='solslot-recovery-',dir=RUN) as folder:
        p=Path(folder)/'identity'
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(private_key)
        args=['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes',
              '-oUserKnownHostsFile='+str(ROOT/'coordinator-known-host'),
              '-oIdentitiesOnly=yes','-oConnectTimeout=10','-oServerAliveInterval=15',
              '-oServerAliveCountMax=2','-i',str(p),'solslot-recovery-ae181@10.77.0.1']
        # Spool only the bounded encrypted-transport response into tmpfs. It is
        # never a persistent local copy of a property file.
        with tempfile.TemporaryFile(dir=folder) as output:
            def bound_output():
                resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
            result=subprocess.run(args,input=canonical(request)+b'\n',stdout=output,
                                  stderr=subprocess.DEVNULL,timeout=150,check=False,
                                  preexec_fn=bound_output)
            if result.returncode or output.tell()>limit:raise ValueError('Restricted recovery transport failed')
            output.seek(0);data=output.read(limit+1)
            if len(data)>limit:raise ValueError('Recovery transport cap exceeded')
        return json.loads(data)


def validate_export(q):
    if not isinstance(q,dict) or set(q)!= {'manifest','payloads'}:raise ValueError('Export contract differs')
    m=q['manifest']
    if (m.get('schema')!='solslot.collection-recovery.v1' or m.get('entity')!='SOLSLOT'
            or m.get('network')!='testnet11' or set(m['tables'])!=set(TABLES)
            or set(m['tableSchemas'])!=set(TABLES)):
        raise ValueError('Export authority differs')
    if not isinstance(m['files'],list) or len(m['files'])>1000:raise ValueError('Export inventory cap differs')
    used=0;digests=set()
    for f in m['files']:
        if not isinstance(f.get('sha256'),str) or not HEX.fullmatch(f['sha256']) or not isinstance(f.get('bytes'),int) or not 0<f['bytes']<=MAX_OBJECT:
            raise ValueError('Export asset commitment differs')
        used+=f['bytes'];digests.add(f['sha256'])
    if used>MAX_SOURCE or not set(q['payloads']).issubset(digests):raise ValueError('Export bounds differ')
    for digest,value in q['payloads'].items():
        data=base64.b64decode(value,validate=True)
        if len(data)>MAX_OBJECT or hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Export bytes differ')
        if any(f['bytes']!=len(data) for f in m['files'] if f['sha256']==digest):raise ValueError('Export length differs')
    return m,used


def run():
    azure=Azure();azure.policy()
    key_record=azure.secret(KEY_REF)
    key=base64.b64decode(json.loads(key_record['value'])['keyB64'],validate=True)
    if len(key)!=32:raise ValueError('Backup key differs')
    identity=json.loads(azure.secret(SSH_REF)['value'])
    if identity.get('purpose')!='collection-recovery-read-only-AE181':raise ValueError('SSH credential scope differs')
    private=identity['privateKey']
    if not isinstance(private,str) or not 100<len(private)<8192 or not private.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
        raise ValueError('SSH credential format differs')
    state_path=ROOT/'state/state.json'
    old=json.loads(protected_read(state_path,512*1024)) if state_path.exists() else {'objects':{},'restoredAt':0}
    if set(old)!= {'objects','restoredAt'} or len(old['objects'])>1000:raise ValueError('Recovery state differs')
    full=time.time()-old['restoredAt']>3000
    export=ssh_request(private,{'op':'snapshot','known':[] if full else list(old['objects'])},MAX_WIRE)
    manifest,used=validate_export(export)
    node=json.loads(azure.secret(NODE_REF)['value'])
    if manifest['ipfsPeerId']!=node['PeerID']:raise ValueError('Recovered IPFS identity differs')
    objects={};restore_payloads={}
    for item in manifest['files']:
        digest=item['sha256']
        if digest in objects:continue
        if digest in export['payloads']:
            plain=base64.b64decode(export['payloads'][digest],validate=True)
            objects[digest]=ensure_blob(azure,plain,key)
            if full:restore_payloads[digest]=plain
        else:
            prior=old['objects'].get(digest)
            if not prior or prior['bytes']!=item['bytes'] or prior['blobName']!='collections/AE181/'+digest+'.aesgcm.json':
                raise ValueError('No verified private recovery object')
            # HEAD confirms every referenced object still exists. Full decrypt
            # occurs at least hourly or whenever the object is first written.
            _,headers=azure.call(STORAGE+'/'+prior['blobName'],method='HEAD',limit=0)
            head={k.lower():v for k,v in headers.items()}
            if not prior.get('etag') or prior['etag']!=head.get('etag'):
                raise ValueError('Immutable recovery object changed')
            objects[digest]=prior
    committed=dict(manifest,recoveryObjects=objects)
    ref=ensure_blob(azure,canonical(committed),key)
    if full:
        # Read the stored manifest independently and reconstruct rows/files from
        # Blob GET results, not the source export still held in memory.
        encoded,_=azure.call(STORAGE+'/'+ref['blobName'])
        recovered=json.loads(restored(encoded,key,ref['sha256']))
        for digest,record in objects.items():
            encoded,_=azure.call(STORAGE+'/'+record['blobName'])
            restore_payloads[digest]=restored(encoded,key,digest)
        verify_isolated_restore(recovered,restore_payloads)
    now=time.time();restored_at=now if full else old['restoredAt']
    receipt={'schema':'solslot.collection-recovery-health.v1','actionEnvelopeId':AE,'entity':'SOLSLOT',
             'network':'testnet11','principalId':PRINCIPAL,'checkedAt':now,'restoredAt':restored_at,
             'healthy':True,'containerPrivate':True,'immutabilityVerified':True,'createOnly':True,
             'restoreMatches':True,'manifestSha256':ref['sha256'],'blobName':ref['blobName'],
             'assetCount':len(manifest['files']),'acceptedBytes':used}
    validate_receipt(receipt)
    result=ssh_request(private,{'op':'receipt','receipt':receipt},8192)
    if result!= {'status':'receipt_saved'}:raise ValueError('Coordinator receipt was not saved')
    temp=state_path.with_name('state-new.json')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(canonical({'objects':objects,'restoredAt':restored_at}));f.flush();os.fsync(f.fileno())
    os.replace(temp,state_path)
    print(canonical(receipt).decode())


def main():
    try:
        fd=os.open(ROOT/'state/worker.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);run()
        return 0
    except Exception:
        # On failure no success receipt is renewed; API authoring closes after
        # ten minutes. Neither exceptions nor server bodies reach logs.
        print('Collection recovery failed closed; property authoring health was not renewed',file=__import__('sys').stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
