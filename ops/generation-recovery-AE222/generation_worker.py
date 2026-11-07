"""Recurring Azure worker. Uses existing AE181 scoped identities, no IAM changes.

Installation must authorize the additional fixed generation-only SSH principal.
The old collection user/export and its forced command remain unchanged.
"""
import base64
from hashlib import sha256
import json
import os
import pwd
import stat
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from generation_snapshot import canonical, validate_export, MAX_TOTAL
from generation_replication import replicate, KEY_REFERENCE, AE
from generation_export import load_config

OLD=Path('/opt/solslot/collection-recovery-AE181')
ROOT=Path('/opt/solslot/generation-recovery-AE222')
RUN=Path('/run/solslot-generation-recovery-ae222')
SSH_REFERENCE='https://kv-sfcog-sols2-856e6.vault.azure.net/secrets/solslot-collection-ssh-ae181/a919a8bb3dc44cbc95cbe99bf7591287'
PINS={'replicate_collection.py':'c073da805df86a874000e08d623edb716df898446de6d48ac1ec95e71fc7b4b7',
      'collection_snapshot.py':'59f9346fde1772581c156c4171eb142750313a56945dd160a538ccaec7ffdbb6',
      'recovery_health.py':'aabae2a2b41171c74939a40d719023dd3faace9b58f9ebed4ac2e1de2d939d47'}


TOKEN_FILE=RUN/'managed-identity-tokens.json'
RESOURCES={'https://storage.azure.com/','https://management.azure.com/','https://vault.azure.net/'}


def validate_tokens(record,config,*,now=None):
    now=time.time() if now is None else now
    if not isinstance(record,dict) or set(record)!= {'schema','actionEnvelopeId','generationId','sourceHash','tokens'} or (
        record['schema']!='solslot.generation-identity-tokens.v1' or record['actionEnvelopeId']!=AE
        or record['generationId']!=config['generationId'] or record['sourceHash']!=config['sourceHash']
        or not isinstance(record['tokens'],dict) or set(record['tokens'])!=RESOURCES):
        raise ValueError('GENERATION_IDENTITY_BINDING_DIFFERS')
    result={}
    for resource,value in record['tokens'].items():
        if not isinstance(value,str) or len(value)>16384:raise ValueError('GENERATION_IDENTITY_TOKEN_TOO_LARGE')
        claims=json.loads(base64.urlsafe_b64decode(value.split('.')[1]+'=='))
        audiences={resource.rstrip('/')}
        if resource=='https://vault.azure.net/':audiences.add('cfa8b339-82a2-471a-a3c9-0fc0be7a4093')
        if (claims.get('oid')!='6b6d66ae-e403-406e-8e2c-0f0b2709f1f4'
            or claims.get('tid')!='0c1708db-7f87-4fe9-9a96-eac4795c39bd'
            or str(claims.get('aud','')).rstrip('/') not in audiences
            or type(claims.get('exp')) is not int or claims['exp']<=now+300):
            raise ValueError('GENERATION_MANAGED_IDENTITY_DIFFERS')
        result[resource]=(claims['exp'],value)
    return result


def read_staged_tokens(config,path=TOKEN_FILE):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o027 or info.st_size>65536:
            raise ValueError('GENERATION_IDENTITY_FILE_NOT_PROTECTED')
        record=json.loads(stream.read(65537))
    return validate_tokens(record,config)


def existing_azure(config=None,*,token_file=TOKEN_FILE,root_stage=False):
    for name,digest in PINS.items():
        p=OLD/name
        if p.is_symlink() or sha256(p.read_bytes()).hexdigest()!=digest:
            raise ValueError('EXISTING_RECOVERY_TRANSPORT_CHANGED')
    sys.path.insert(0,str(OLD))
    from replicate_collection import Azure
    if root_stage:
        if os.geteuid()!=0:raise ValueError('GENERATION_IDENTITY_STAGING_REQUIRES_ROOT')
        return Azure()
    if config is None:config=load_config()
    class GenerationAzure(Azure):
        def token(self,resource):
            if resource not in RESOURCES:raise ValueError('GENERATION_IDENTITY_RESOURCE_DIFFERS')
            # Preserve the host's root-only IMDS boundary. The dedicated worker
            # only reads root-authored short-lived, generation-bound tmpfs tokens.
            tokens=read_staged_tokens(config,token_file)
            return tokens[resource][1]
    return GenerationAzure()


def stage_tokens(config=None,*,path=TOKEN_FILE,user='solslot-gen-recovery-ae222'):
    if os.geteuid()!=0:raise ValueError('GENERATION_IDENTITY_STAGING_REQUIRES_ROOT')
    if config is None:config=load_config()
    identity=existing_azure(root_stage=True)
    record={'schema':'solslot.generation-identity-tokens.v1','actionEnvelopeId':AE,
        'generationId':config['generationId'],'sourceHash':config['sourceHash'],
        'tokens':{resource:identity.token(resource) for resource in RESOURCES}}
    validate_tokens(record,config)
    account=pwd.getpwnam(user);target=Path(path);incoming=target.with_name('identity.incoming-ae222')
    fd=os.open(incoming,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    try:
        os.fchown(fd,0,account.pw_gid)
        os.fchmod(fd,0o640)
        with os.fdopen(fd,'wb') as stream:
            stream.write(canonical(record));stream.flush();os.fsync(stream.fileno())
        os.replace(incoming,target)
    finally:
        if incoming.exists():incoming.unlink()


def ssh_request(private,request,*,limit):
    with tempfile.TemporaryDirectory(prefix='generation-transport-',dir=RUN) as folder:
        key=Path(folder)/'identity'
        fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(private)
        args=['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oIdentitiesOnly=yes',
              '-oUserKnownHostsFile='+str(ROOT/'coordinator-known-host'),'-oConnectTimeout=10',
              '-oServerAliveInterval=15','-oServerAliveCountMax=2','-oClearAllForwardings=yes',
              '-oForwardAgent=no','-oRequestTTY=no','-i',str(key),
              'solslot-gen-recovery-ae222@10.77.0.1']
        with tempfile.TemporaryFile(dir=folder) as output:
            def bound():resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
            result=subprocess.run(args,input=canonical(request)+b'\n',stdout=output,
                stderr=subprocess.DEVNULL,check=False,timeout=90,preexec_fn=bound)
            if result.returncode or output.tell()>limit:raise ValueError('GENERATION_RECOVERY_TRANSPORT_FAILED')
            output.seek(0);raw=output.read(limit+1)
            if len(raw)>limit:raise ValueError('GENERATION_RECOVERY_TRANSPORT_TOO_LARGE')
        return json.loads(raw)


def run():
    config=load_config();azure=existing_azure(config);azure.policy()
    credential=json.loads(azure.secret(SSH_REFERENCE)['value'])
    if credential.get('purpose')!='collection-recovery-read-only-AE181':
        raise ValueError('EXISTING_RECOVERY_CREDENTIAL_DIFFERS')
    private=credential.get('privateKey')
    if not isinstance(private,str) or not 100<len(private)<8192 or not private.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
        raise ValueError('EXISTING_RECOVERY_CREDENTIAL_INVALID')
    key=base64.b64decode(json.loads(azure.secret(KEY_REFERENCE)['value'])['keyB64'],validate=True)
    if len(key)!=32:raise ValueError('EXISTING_BACKUP_KEY_INVALID')
    media_receipt=None
    if config.get('mediaRoot'):
        from generation_media import replicate as replicate_media, validate as validate_media
        package=ssh_request(private,{'op':'media-snapshot','generationId':config['generationId']},limit=MAX_TOTAL*2+1024**2)
        manifest,_=validate_media(package,config['generationId'])
        node_ref='https://kv-sfcog-sols2-856e6.vault.azure.net/secrets/solslot-collection-ipfs-node-ae165/84694916ebc64c3aa159cea98d669c0a'
        node=json.loads(azure.secret(node_ref)['value'])
        if manifest['ipfsPeerId']!=node['PeerID']:raise ValueError('GENERATION_MEDIA_IPFS_ID_DIFFERS')
        receipt,media_receipt=replicate_media(package,azure,key,config['generationId'],config['sourceHash'],parent=RUN,clock=time.time)
    else:
        package=ssh_request(private,{'op':'snapshot','generationId':config['generationId']},limit=MAX_TOTAL*2+1024**2)
        validate_export(package,config['generationId'])
        receipt=replicate(package,azure,key,config['generationId'],config['sourceHash'],parent=RUN)
    answer=ssh_request(private,{'op':'receipt','generationId':config['generationId'],'receipt':receipt},limit=16384)
    if answer!={'accepted':True,'generationId':config['generationId']}:raise ValueError('GENERATION_RECOVERY_RECEIPT_NOT_ACCEPTED')
    if media_receipt is not None:
        answer=ssh_request(private,{'op':'media-receipt','generationId':config['generationId'],'receipt':media_receipt},limit=16384)
        if answer!={'accepted':True,'generationId':config['generationId'],'media':True}:raise ValueError('GENERATION_MEDIA_RECEIPT_NOT_ACCEPTED')
    print(json.dumps({'actionEnvelopeId':AE,'generationId':config['generationId'],
        'manifestSha256':receipt['manifest']['sha256'],'databaseCount':receipt['databaseCount'],
        'restoredBytes':receipt['restoredBytes'],'restoreMatches':True,'checkedAt':receipt['checkedAt']}))


if __name__=='__main__':
    try:run()
    except Exception:
        print('Generation recovery failed; the previous receipt will expire. No secret values are emitted.',file=sys.stderr)
        raise SystemExit(1)
