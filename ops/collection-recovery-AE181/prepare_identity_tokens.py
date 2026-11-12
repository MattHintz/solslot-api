"""Root-only fixed IMDS startup step; tokens remain in private runtime tmpfs."""
import json
import os
import pwd
from replicate_collection import Azure,RUN,TOKEN_FILE,TOKEN_RESOURCES,canonical,AE,PRINCIPAL,staged_token


def main():
    if os.geteuid()!=0 or RUN.is_symlink():raise ValueError('Fixed root identity startup required')
    group=pwd.getpwnam('solslot-recovery-ae181').pw_gid
    azure=Azure()
    q={'schema':'solslot.managed-identity-tokens.v1','actionEnvelopeId':AE,'principalId':PRINCIPAL,
       'tenantId':'0c1708db-7f87-4fe9-9a96-eac4795c39bd',
       'tokens':{resource:azure.token(resource) for resource in sorted(TOKEN_RESOURCES)}}
    data=canonical(q)
    if len(data)>65536:raise ValueError('Identity staging cap exceeded')
    temp=RUN/'managed-identity-tokens.incoming'
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
    with os.fdopen(fd,'wb') as f:
        os.fchown(f.fileno(),0,group);os.fchmod(f.fileno(),0o640)
        f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(temp,TOKEN_FILE)
    for resource in TOKEN_RESOURCES:staged_token(resource)


if __name__=='__main__':
    try:main()
    except Exception:
        print('Recovery identity startup failed closed; credential values were not logged',file=__import__('sys').stderr)
        raise SystemExit(1)
