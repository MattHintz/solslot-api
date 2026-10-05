"""Run in the existing authenticated Azure CLI only after exact AE181 approval."""
import json
import subprocess
import sys
from pathlib import Path

AE='AE-SOLSLOT-COLLECTION-AUTHORING-20261005-181'
def az(args):
    result=subprocess.run(['az',*args,'--only-show-errors','--output','json'],check=True,capture_output=True,text=True)
    return json.loads(result.stdout) if result.stdout.strip() else None

def main():
    if len(sys.argv)!=5 or sys.argv[1:3]!=['--approved',AE]:raise ValueError('Exact approved AE181 operation required')
    plan=json.loads(Path(sys.argv[3]).read_text());phase=sys.argv[4]
    account=az(['account','show'])
    if account['id']!=plan['azure']['subscription'] or account['tenantId']!=plan['azure']['tenant']:raise ValueError('Azure account differs')
    grants=plan['azure']['newAssignments']
    if phase=='grant':
        # Inspect the existing custom setter's exact authority before assigning it.
        role=az(['role','definition','list','--name',plan['azure']['setterRole']])[0]
        perms=role['permissions']
        if len(perms)!=1 or perms[0]['dataActions']!=['Microsoft.KeyVault/vaults/secrets/setSecret/action'] or perms[0]['actions'] or perms[0]['notActions'] or perms[0]['notDataActions']:
            raise ValueError('Temporary setter role differs')
        for grant in grants:
            existing=az(['role','assignment','list','--scope',grant['scope']])
            by_id=[r for r in existing if r['name']==grant['id']]
            if by_id:
                if len(by_id)!=1 or by_id[0]['principalId']!=plan['azure']['principal'] or by_id[0]['roleDefinitionId'].rsplit('/',1)[-1]!=grant['role']:raise ValueError('Assignment collision')
                continue
            az(['role','assignment','create','--name',grant['id'],'--assignee-object-id',plan['azure']['principal'],
                '--assignee-principal-type','ServicePrincipal','--role',grant['role'],'--scope',grant['scope']])
    elif phase in ('revoke-setter','rollback'):
        selected=[g for g in grants if phase=='rollback' or g['temporary']]
        for grant in selected:
            target=grant['scope']+'/providers/Microsoft.Authorization/roleAssignments/'+grant['id']
            az(['role','assignment','delete','--ids',target])
            if any(r['name']==grant['id'] for r in az(['role','assignment','list','--scope',grant['scope']])):raise ValueError('Revocation did not complete')
    else:raise ValueError('Unsupported permission phase')
    print(json.dumps({'actionEnvelopeId':AE,'phase':phase,'status':'completed','secretValuesRecorded':False}))

if __name__=='__main__':
    try:main()
    except Exception:
        print('AE181 Azure permission operation stopped; no credentials or provider bodies logged',file=sys.stderr)
        raise SystemExit(1)
