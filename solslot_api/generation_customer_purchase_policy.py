"""Read one frozen public Testnet issuer policy, never a private credential."""
from hashlib import sha256
import json,os,stat
from pathlib import Path
from chia_rs.sized_bytes import bytes32
from .generation_customer_issuer import TestnetIssuerPolicy


def read_current_issuer_policy(path,expected_file_hash):
    p=Path(path)
    info=p.lstat()
    if p.is_symlink()or not stat.S_ISREG(info.st_mode)or not 1<=info.st_size<=65536:
        raise ValueError('CURRENT_PURCHASE_FIXED_POLICY_FILE_REQUIRED')
    raw=p.read_bytes()
    if '0x'+sha256(raw).hexdigest()!=expected_file_hash:raise ValueError('CURRENT_PURCHASE_POLICY_FILE_CHANGED')
    q=json.loads(raw)
    keys={'schema','network','generationId','collectionHash','editionHash','metadataRoot','proceedsPuzzleHash',
        'feePuzzleHash','issuerPublicKey','deedLauncherIds','buyerVaultLauncherId','maximumGrossMojos',
        'maximumPurchases','issuedAt','expiresAt','technologyFeeBps','companyShareOfFeeBps','sgtShareOfFeeBps',
        'scope','masterKeyExportAuthorized'}
    nominal=q.get('schema')=='solslot.testnet-issuer-forwarding-policy.v2'
    rate=None
    if nominal:
        keys=keys|{'pricing'}
        p=q.get('pricing')
        if (not isinstance(p,dict)or set(p)!={'mode','usdMinorPerTxch'}or p['mode']!='FIXED_TESTNET_CONVERSION'
                or not isinstance(p['usdMinorPerTxch'],str)or not p['usdMinorPerTxch'].isdigit()
                or str(int(p['usdMinorPerTxch']))!=p['usdMinorPerTxch']):
            raise ValueError('CURRENT_PURCHASE_FIXED_TEST_CONVERSION_INVALID')
        rate=int(p['usdMinorPerTxch'])
    if (set(q)!=keys or q['schema']not in ('solslot.testnet-issuer-forwarding-policy.v1','solslot.testnet-issuer-forwarding-policy.v2') or q['network']!='testnet11'
            or q['scope']!='NEW_EPHEMERAL_PRIMARY_PROCEEDS_ONLY' or q['masterKeyExportAuthorized']is not False
            or [q[k]for k in ('technologyFeeBps','companyShareOfFeeBps','sgtShareOfFeeBps')]!=[100,7000,3000]
            or not isinstance(q['maximumGrossMojos'],str)or not q['maximumGrossMojos'].isdigit()
            or str(int(q['maximumGrossMojos']))!=q['maximumGrossMojos']
            or not isinstance(q['deedLauncherIds'],list)or q['deedLauncherIds']!=sorted(set(q['deedLauncherIds']))):
        raise ValueError('CURRENT_PURCHASE_FIXED_POLICY_FIELDS_CHANGED')
    def b(name):return bytes32.from_hexstr(q[name])
    policy=TestnetIssuerPolicy(b('generationId'),b('collectionHash'),b('editionHash'),b('metadataRoot'),
        b('proceedsPuzzleHash'),b('feePuzzleHash'),bytes.fromhex(q['issuerPublicKey'].removeprefix('0x')),
        frozenset(bytes32.from_hexstr(x)for x in q['deedLauncherIds']),b('buyerVaultLauncherId'),
        int(q['maximumGrossMojos']),q['maximumPurchases'],q['issuedAt'],q['expiresAt'],rate).validate()
    if policy.public()!=q:raise ValueError('CURRENT_PURCHASE_CANONICAL_POLICY_REQUIRED')
    return policy


def selected_purchase_policy(settings):
    if not settings.generation_customer_purchase_enabled or settings.network!='testnet11':
        raise ValueError('CURRENT_PURCHASE_POLICY_DISABLED')
    p=read_current_issuer_policy(settings.generation_customer_purchase_policy_path,settings.generation_customer_purchase_policy_hash)
    if '0x'+p.generation.hex()!=settings.deployment_generation_id:raise ValueError('CURRENT_PURCHASE_POLICY_GENERATION_CHANGED')
    return p
