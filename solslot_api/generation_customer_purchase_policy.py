"""Read one frozen public Testnet issuer policy, never a private credential."""
from hashlib import sha256
import json,os,stat
from pathlib import Path
from chia_rs.sized_bytes import bytes32
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy, read_collection_issuer_policy
from .generation_customer_purchase_cutover import read_checkout_cutover


def validate_purchase_policy_renewal(prior,current,*,now=None):
    """Time-only lineage; an explicit clock additionally requires live authority."""
    prior.validate();current.validate()
    old,new=prior.public(),current.public()
    for field in ('issuedAt','expiresAt'):
        old.pop(field);new.pop(field)
    if (old!=new or current.issued_at<prior.expires_at
            or current.expires_at<=prior.expires_at
            or now is not None and (type(now)is not int or not current.issued_at<=now<current.expires_at)):
        raise ValueError('CURRENT_PURCHASE_RENEWAL_SCOPE_CHANGED')
    return prior


def validate_collection_policy_successor(prior, current):
    prior.validate()
    current.validate()
    preserved = ('generation', 'collection', 'edition', 'metadata_root', 'proceeds_puzzle',
        'fee_puzzle', 'issuer_public_key', 'maximum_gross_mojos', 'test_usd_minor_per_txch')
    if (any(getattr(prior, field) != getattr(current, field) for field in preserved)
            or not prior.deed_launchers.issubset(current.deed_launchers)):
        raise ValueError('CURRENT_PURCHASE_COLLECTION_SCOPE_CHANGED')
    return prior


def selected_prior_purchase_policy(settings,current,*,now=None):
    path=getattr(settings,'generation_customer_purchase_prior_policy_path','')
    pin=getattr(settings,'generation_customer_purchase_prior_policy_hash','')
    if not path and not pin and not isinstance(current, TestnetCollectionIssuerPolicy):
        return None
    if not path or not pin:raise ValueError('CURRENT_PURCHASE_PRIOR_POLICY_PIN_REQUIRED')
    prior = read_current_issuer_policy(path, pin)
    if isinstance(current, TestnetCollectionIssuerPolicy):
        return validate_collection_policy_successor(prior, current)
    return validate_purchase_policy_renewal(prior,current,now=now)


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
    path = settings.generation_customer_purchase_policy_path
    pin = settings.generation_customer_purchase_policy_hash
    if getattr(settings, 'generation_customer_purchase_cutover_hash', ''):
        policy = read_collection_issuer_policy(path, pin)
        prior = selected_prior_purchase_policy(settings, policy)
        read_checkout_cutover(settings, prior, policy)
    else:
        policy = read_current_issuer_policy(path, pin)
        selected_prior_purchase_policy(settings, policy)
    if '0x'+policy.generation.hex()!=settings.deployment_generation_id:
        raise ValueError('CURRENT_PURCHASE_POLICY_GENERATION_CHANGED')
    return policy
