"""Separate collection-scoped Testnet issuer authority; not an activation path.

This schema does not reinterpret the finite legacy policy or grant a key.  A
caller must independently validate current on-chain inventory and vault evidence
and install a transitioned durable issuer/fee journal before using it.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import stat
from pathlib import Path

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD
from chia_rs import G1Element
from chia_rs.sized_bytes import bytes32

_MOD_BYTES=bytes(MOD)


def _hex(value):
    return '0x' + bytes(value).hex()


@dataclass(frozen=True)
class TestnetCollectionIssuerPolicy:
    generation: bytes32
    collection: bytes32
    edition: bytes32
    metadata_root: bytes32
    proceeds_puzzle: bytes32
    fee_puzzle: bytes32
    issuer_public_key: bytes
    deed_launchers: frozenset[bytes32]
    maximum_gross_mojos: int
    test_usd_minor_per_txch: int | None = None

    def validate(self):
        if not isinstance(self.deed_launchers,frozenset) or not 1<=len(self.deed_launchers)<=25:
            raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_INVALID')
        fields=(self.generation,self.collection,self.edition,self.metadata_root,
                self.proceeds_puzzle,self.fee_puzzle,*self.deed_launchers)
        if (any(not isinstance(v,bytes32) or v==bytes32.zeros for v in fields)
                or type(self.maximum_gross_mojos) is not int or not 1<self.maximum_gross_mojos<2**64
                or (self.test_usd_minor_per_txch is not None and (type(self.test_usd_minor_per_txch)is not int
                    or not 1<=self.test_usd_minor_per_txch<=10**15))
                or not isinstance(self.issuer_public_key,bytes) or len(self.issuer_public_key)!=48):
            raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_INVALID')
        try:
            key=G1Element.from_bytes(self.issuer_public_key)
            if key==G1Element() or Program.from_bytes(_MOD_BYTES).curry(key).get_tree_hash()!=self.proceeds_puzzle:raise ValueError()
        except Exception as exc:
            raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_INVALID') from exc
        return self

    def public(self):
        value={'schema':'solslot.testnet-collection-issuer-policy.v1','network':'testnet11',
            'generationId':_hex(self.generation),'collectionHash':_hex(self.collection),
            'editionHash':_hex(self.edition),'metadataRoot':_hex(self.metadata_root),
            'proceedsPuzzleHash':_hex(self.proceeds_puzzle),'feePuzzleHash':_hex(self.fee_puzzle),
            'issuerPublicKey':_hex(self.issuer_public_key),
            'deedLauncherIds':sorted(_hex(value) for value in self.deed_launchers),
            'maximumGrossMojos':str(self.maximum_gross_mojos),
            'technologyFeeBps':100,'companyShareOfFeeBps':7000,'sgtShareOfFeeBps':3000,
            'scope':'NEW_EPHEMERAL_PRIMARY_PROCEEDS_ONLY',
            'mainnetEnabled':False,'masterKeyExportAuthorized':False}
        if self.test_usd_minor_per_txch is not None:
            value['pricing']={'mode':'FIXED_TESTNET_CONVERSION','usdMinorPerTxch':str(self.test_usd_minor_per_txch)}
        return value

    @property
    def commitment(self):
        self.validate()
        return '0x'+sha256(json.dumps(self.public(),sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def require_terms(self, terms, *, now=None):
        """Check sealed mint terms; no caller-supplied destination is accepted."""
        self.validate()
        try:
            bindings=list(Program.from_bytes(terms.generation_batch_bindings).as_iter())
            valid=(terms.network=='testnet11' and terms.inventory_version==4 and len(bindings)==8
                and bindings[0].as_atom()==bytes(self.generation)
                and terms.collection_id==self.collection and terms.metadata_anchor_id==self.edition
                and terms.metadata_root==self.metadata_root and terms.deed_launcher_id in self.deed_launchers
                and terms.protocol_puzhash==self.proceeds_puzzle
                and terms.protocol_treasury_puzzle_hash==self.fee_puzzle and terms.technology_fee_bps==100)
        except Exception as exc:
            raise ValueError('CURRENT_COLLECTION_ISSUER_TERMS_CHANGED') from exc
        if not valid:raise ValueError('CURRENT_COLLECTION_ISSUER_TERMS_CHANGED')
        return self

    def require_purchase(self, artifact, terms, vault, *, launcher, auth_type, now):
        """Scope one exact native quote to sealed terms and the current vault.

        Signature, live coin state, ownership session and chain evidence must
        still be verified by the caller before using an issuer key.
        """
        from solslot_puzzles.payment_artifacts_v2 import PaymentRail
        from solslot_puzzles.stripe_settlement_v1_driver import assert_artifact_matches_terms
        self.require_terms(terms)
        self.require_verified_vault(vault,launcher=launcher,auth_type=auth_type)
        try:
            assert_artifact_matches_terms(artifact,terms)
            valid=(artifact.vault_launcher_id==launcher and artifact.zkpassport_root==vault.root
                and artifact.rail==PaymentRail.CHIA_XCH and type(now)is int
                and now<artifact.quote_expires_at<=artifact.authorization_expires_at
                and 1<int(artifact.rail_amount)<=self.maximum_gross_mojos)
        except Exception as exc:
            raise ValueError('CURRENT_COLLECTION_ISSUER_PURCHASE_SCOPE_CHANGED') from exc
        if not valid:raise ValueError('CURRENT_COLLECTION_ISSUER_PURCHASE_SCOPE_CHANGED')
        return self

    def require_verified_vault(self, vault, *, launcher, auth_type, owner_key=None):
        """Require a reconstructed current Chia-owned vault for native XCH.

        The launcher and auth type must come from the authenticated session;
        this method is not itself an authentication or primary-chain read.
        """
        from .generation_customer_vault import CurrentCustomerVault
        self.validate()
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton, SINGLETON_MOD_HASH, SINGLETON_LAUNCHER_HASH
        from solslot_puzzles.vault_driver import AUTH_TYPE_BLS
        from solslot_puzzles import load_puzzle
        if (not isinstance(vault,CurrentCustomerVault) or auth_type!='chia_bls'
                or not isinstance(launcher,bytes32) or launcher==bytes32.zeros
                or vault.launcher!=launcher or vault.generation!=self.generation
                or not vault.identity_verified or type(vault.confirmed_height)is not int
                or vault.confirmed_height<=0):
            raise ValueError('CURRENT_COLLECTION_ISSUER_VERIFIED_CHIA_VAULT_REQUIRED')
        try:
            module,args=vault.inner.uncurry();fields=list(args.as_iter())
            singleton=Program.to((SINGLETON_MOD_HASH,(launcher,SINGLETON_LAUNCHER_HASH)))
            valid=(module.get_tree_hash()==load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash()
                and len(fields)==9 and bytes(fields[0])==bytes(singleton)
                and fields[2].as_int()==AUTH_TYPE_BLS and fields[4].as_atom()==bytes(vault.root)
                and (owner_key is None or (isinstance(owner_key, str) and owner_key.lower()==_hex(fields[1].as_atom())))
                and vault.coin.amount==1 and vault.coin.puzzle_hash==puzzle_for_singleton(launcher,vault.inner).get_tree_hash())
        except Exception as exc:
            raise ValueError('CURRENT_COLLECTION_ISSUER_VERIFIED_CHIA_VAULT_REQUIRED') from exc
        if not valid:raise ValueError('CURRENT_COLLECTION_ISSUER_VERIFIED_CHIA_VAULT_REQUIRED')
        return self


def read_collection_issuer_policy(path,expected_file_hash):
    """Read an exact pinned public policy. Legacy v1/v2 readers are untouched."""
    p=Path(path)
    info=p.lstat()
    if p.is_symlink() or not stat.S_ISREG(info.st_mode) or not 1<=info.st_size<=65536:
        raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_FILE_INVALID')
    raw=p.read_bytes()
    if len(raw)!=info.st_size:raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_FILE_CHANGED')
    if '0x'+sha256(raw).hexdigest()!=expected_file_hash:
        raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_FILE_CHANGED')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_DUPLICATE_FIELD')
            result[key]=value
        return result
    q=json.loads(raw,object_pairs_hook=unique)
    keys={'schema','network','generationId','collectionHash','editionHash','metadataRoot',
          'proceedsPuzzleHash','feePuzzleHash','issuerPublicKey','deedLauncherIds',
          'maximumGrossMojos','technologyFeeBps','companyShareOfFeeBps','sgtShareOfFeeBps',
          'scope','mainnetEnabled','masterKeyExportAuthorized'}
    pricing=q.get('pricing') if isinstance(q,dict) else None
    if pricing is not None:
        keys.add('pricing')
        if (not isinstance(pricing,dict) or set(pricing)!={'mode','usdMinorPerTxch'}
                or pricing['mode']!='FIXED_TESTNET_CONVERSION' or not isinstance(pricing['usdMinorPerTxch'],str)
                or not pricing['usdMinorPerTxch'].isdigit() or str(int(pricing['usdMinorPerTxch']))!=pricing['usdMinorPerTxch']):
            raise ValueError('CURRENT_COLLECTION_ISSUER_PRICING_INVALID')
    if (not isinstance(q,dict) or set(q)!=keys or q['schema']!='solslot.testnet-collection-issuer-policy.v1'
            or q['network']!='testnet11' or q['mainnetEnabled'] is not False
            or q['masterKeyExportAuthorized'] is not False
            or q['scope']!='NEW_EPHEMERAL_PRIMARY_PROCEEDS_ONLY'
            or [q[k] for k in ('technologyFeeBps','companyShareOfFeeBps','sgtShareOfFeeBps')]!=[100,7000,3000]
            or not isinstance(q['deedLauncherIds'],list) or not all(isinstance(x,str) for x in q['deedLauncherIds'])
            or q['deedLauncherIds']!=sorted(set(q['deedLauncherIds']))
            or not isinstance(q['maximumGrossMojos'],str) or not q['maximumGrossMojos'].isdigit()
            or str(int(q['maximumGrossMojos']))!=q['maximumGrossMojos']):
        raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_FIELDS_CHANGED')
    try:
        b=lambda name:bytes32.from_hexstr(q[name])
        policy=TestnetCollectionIssuerPolicy(b('generationId'),b('collectionHash'),b('editionHash'),b('metadataRoot'),
            b('proceedsPuzzleHash'),b('feePuzzleHash'),bytes.fromhex(q['issuerPublicKey'].removeprefix('0x')),
            frozenset(bytes32.from_hexstr(x) for x in q['deedLauncherIds']),int(q['maximumGrossMojos']),
            int(pricing['usdMinorPerTxch']) if pricing is not None else None).validate()
    except (TypeError,ValueError,KeyError) as exc:
        raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_FIELDS_CHANGED') from exc
    if policy.public()!=q:raise ValueError('CURRENT_COLLECTION_ISSUER_POLICY_CANONICAL_REQUIRED')
    return policy
