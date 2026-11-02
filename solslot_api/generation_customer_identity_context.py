"""Explicit reuse of verifier infrastructure, never old vault/ID admission.

The generation commits its custody and bridge policy on chain. A separately
reviewed, hash-pinned release may reuse compatible external verifier contracts
and unused bridge coins. That release is named as configuration, not relabeled
as a new signed genesis or an on-chain identity amendment.
"""
from hashlib import sha256
import json
from typing import Annotated,Literal

from chia_rs import Coin,G1Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from pydantic import Field,model_validator
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash
from .generation_preparation import PreparationModel

Hash=Annotated[str,Field(pattern=r'^0x[0-9a-f]{64}$')]
Address=Annotated[str,Field(pattern=r'^0x[0-9a-f]{40}$')]
PublicKey=Annotated[str,Field(pattern=r'^0x[0-9a-f]{96}$')]


class IdentityContract(PreparationModel):
    role:Literal['forwarder','verifierAdapter','attestationEmitter','zkPassportRootVerifier']
    address:Address
    code_hash:Hash=Field(alias='codeHash')

    @model_validator(mode='after')
    def nonzero(self):
        if self.address=='0x'+'00'*20 or self.code_hash=='0x'+'00'*32:
            raise ValueError('identity contracts require exact nonzero address and deployed-code hash')
        return self


class IdentityBridgeCoin(PreparationModel):
    parent_id:Hash=Field(alias='parentId')
    coin_id:Hash=Field(alias='coinId')


class CurrentCustomerIdentityProfile(PreparationModel):
    schema_version:Literal['solslot.current-customer-identity-profile.v1']=Field(alias='schema')
    purpose:Literal['REUSE_VERIFIER_INFRASTRUCTURE_FRESH_ENROLLMENTS_ONLY']
    network:Literal['testnet11']
    generation_id:Hash=Field(alias='generationId')
    preparation_manifest:Hash=Field(alias='preparationManifest')
    pool_launcher_id:Hash=Field(alias='poolLauncherId')
    vault_module_hash:Hash=Field(alias='vaultModuleHash')
    bridge_policy_hash:Hash=Field(alias='bridgePolicyHash')
    validator_public_keys:tuple[PublicKey,PublicKey,PublicKey]=Field(alias='validatorPublicKeys')
    validator_threshold:Literal[2]=Field(alias='validatorThreshold')
    bridge_coins:tuple[IdentityBridgeCoin,...]=Field(alias='bridgeCoins',min_length=1,max_length=128)
    evm_chain_id:Literal[8453]=Field(alias='evmChainId')
    trusted_direct_relayer:Address=Field(alias='trustedDirectRelayer')
    contracts:tuple[IdentityContract,IdentityContract,IdentityContract,IdentityContract]
    source_identity_amendment:Hash=Field(alias='sourceIdentityAmendment')
    accepted_proof_versions:tuple[Literal['0.20.0','0.21.0'],...]=Field(alias='acceptedProofVersions',min_length=1,max_length=2)
    legacy_vaults_admitted:Literal[False]=Field(alias='legacyVaultsAdmitted')
    legacy_receipts_admitted:Literal[False]=Field(alias='legacyReceiptsAdmitted')
    requires_fresh_private_check:Literal[True]=Field(alias='requiresFreshPrivateCheck')
    real_document_only:Literal[True]=Field(alias='realDocumentOnly')
    minimum_age:Literal[18]=Field(alias='minimumAge')

    @model_validator(mode='after')
    def canonical_infrastructure(self):
        if self.trusted_direct_relayer == '0x' + '00' * 20:
            raise ValueError('identity infrastructure requires its exact direct relayer')
        for value in (self.generation_id,self.preparation_manifest,self.pool_launcher_id,
                self.vault_module_hash,self.bridge_policy_hash,self.source_identity_amendment):
            if value=='0x'+'00'*32:raise ValueError('identity release references must be nonzero')
        if (len(set(self.validator_public_keys))!=3
                or {c.role for c in self.contracts}!={'forwarder','verifierAdapter','attestationEmitter','zkPassportRootVerifier'}
                or len({c.address for c in self.contracts})!=4
                or len(set(self.accepted_proof_versions))!=len(self.accepted_proof_versions)
                or len({c.coin_id for c in self.bridge_coins})!=len(self.bridge_coins)):
            raise ValueError('identity infrastructure roles, keys, versions and bridge coins must be distinct')
        keys=tuple(bytes.fromhex(value[2:]) for value in self.validator_public_keys)
        if any(G1Element.from_bytes(value)==G1Element() for value in keys):
            raise ValueError('identity validator keys must be nonidentity')
        if '0x'+make_bridge_policy_hash(keys,2).hex()!=self.bridge_policy_hash:
            raise ValueError('identity validator quorum differs from its native bridge policy')
        for row in self.bridge_coins:
            coin=Coin(bytes32.from_hexstr(row.parent_id),bytes32.from_hexstr(self.bridge_policy_hash),uint64(1))
            if '0x'+coin.name().hex()!=row.coin_id:
                raise ValueError('identity bridge coin differs from its exact one-mojo native lineage')
        return self

    def require_native(self,bindings):
        bindings.validate()
        fields={'generation_id':bindings.generation,'preparation_manifest':bindings.preparation_manifest,
            'pool_launcher_id':bindings.pool_launcher,'vault_module_hash':bindings.vault_module,
            'bridge_policy_hash':bindings.bridge_policy}
        if any(getattr(self,name)!='0x'+value.hex() for name,value in fields.items()):
            raise ValueError('identity infrastructure belongs to another native generation or custody policy')
        return self

    @property
    def commitment(self):
        return '0x'+sha256(json.dumps(self.model_dump(mode='json',by_alias=True),
            sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def policy(self):
        return {'schema':'solslot.identity-policy.v1','minimumAge':18,'domain':'solslot.com',
            'realDocumentOnly':True,'devMode':False,
            'sanctions':{'countries':'all','lists':'all','strict':False}}

    def public(self):
        # Explicit source semantics. This must never use the legacy artifact's
        # schema/hash or imply the old amendment activated for this generation.
        return {'schema':'solslot.current-customer-identity-deployment.v1',
            'source':'reviewed-release-and-current-native-bridge-policy',
            'generationId':self.generation_id,'profileHash':self.commitment,'network':self.network,
            'evmChainId':self.evm_chain_id,'addresses':{c.role:c.address for c in self.contracts},
            'contractCodeHashes':{c.role:c.code_hash for c in self.contracts},
            'acceptedProofVersions':list(self.accepted_proof_versions),'identityPolicy':self.policy(),
            'bridgePolicyHash':self.bridge_policy_hash,'requiresFreshPrivateCheck':True,
            'legacyVaultsAdmitted':False,'legacyReceiptsAdmitted':False}


def load_current_identity_profile(settings,index,*,now):
    """Pure configuration/native-index read. No EVM call, key, store or spend."""
    if not getattr(settings,'generation_customer_identity_enabled',False):return None
    if (settings.network!='testnet11' or not getattr(settings,'generation_customer_enabled',False)
            or getattr(settings,'alpha_writes_enabled',False)):
        raise ValueError('current identity requires the separate Testnet generation boundary')
    profile=read_current_identity_profile(settings.generation_customer_identity_profile_path,
        settings.generation_customer_identity_profile_hash)
    from .generation_customer_context import current_customer_launch_bindings
    return profile.require_native(current_customer_launch_bindings(settings,index,now=now))


def read_current_identity_profile(path, expected_hash):
    from .generation_index import _bounded_file
    raw = _bounded_file(path, 65536)
    if '0x' + sha256(raw).hexdigest() != expected_hash:
        raise ValueError('current identity profile differs from its frozen release')
    return CurrentCustomerIdentityProfile.model_validate_json(raw)
