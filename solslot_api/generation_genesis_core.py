"""Atomic, deterministic SGT/authority part of the replacement genesis.

This is an assembler, not a launch authorization or a broadcast interface.
The pool and its remaining economic bindings still need their own reviewed
assembly before the complete generation can be launched. Never expose this
partial assembly as a completed genesis. Source/recovery admission, fresh
recipient evidence, final consent, fees and native admission belong to the
final ceremony, not to a cached read or to this low-level constructor.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Literal

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    launch_conditions_and_coinsol, lineage_proof_for_coinsol,
    puzzle_for_singleton, solution_for_singleton,
)
from chia_rs import G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys
from pydantic import Field, model_validator

from solslot_puzzles import load_puzzle
from solslot_puzzles.admin_authority_v3_driver import (
    ADMIN_AUTHORITY_FUNDING_AMOUNT, AUTHORITY_LAUNCHER_AMOUNT,
    GenesisAdminAuthorityV3, build_genesis_admin_authority_v3,
)
from solslot_puzzles.generation_governance import Governance
from solslot_puzzles.generation_mint import GenerationMint
from solslot_puzzles.generation_statutes import GenerationStatutes
from solslot_puzzles.protocol_statutes_v1 import PermanentRules
from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
from solslot_puzzles.generation_registry import Component, Registry
from solslot_puzzles.generation_sgt import TOTAL_SGT, InitialIssuance, build_initial_issuance, ledger_inner
from solslot_puzzles.generation_transactions import NativeOperation, SingletonTip
from solslot_puzzles.holdings import quorum
from .generation_chain_evidence import GenerationChainAnchor
from .generation_preparation import PreparationModel, GenerationPreparation, commitment
from .generation_recipient_evidence import RecipientEvidence, issuance_plan_from_recipients

CORE_FUNDING_NAMES = ('authority', 'registry', 'governance', 'holdings', 'parameters', 'mint', 'sgt')
MAX_FUNDING_COST = 100_000_000


class GenerationCoreArtifact(PreparationModel):
    """Public keys and economic destinations in a separately frozen review.

    This is deliberately not the signed whole-generation release artifact.
    There is no configurable module, quorum, delay, initial supply or grant.
    """
    schema_version: Literal[1] = Field(default=1, alias='schemaVersion')
    purpose: Literal['GENERATION_CORE_PREPARATION'] = 'GENERATION_CORE_PREPARATION'
    generation_id: str = Field(alias='generationId', pattern=r'^0x[0-9a-f]{64}$')
    preparation_manifest: str = Field(alias='preparationManifest', pattern=r'^0x[0-9a-f]{64}$')
    daily_public_keys: tuple[str, str, str] = Field(alias='dailyPublicKeys')
    recovery_public_keys: tuple[str, str, str] = Field(alias='recoveryPublicKeys')
    treasury_puzzle_hash: str = Field(alias='treasuryPuzzleHash', pattern=r'^0x[0-9a-f]{64}$')
    protocol_puzzle_hash: str = Field(alias='protocolPuzzleHash', pattern=r'^0x[0-9a-f]{64}$')
    delivery_validator_public_keys: tuple[str, str, str] = Field(alias='deliveryValidatorPublicKeys')
    price_oracle_public_keys: tuple[str,...] = Field(default=(),alias='priceOraclePublicKeys')
    delivery_provider_id: str = Field(alias='deliveryProviderId', pattern=r'^0x[0-9a-f]{64}$')

    @model_validator(mode='after')
    def public_keys_and_bindings(self):
        import re
        for name in ('generation_id', 'preparation_manifest', 'treasury_puzzle_hash',
                     'protocol_puzzle_hash', 'delivery_provider_id'):
            if bytes32.from_hexstr(getattr(self, name)) == bytes32.zeros:
                raise ValueError('core artifact bindings must be nonzero')
        for name in ('daily_public_keys', 'recovery_public_keys', 'delivery_validator_public_keys', 'price_oracle_public_keys'):
            if name=='price_oracle_public_keys' and not self.price_oracle_public_keys:continue
            values = getattr(self, name)
            size = 66 if name == 'daily_public_keys' else 96
            if len(set(values)) != 3 or any(not re.fullmatch(r'0x[0-9a-f]{'+str(size)+r'}', v) for v in values):
                raise ValueError('core artifact requires three distinct canonical public keys per role')
            for value in values:
                raw = bytes.fromhex(value[2:])
                if name == 'daily_public_keys':
                    key = keys.PublicKey.from_compressed_bytes(raw)
                    if key.to_compressed_bytes() != raw:
                        raise ValueError('administrator public key is not canonical')
                elif G1Element.from_bytes(raw) == G1Element():
                    raise ValueError('BLS public key must not be infinity')
        return self

    @property
    def artifact_hash(self):
        return commitment(self.model_dump(mode='json', by_alias=True))


class GenerationLaunchArtifact(GenerationCoreArtifact):
    """Full economic assembly intent, still separate from release approval."""
    price_oracle_public_keys: tuple[str,str,str] = Field(alias='priceOraclePublicKeys')
    purpose: Literal['GENERATION_LAUNCH_PREPARATION'] = 'GENERATION_LAUNCH_PREPARATION'
    custody_policy: Literal['SEGREGATED_COMPANY_REVENUE_V1'] = Field(alias='custodyPolicy')
    company_revenue_puzzle_hash: str = Field(alias='companyRevenuePuzzleHash', pattern=r'^0x[0-9a-f]{64}$')


def component_id(generation: bytes32, label: str) -> bytes32:
    if label not in ('governance', 'parameters', 'mint', 'pool'):
        raise ValueError('unknown core component label')
    return Program.to([b'SOLSLOT_GENERATION_COMPONENT_V1', generation, label.encode()]).get_tree_hash()


@dataclass(frozen=True)
class CoreFundingRequest:
    name: str
    coin: Coin
    conditions: Program


@dataclass(frozen=True)
class GenerationCoreAssembly:
    operation: NativeOperation
    anchor: GenerationChainAnchor
    authority: GenesisAdminAuthorityV3
    issuance: InitialIssuance
    core_commitment: bytes32
    preparation_manifest: str
    artifact_hash: str
    complete_assembly: bool = False

    def review(self) -> dict:
        root = self.issuance.holdings.root
        parameters = self.anchor.economic_components[0].economic_parameters()
        return {
            'purpose': 'GENERATION_LAUNCH_PREPARATION' if self.complete_assembly else 'GENERATION_CORE_PREPARATION', 'launchComplete': False,
            'assemblyComplete':self.complete_assembly,
            'generationId': '0x'+self.operation.generation.hex(), 'network': 'testnet11',
            'preparationManifest': self.preparation_manifest, 'artifactHash': self.artifact_hash,
            'coreCommitment': '0x'+self.core_commitment.hex(),
            'remainingAssembly': ['FINAL_RELEASE_RECOVERY_AND_CONSENT'] if self.complete_assembly else ['POOL_AND_ECONOMIC_BINDINGS', 'FINAL_RELEASE_RECOVERY_AND_CONSENT'],
            'sgtTailHash': '0x'+self.anchor.issuance.tail().get_tree_hash().hex(),
            'sgtOutputs': [{'coinId': '0x'+coin.name().hex(), 'puzzleHash': '0x'+coin.puzzle_hash.hex(),
                            'amount': int(coin.amount), 'kind': output.kind.name,
                            'ownerPuzzleHash': '0x'+output.owner.hex()}
                           for coin, output in zip(self.issuance.coins, self.issuance.outputs, strict=True)],
            'supply': {'total': root.total, 'distributed': root.eligible,
                      'reserve': TOTAL_SGT-root.eligible, 'quorum': quorum(root.eligible)},
            'exchangeFees': {'totalBps': parameters.exchange_fee_bps,
                            'protocolBps': parameters.protocol_fee_bps,
                            'sgtRewardsBps': parameters.sgt_rewards_fee_bps},
            'custody': self._custody_review(),
            'readAnchor': {
                'schemaVersion': 1, 'purpose': 'GENERATION_CHAIN_READ_ANCHOR',
                'preparationManifest': self.preparation_manifest,
                'registryInner': '0x'+bytes(self.anchor.registry.inner()).hex(),
                'governanceComponentId': '0x'+self.anchor.governance.component_id.hex(),
                'economicInners': {name: '0x'+bytes(state.inner()).hex()
                    for name, state in zip(('parameters', 'mint', 'pool') if self.complete_assembly else ('parameters', 'mint'), self.anchor.economic_components, strict=True)},
                'administrator':{
                    'sourceManifestHash':'0x'+self.authority.source_manifest_hash.hex(),
                    'dailyPublicKeys':['0x'+i.daily_compressed_pubkey.hex() for i in self.authority.identity_vaults],
                    'recoveryPublicKeys':['0x'+i.recovery_bls_pubkey.hex() for i in self.authority.identity_vaults]},
            },
        }

    def _custody_review(self):
        from solslot_puzzles.generation_revenue import CompanyRevenue, BackingCustody, PrimaryFeeSplitter
        generation = self.operation.generation
        if not self.complete_assembly:
            return {'assembly': 'INCOMPLETE_NOT_LAUNCH_AUTHORITY'}
        revenue = CompanyRevenue(generation, self.authority.authority_launcher_id)
        return {'policy': 'SEGREGATED_COMPANY_REVENUE_V1', 'companyRevenue': revenue.review(),
            'primaryFeeSplitter': '0x'+PrimaryFeeSplitter(self.anchor.issuance.bindings(),
                self.anchor.economic_components[0].launcher_id, revenue).inner().get_tree_hash().hex(),
            'nonwithdrawableBacking': '0x'+BackingCustody(generation).inner().get_tree_hash().hex(),
            'sgtRewards': 'SEPARATE_HOLDER_CLAIMS', 'redemptions': 'SEPARATE_ISSUER_FUNDED_LEAVES'}


@dataclass(frozen=True)
class _CoreGraph:
    preparation: GenerationPreparation
    artifact: GenerationCoreArtifact
    authority: GenesisAdminAuthorityV3
    anchor: GenerationChainAnchor
    issuance: InitialIssuance
    commitment: bytes32
    complete: bool = False


def _graph(preparation, artifact, evidence, *, trusted_preparation_hash, trusted_artifact_hash, complete=False):
    # Copy maps before constructing any tree or accepting caller-owned objects.
    prep = GenerationPreparation.model_validate_json(preparation.model_dump_json(by_alias=True))
    art = (GenerationLaunchArtifact if complete else GenerationCoreArtifact).model_validate_json(artifact.model_dump_json(by_alias=True))
    if (prep.manifest_hash != trusted_preparation_hash or art.artifact_hash != trusted_artifact_hash
            or art.preparation_manifest != prep.manifest_hash or art.generation_id != prep.generation_id):
        raise ValueError('genesis core requires the exact separately reviewed preparation and artifact')
    for admin, public_key in zip(prep.administrators, art.daily_public_keys, strict=True):
        key = keys.PublicKey.from_compressed_bytes(bytes.fromhex(public_key[2:]))
        if '0x'+key.to_canonical_address().hex() != admin.wallet:
            raise ValueError('authority daily key does not match the frozen administrator wallet')
    plan = issuance_plan_from_recipients(prep, evidence)
    if any(type(r.confirmed_height) is not int or r.confirmed_height <= 0
           or r.coin_id == bytes32.zeros for r in evidence.recipients):
        raise ValueError('core assembly requires confirmed recipient evidence')
    for admin, recipient in zip(prep.administrators, evidence.recipients, strict=True):
        expected = Coin(bytes32.from_hexstr(admin.custody.launcher_id),
            puzzle_for_singleton(bytes32.from_hexstr(admin.custody.launcher_id),
                                 prep.custody_inner(admin)).get_tree_hash(), uint64(1))
        if recipient.coin_id != expected.name():
            raise ValueError('recipient evidence differs from the exact frozen custody output')
    b = bytes32.from_hexstr
    coordinate = lambda name: b(prep.coordinates[name].launcher_id)
    revenue = None
    if complete:
        from solslot_puzzles.generation_revenue import CompanyRevenue, BackingCustody, PrimaryFeeSplitter
        revenue = CompanyRevenue(plan.generation, coordinate('authority'))
        backing = BackingCustody(plan.generation)
        if (b(art.treasury_puzzle_hash) != backing.inner().get_tree_hash()
                or b(art.company_revenue_puzzle_hash) != revenue.inner().get_tree_hash()
                or b(art.protocol_puzzle_hash) in (backing.inner().get_tree_hash(), revenue.inner().get_tree_hash())):
            raise ValueError('launch requires exact segregated backing/revenue custody and separate primary proceeds')
    authority = build_genesis_admin_authority_v3(
        parent_coin_id=b(prep.coordinates['authority'].funding_coin_id), network='testnet11',
        daily_compressed_pubkeys=tuple(bytes.fromhex(v[2:]) for v in art.daily_public_keys),
        recovery_bls_pubkeys=tuple(bytes.fromhex(v[2:]) for v in art.recovery_public_keys),
        source_manifest_hash=b(art.artifact_hash), authority_puzzle_version=4)
    if (authority.authority_launcher_id != coordinate('authority')
            or tuple('0x'+i.launcher_id.hex() for i in authority.identity_vaults)
            != tuple(a.identity_authority_launcher for a in prep.administrators)):
        raise ValueError('administrator authority differs from the reserved identities')
    gov = Governance(plan.bindings(), coordinate('registry'), coordinate('authority'), coordinate('mint'),
        component_id(plan.generation, 'governance'), load_puzzle('generation_extension_v1.clsp').get_tree_hash())
    params = GenerationStatutes(plan.generation, coordinate('registry'), coordinate('governance'),
        coordinate('parameters'), component_id(plan.generation, 'parameters'), pool_id=coordinate('pool'),
        permanent_rules=PermanentRules(plan.bindings().tail_hash,TOTAL_SGT,pool_token_tail_hash(coordinate('pool')),
            b(prep.bridge_policy_hash),b(art.treasury_puzzle_hash),plan.generation))
    mint = GenerationMint(plan.generation, coordinate('registry'), coordinate('governance'),
        coordinate('mint'), component_id(plan.generation, 'mint'), coordinate('pool'),
        PrimaryFeeSplitter(plan.bindings(),coordinate('parameters'),revenue).inner().get_tree_hash() if complete else b(art.treasury_puzzle_hash), b(art.protocol_puzzle_hash),
        tuple(bytes.fromhex(v[2:]) for v in art.delivery_validator_public_keys), b(art.delivery_provider_id))
    if complete:
        from solslot_puzzles.generation_primary_inventory import batch_bindings
        mint = replace(mint, primary_batch_bindings=batch_bindings(generation=plan.generation,
            pool_id=coordinate('pool'), sgt=plan.bindings(), statutes_id=coordinate('parameters'),
            treasury=revenue.inner().get_tree_hash(),oracle_pubkeys=tuple(bytes.fromhex(v[2:]) for v in art.price_oracle_public_keys),pool_kernel_version=2))
    gov_component = Component(gov.component_id, coordinate('governance'),
        load_puzzle('generation_governance_v1.clsp').get_tree_hash(), gov.module_hash, 1, 1)
    economic=(params,mint)
    if complete:
        from chia.wallet.cat_wallet.cat_utils import CAT_MOD
        from chia.wallet.trading.offer import OFFER_MOD_HASH
        from solslot_puzzles.generation_pool import GenerationPool
        from solslot_puzzles.generation_registry import singleton_struct
        from solslot_puzzles.generation_sols_reserve import reserve_inner
        from solslot_puzzles.generation_rewards import RewardCustody
        from solslot_puzzles.pool_v4_driver import PoolV4Config
        from solslot_puzzles.sols_pool_v4 import SolsPoolStateV4
        from solslot_puzzles.sols_economics_v3 import SolsEconomicState
        pool_component=component_id(plan.generation,'pool')
        reserve=reserve_inner(generation=plan.generation,registry_id=coordinate('registry'),pool_id=coordinate('pool'),component_id=pool_component,pool_kernel_version=2)
        reward=RewardCustody(plan.bindings(),params.launcher_id,params.permanent_rules.sols_tail_hash)
        permanent=PoolV4Config(coordinate('pool'),load_puzzle('generation_statutes_v1.clsp').get_tree_hash(),
            singleton_struct(params.launcher_id),singleton_struct(coordinate('governance')),params.permanent_rules,
            CAT_MOD.get_tree_hash(),OFFER_MOD_HASH,load_puzzle('p2_vault.clsp').get_tree_hash(),
            load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash(),load_puzzle('p2_pool_v2.clsp').get_tree_hash(),
            load_puzzle('singleton_launcher_with_did.clsp').curry(singleton_struct(mint.launcher_id)).get_tree_hash(),
            reserve.get_tree_hash(),reward.inner().get_tree_hash())
        pool=GenerationPool(plan.generation,coordinate('registry'),pool_component,permanent,
            SolsPoolStateV4(Program.to([]).get_tree_hash(),SolsEconomicState(False,0,0,0,0,1,1),1),
            company_revenue_puzzle_hash=revenue.inner().get_tree_hash())
        economic=(*economic,pool)
    registry = Registry(plan.generation, coordinate('registry'), coordinate('governance'),
        coordinate('authority'), (gov_component, *(s.component() for s in economic)))
    anchor = GenerationChainAnchor(plan, registry, gov, economic, authority)
    issuance = build_initial_issuance(plan)
    # Bind the actual locally compiled programs, not only their source labels.
    inners = [authority.inner_puzzle, *(i.custody_reveal for i in authority.identity_vaults),
              registry.inner(), gov.inner(), ledger_inner(plan.bindings(), issuance.holdings, 0),
              *(s.inner() for s in economic), plan.tail()]
    core_hash = Program.to([b'SOLSLOT_GENESIS_LAUNCH_V1' if complete else b'SOLSLOT_GENESIS_CORE_V1', b(prep.manifest_hash), b(art.artifact_hash),
        [p.get_tree_hash() for p in inners], [c.name() for c in issuance.coins]]).get_tree_hash()
    return _CoreGraph(prep, art, authority, anchor, issuance, core_hash, complete)


def _templates(graph: _CoreGraph, funding_coins: dict[str, Coin], consent_issued_at=None):
    if consent_issued_at is not None and (not graph.complete or type(consent_issued_at) is not int
            or not 0 < consent_issued_at < 2**63-86400):
        raise ValueError('final launch consent requires an exact 24-hour interval')
    names=(*CORE_FUNDING_NAMES,'pool') if graph.complete else CORE_FUNDING_NAMES
    if set(funding_coins) != set(names):
        raise ValueError('genesis requires every distinct reserved funding parent')
    prep, anchor, authority, issue = graph.preparation, graph.anchor, graph.authority, graph.issuance
    if len({c.name() for c in funding_coins.values()}) != len(names):
        raise ValueError('core funding parents cannot be reused')
    for name, coin in funding_coins.items():
        expected = prep.sgt_funding_coin_id if name == 'sgt' else prep.coordinates[name].funding_coin_id
        minimum = TOTAL_SGT if name == 'sgt' else ADMIN_AUTHORITY_FUNDING_AMOUNT if name == 'authority' else 2 if name=='pool' else 1
        if '0x'+coin.name().hex() != expected or coin.amount < minimum:
            raise ValueError('core funding differs from its reserved parent or required amount')
    inners = {'registry': anchor.registry.inner(), 'governance': anchor.governance.inner(),
              'holdings': ledger_inner(anchor.issuance.bindings(), issue.holdings, 0),
              'parameters': anchor.economic_components[0].inner(), 'mint': anchor.economic_components[1].inner()}
    if graph.complete:inners['pool']=anchor.economic_components[2].inner()
    requests, launches = [], []
    for name in names:
        parent = funding_coins[name]
        if name == 'sgt':
            conditions = [Program.to([51, issue.eve_coin.puzzle_hash, TOTAL_SGT])]
            required_amount = TOTAL_SGT
        else:
            targets = [(authority.inner_puzzle, AUTHORITY_LAUNCHER_AMOUNT),
                       *((i.custody_reveal, i.launcher_amount) for i in authority.identity_vaults)] \
                if name == 'authority' else [(inners[name], 1)]
            conditions, required_amount = [], sum(amount for _, amount in targets)
            for inner, amount in targets:
                more, launch = launch_conditions_and_coinsol(parent, inner, [], uint64(amount))
                conditions.extend(more); launches.append((name, inner, launch))
            if name=='pool':
                from solslot_puzzles.generation_sols_genesis import sols_seed
                seed=sols_seed(anchor.economic_components[2],parent)
                conditions.append(Program.to([51,seed.eve.puzzle_hash,1]));required_amount+=1
        change = int(parent.amount)-required_amount
        if change:
            conditions.append(Program.to([51, parent.puzzle_hash, change]))
        # All core parents authorize the same plan and require every other
        # parent. A bundle cannot launch only the authority or only the SGT.
        conditions.append(Program.to([60, graph.commitment]))
        conditions.extend(Program.to([61, sha256(bytes(funding_coins[other_name].name())+bytes(graph.commitment)).digest()])
                          for other_name in names if other_name != name)
        if consent_issued_at is not None:
            conditions.extend(Program.to(c) for c in ([81,consent_issued_at],[85,consent_issued_at+86400]))
        requests.append(CoreFundingRequest(name, parent, Program.to(conditions)))
    return tuple(requests), tuple(launches)


def genesis_core_funding_requests(preparation: GenerationPreparation, artifact: GenerationCoreArtifact,
                                 evidence: RecipientEvidence, funding_coins: dict[str, Coin], *,
                                 trusted_preparation_hash: str, trusted_artifact_hash: str):
    """Exact delegated conditions for explicit signer review. Never signs."""
    graph = _graph(preparation, artifact, evidence, trusted_preparation_hash=trusted_preparation_hash,
                   trusted_artifact_hash=trusted_artifact_hash)
    return _templates(graph, dict(funding_coins))[0]


def assemble_genesis_core(preparation: GenerationPreparation, artifact: GenerationCoreArtifact,
                          evidence: RecipientEvidence, funding_spends: dict[str, CoinSpend], *,
                          trusted_preparation_hash: str, trusted_artifact_hash: str,
                          aggregated_signature: G2Element = G2Element()) -> GenerationCoreAssembly:
    return _assemble(preparation,artifact,evidence,funding_spends,trusted_preparation_hash=trusted_preparation_hash,
        trusted_artifact_hash=trusted_artifact_hash,aggregated_signature=aggregated_signature,complete=False)


def genesis_launch_funding_requests(preparation: GenerationPreparation, artifact: GenerationLaunchArtifact,
        evidence: RecipientEvidence,funding_coins:dict[str,Coin],*,trusted_preparation_hash:str,trusted_artifact_hash:str,
        consent_issued_at=None):
    graph=_graph(preparation,artifact,evidence,trusted_preparation_hash=trusted_preparation_hash,
        trusted_artifact_hash=trusted_artifact_hash,complete=True)
    return _templates(graph,dict(funding_coins),consent_issued_at)[0]


def assemble_genesis_launch(preparation: GenerationPreparation, artifact: GenerationLaunchArtifact,
        evidence: RecipientEvidence,funding_spends:dict[str,CoinSpend],*,trusted_preparation_hash:str,
        trusted_artifact_hash:str,aggregated_signature:G2Element=G2Element(),consent_issued_at=None)->GenerationCoreAssembly:
    return _assemble(preparation,artifact,evidence,funding_spends,trusted_preparation_hash=trusted_preparation_hash,
        trusted_artifact_hash=trusted_artifact_hash,aggregated_signature=aggregated_signature,complete=True,
        consent_issued_at=consent_issued_at)


def _assemble(preparation,artifact,evidence,funding_spends,*,trusted_preparation_hash,
        trusted_artifact_hash,aggregated_signature,complete,consent_issued_at=None):
    graph = _graph(preparation, artifact, evidence, trusted_preparation_hash=trusted_preparation_hash,
                   trusted_artifact_hash=trusted_artifact_hash,complete=complete)
    spends = dict(funding_spends)
    requests, launches = _templates(graph, {k: v.coin for k, v in spends.items()},consent_issued_at)
    for request in requests:
        spend = spends[request.name]
        puzzle = Program.from_bytes(bytes(spend.puzzle_reveal))
        if puzzle.get_tree_hash() != request.coin.puzzle_hash:
            raise ValueError('funding reveal differs from its reserved coin')
        _, result = puzzle.run_with_cost(MAX_FUNDING_COST, Program.from_bytes(bytes(spend.solution)))
        conditions = list(result.as_iter())
        # Native signature verification follows in admission. Every other
        # condition must be the exact reviewed launcher/change/atomicity set.
        nonsignatures = [condition for condition in conditions if not 43 <= condition.first().as_int() <= 50]
        if sorted(bytes(c) for c in nonsignatures) != sorted(bytes(c) for c in request.conditions.as_iter()):
            raise ValueError('funding conditions change the exact reviewed core or its unchanged-owner change')
    if not isinstance(aggregated_signature, G2Element):
        raise ValueError('core signatures require a canonical BLS aggregate')
    native_spends = [spends[r.name] for r in requests]
    tips, auxiliary = [], []
    for name, inner, launch in launches:
        native_spends.append(launch)
        coin = Coin(launch.coin.name(), puzzle_for_singleton(launch.coin.name(), inner).get_tree_hash(), launch.coin.amount)
        if name == 'authority':
            auxiliary.append(coin)
            continue
        tip = SingletonTip(launch.coin.name(), inner, coin, launch).validate()
        if name == 'holdings':
            init = make_spend(coin, puzzle_for_singleton(tip.launcher_id, inner),
                solution_for_singleton(lineage_proof_for_coinsol(launch), uint64(1), graph.issuance.ledger_initialization()))
            native_spends.append(init)
            tip = tip.advanced(init, inner)
        if name=='pool':
            from dataclasses import replace
            from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,unsigned_spend_bundle_for_spendable_cats
            from solslot_puzzles.generation_sols_genesis import sols_seed
            pool=graph.anchor.economic_components[2];seed=sols_seed(pool,spends[name].coin)
            transition=tip.spend(pool.solution(tip.coin,'SEED_SOLS',[spends[name].coin.name(),seed.eve.name()]))
            native_spends.append(transition)
            seeded=replace(pool,economics=replace(pool.economics,state_version=2))
            tip=tip.advanced(transition,seeded.inner())
            cat=SpendableCAT(seed.eve,seed.tail.get_tree_hash(),seed.inner,
                Program.to([seed.tail,pool.inner().get_tree_hash(),transition.coin.name(),seed.eve.name()]),limitations_program_reveal=seed.tail)
            native_spends.extend(unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat]).coin_spends)
            auxiliary.append(seed.reserve)
        tips.append(tip)
    native_spends.append(graph.issuance.eve_spend)
    operation = NativeOperation(graph.anchor.issuance.generation, 'INITIALIZE_GENERATION' if complete else 'INITIALIZE_GENERATION_CORE',
        tuple(native_spends), tuple(tips), tuple(auxiliary)+graph.issuance.coins, aggregated_signature)
    bundle = operation.bundle()
    if sum(c.amount for c in bundle.removals()) != sum(c.amount for c in bundle.additions()):
        raise ValueError('genesis core cannot hide an implicit fee or create value')
    return GenerationCoreAssembly(operation, graph.anchor, graph.authority, graph.issuance,
        graph.commitment, graph.preparation.manifest_hash, graph.artifact.artifact_hash,complete)
