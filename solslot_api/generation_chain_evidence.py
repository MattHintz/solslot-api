"""Primary-node reconstruction of holder governance and its holdings snapshots.

Inputs are frozen initial contracts, never coordinator-selected current roots.
Call from a reconciler; user status requests read the persisted projection.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass,field

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import Governance
from solslot_puzzles.generation_economic_reader import EconomicComponent,reconstruct_economic_successor
from solslot_puzzles.generation_governance_reader import reconstruct_governance_successor
from solslot_puzzles.generation_holdings_reader import reconstruct_holdings_successor
from solslot_puzzles.generation_registry import Registry
from solslot_puzzles.generation_registry_reader import exact_list, reconstruct_registry_successor,parse_upgrade_plan,uint
from solslot_puzzles.generation_sgt import GenesisIssuancePlan, build_initial_issuance, ledger_inner
from solslot_puzzles.holdings import HoldingsTree, HoldingKind
from solslot_puzzles.admin_authority_v3_driver import GenesisAdminAuthorityV3
from solslot_puzzles.generation_admin_transactions import validate_frozen_administrator

from .generation_registry_evidence import _spend
from .vault_chain_evidence import ConfirmedVaultCoin, read_vault_coin

MAX_HISTORY = 512


def public_bill(bill):
    """Typed public intent for review, derived from the consensus-bound bill."""
    tag=bill.first().as_atom().decode('ascii')
    value={'kind':tag,'billHash':'0x'+bill.get_tree_hash().hex()}
    if tag=='UPGRADE':
        _,nonce,raw=exact_list(bill,3);plan=parse_upgrade_plan(raw)
        value.update(registryNonce=nonce.as_int(),upgrade={'sourceManifestHash':'0x'+plan.source_manifest_hash.hex(),
            'changes':[{'componentId':'0x'+c.component_id.hex(),'oldModuleHash':'0x'+c.old_module_hash.hex(),
                'newModuleHash':'0x'+c.new_module_hash.hex(),'nextVersion':c.next_version,
                'compatibility':c.compatibility,'transition':'PRESERVE_STATE'} for c in plan.changes]})
    elif tag=='REOPEN':
        _,epoch,scope=exact_list(bill,3);value.update(pauseEpoch=epoch.as_int(),scope=scope.as_int())
    elif tag=='PARAMETERS':
        _,component,launcher,revision,previous,values=exact_list(bill,6)
        value['parameters']={'componentId':'0x'+component.as_atom().hex(),'launcherId':'0x'+launcher.as_atom().hex(),
            'revision':revision.as_int(),'previousValuesHash':'0x'+previous.as_atom().hex(),
            'values':[v.as_int() for v in exact_list(values,6)]}
    elif tag=='MINT_TEST_ONLY':
        _,collection,edition,count=exact_list(bill,4)
        collection_id,edition_hash=bytes32(collection.as_atom()),bytes32(edition.as_atom())
        deed_count=uint(count)
        if collection_id==bytes32.zeros or edition_hash==bytes32.zeros or not 1<=deed_count<=100:
            raise ValueError('test mint requires an exact collection, edition and bounded deed count')
        value['testMint']={'purpose':'TEST_ONLY','collectionId':'0x'+collection_id.hex(),
            'editionHash':'0x'+edition_hash.hex(),'deedCount':deed_count}
    elif tag=='STATUTES':
        from solslot_puzzles.generation_economic_reader import parse_statute_record
        _,component,launcher,revision,kind,key,raw,old,new=exact_list(bill,9)
        label=kind.as_atom().decode('ascii');record=parse_statute_record(label,raw)
        identity=bytes32(key.as_atom())
        if identity==bytes32.zeros or identity!=record.as_program_value()[0] or old==new:
            raise ValueError('statutes bill must bind one changed canonical record')
        value['statutes']={'componentId':'0x'+bytes32(component.as_atom()).hex(),
            'launcherId':'0x'+bytes32(launcher.as_atom()).hex(),'revision':uint(revision),
            'recordKind':label,'key':'0x'+identity.hex(),
            'record':['0x'+v.hex() if isinstance(v,bytes32) else v for v in record.as_program_value()],
            'previousRoot':'0x'+bytes32(old.as_atom()).hex(),'nextRoot':'0x'+bytes32(new.as_atom()).hex()}
    elif tag=='FUND_REDEMPTION':
        _,parent,collection,settlement,asset,amount,raw,launcher,coin=exact_list(bill,9)
        from solslot_puzzles.funded_redemption_v1 import FundedRedemptionPlanV1,FundedRedemptionAllocation,canonical_redemption_allocations
        entries=tuple(FundedRedemptionAllocation(bytes32(row[0].as_atom()),bytes32(row[1].as_atom()),
            uint(row[2]),uint(row[3])) for row in (exact_list(item,4) for item in raw.as_iter()))
        if not 1<=len(entries)<=100 or entries!=canonical_redemption_allocations(entries):
            raise ValueError('redemption review requires canonical bounded allocations')
        plan=FundedRedemptionPlanV1(bytes32(collection.as_atom()),bytes32(settlement.as_atom()),
            bytes32(asset.as_atom()),uint(amount),entries).validate()
        if any(value==bytes32.zeros for value in (bytes32(coin.as_atom()),bytes32(parent.as_atom()),
                bytes32(launcher.as_atom()),plan.collection_id,plan.settlement_id,plan.payment_asset_id,
                *(entry.deed_commitment for entry in entries))):
            raise ValueError('redemption review contains an unknown commitment')
        value['redemption']={'treasuryCoinId':'0x'+coin.as_atom().hex(),'treasuryParentId':'0x'+parent.as_atom().hex(),
            'collectionId':'0x'+plan.collection_id.hex(),'settlementId':'0x'+plan.settlement_id.hex(),
            'paymentAssetId':'0x'+plan.payment_asset_id.hex(),'totalPaymentAmount':plan.total_payment_amount,
            'deedLauncherPuzzleHash':'0x'+launcher.as_atom().hex(),'allocations':[
                {'deedLauncherId':'0x'+entry.deed_launcher_id.hex(),'deedCommitment':'0x'+entry.deed_commitment.hex(),
                 'sharePpm':entry.share_ppm,'paymentAmount':entry.payment_amount} for entry in entries]}
    elif tag=='GRANT':
        _,source,raw_outputs=exact_list(bill,3)
        source_id=bytes32(source.as_atom())
        outputs=list(raw_outputs.as_iter())
        # Bound the review payload. Actual issuance and conservation are still
        # enforced by the reserve CAT and authenticated holdings transition.
        if source_id==bytes32.zeros or not 1<=len(outputs)<=32 or Program.to(outputs)!=raw_outputs:
            raise ValueError('grant review requires an exact reserve input and at most 32 outputs')
        descriptors=[];total=0
        for output in outputs:
            kind,owner,lock,amount=exact_list(output,4)
            k,identity,quantity=uint(kind),bytes32(owner.as_atom()),uint(amount)
            # Reserve allocation first creates undelivered escrow; it does not
            # create immediate holder voting weight or an arbitrary lock.
            if k not in (3,4) or identity==bytes32.zeros or lock!=Program.to([]) or not 1<=quantity<=1_000_000:
                raise ValueError('grant output must be nonvoting reserve or undelivered escrow')
            total+=quantity
            descriptors.append({'kind':k,'ownerPuzzleHash':'0x'+identity.hex(),'lockId':None,'amount':quantity})
        if total>1_000_000 or len({bytes(v) for v in outputs})!=len(outputs):
            raise ValueError('grant review has excess supply or duplicate outputs')
        value['grant']={'reserveCoinId':'0x'+source_id.hex(),'outputs':descriptors}
    else:
        raise ValueError('unsupported governance bill cannot be displayed as an opaque approval')
    return value


@dataclass(frozen=True)
class GenerationChainAnchor:
    issuance: GenesisIssuancePlan
    registry: Registry
    governance: Governance
    economic_components: tuple[EconomicComponent,...] = ()
    administrator: GenesisAdminAuthorityV3 | None = None

    def __post_init__(self):
        bindings = self.issuance.bindings()
        if self.administrator is not None:
            validate_frozen_administrator(self.administrator)
            if self.administrator.authority_launcher_id!=self.registry.administrator_id:
                raise ValueError('administrator anchor must bind the exact initial V4 recovery authority')
        if (bindings != self.governance.sgt or self.registry.generation != bindings.generation
                or self.registry.governance_id != bindings.governance_launcher_id
                or self.governance.registry_id != self.registry.launcher_id
                or self.governance.admin_id != self.registry.administrator_id
                or self.registry.nonce or self.registry.pending or self.registry.reopening
                or self.registry.pause_mask or self.registry.pause_epoch
                or self.governance.nonce or self.governance.active
                or self.governance.closed.keys or self.governance.approved.keys
                or self.governance.upgrade_reserved):
            raise ValueError('chain anchor must bind the exact initial generation')
        component = next((c for c in self.registry.components if c.component_id == self.governance.component_id), None)
        if (component is None or component.launcher_id != bindings.governance_launcher_id
                or component.kernel_hash != load_puzzle('generation_governance_v1.clsp').get_tree_hash()
                or component.module_hash != self.governance.module_hash
                or component.version != self.governance.version
                or component.compatibility != self.governance.compatibility):
            raise ValueError('governance component differs from the frozen registry')
        if len(self.economic_components)>31 or len({s.component_id for s in self.economic_components})!=len(self.economic_components):
            raise ValueError('economic anchor requires distinct bounded component authorities')
        for state in self.economic_components:
            from solslot_puzzles.generation_economic_reader import decode_initial_economic_inner
            decode_initial_economic_inner(state.inner(),generation=bindings.generation,registry_id=self.registry.launcher_id,
                governance_id=bindings.governance_launcher_id,launcher_id=state.launcher_id)
            if state.component() not in self.registry.components or state.component_id==self.governance.component_id:
                raise ValueError('economic component differs from the frozen registry')



@dataclass(frozen=True)
class SingletonHistory:
    state: object
    current: ConfirmedVaultCoin
    records: tuple[ConfirmedVaultCoin, ...]
    transitions: tuple
    parent_spend: CoinSpend

    def verified_tip(self, launcher_id, inner):
        """Exact local lineage for an explicit prepare action, not cached UI state."""
        from solslot_puzzles.generation_transactions import SingletonTip
        return SingletonTip(launcher_id,inner,self.current.coin,self.parent_spend).validate()


async def _history(provider, launcher_id, initial, inner, project) -> SingletonHistory:
    async def read(identity):
        return read_vault_coin(await provider.get_coin_record_by_name_primary('0x'+identity.hex()), identity)
    launcher = await read(launcher_id)
    if launcher.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH or not launcher.spent_height:
        raise ValueError('generation launcher is not confirmed')
    launch = _spend(await provider.get_puzzle_and_solution_primary('0x'+launcher_id.hex(), launcher.spent_height), launcher.coin)
    additions, _ = compute_additions_with_cost(launch, max_cost=5_000_000)
    expected = Coin(launcher_id, puzzle_for_singleton(launcher_id, inner(initial)).get_tree_hash(), uint64(1))
    if [coin for coin in additions if coin.amount % 2] != [expected]:
        raise ValueError('generation launch differs from its frozen initial state')
    state, records, transitions, parent = initial, [launcher], [], launch
    height = launcher.spent_height
    for _ in range(MAX_HISTORY + 1):
        record = await read(expected.name())
        if record.coin != expected or record.confirmed_height != height:
            raise ValueError('generation history lacks its exact confirmed continuation')
        records.append(record)
        if not record.spent_height:
            return SingletonHistory(state, record, tuple(records), tuple(transitions), parent)
        if len(transitions) == MAX_HISTORY:
            raise ValueError('generation history exceeds its reconciliation bound')
        spend = _spend(await provider.get_puzzle_and_solution_primary('0x'+expected.name().hex(), record.spent_height), expected)
        state, expected, detail = project(state, spend)
        parent = spend
        transitions.append(detail)
        height = record.spent_height
    raise AssertionError('history did not return or fail')


@dataclass(frozen=True)
class GenerationChainEvidence:
    registry: SingletonHistory
    governance: SingletonHistory
    holdings: SingletonHistory
    snapshots: dict[bytes32, tuple[HoldingsTree, int]]
    tickets: tuple[dict, ...]
    economic_components: dict[bytes32,SingletonHistory] = field(default_factory=dict)

    @property
    def current_records(self):
        return tuple(h.current for h in (self.registry, self.governance, self.holdings,*self.economic_components.values()))

    def public_status(self, checked_at: int) -> dict:
        registry, gov = self.registry.state, self.governance.state
        tree, sequence = self.holdings.state
        h = lambda value: '0x'+value.hex()
        totals = {kind: sum(v.amount for v in tree.holdings.values() if v.kind == kind) for kind in HoldingKind}
        closed_stakes=[{'coinId':h(identity),'ownerPuzzleHash':h(holding.owner_hash),'amount':holding.amount,
                       'proposalId':h(holding.lock_id)} for identity,holding in sorted(tree.holdings.items())
                       if holding.kind==HoldingKind.LOCKED_HOLDER and holding.lock_id in gov.closed.keys]
        from solslot_puzzles.generation_parameters import GenerationParameters
        from solslot_puzzles import load_puzzle
        from solslot_puzzles.generation_statutes import GenerationStatutes, RECORDS
        from solslot_puzzles.protocol_statutes_v1 import keyed_root
        fees=None;statutes_witnesses={};reward_authorities=[]
        for history in self.economic_components.values():
            if isinstance(history.state,GenerationStatutes):
                state=history.state
                reward_authorities.append({'statutesComponentId':h(state.component_id),
                    'statutesLauncherId':h(state.launcher_id),'assetId':h(state.permanent_rules.sols_tail_hash),
                    'revision':state.revision,'valuesHash':h(Program.to(list(state.values)).get_tree_hash()),
                    'epochSeconds':state.values[5]})
                entries={kind:() for kind in RECORDS}
                for transition in history.transitions:
                    if transition.statute_kind:entries[transition.statute_kind]=transition.statute_records
                for kind,records in entries.items():
                    if keyed_root(records)!=getattr(history.state,RECORDS[kind][0]):
                        raise ValueError('statutes record projection differs from current confirmed root')
                statutes_witnesses[h(history.state.component_id)]={kind:[
                    [h(v) if isinstance(v,bytes32) else v for v in record.as_program_value()] for record in records]
                    for kind,records in entries.items()}
            if isinstance(history.state,GenerationParameters):
                parameters=history.state.economic_parameters()
                if fees is not None:raise ValueError('multiple economic fee authorities are ambiguous')
                fees={'totalBps':parameters.exchange_fee_bps,'protocolBps':parameters.protocol_fee_bps,
                    'sgtRewardsBps':parameters.sgt_rewards_fee_bps,'authorityId':h(history.state.component_id),
                    'revision':history.state.revision}
        proposal = None
        opened=[t.after.active for t in self.governance.transitions if t.action=='OPEN']
        approved=[{'proposalId':h(p.proposal_id),**public_bill(p.bill)} for p in opened
                  if gov.action_key(p.proposal_id,p.bill) in gov.approved.keys]
        pending_upgrade=None
        if registry.pending:
            for p in opened:
                if p.bill.first().as_atom()!=b'UPGRADE':continue
                _,nonce,raw=exact_list(p.bill,3)
                plan=parse_upgrade_plan(raw)
                if registry.commitment(plan,nonce=nonce.as_int())==registry.pending[0]:
                    pending_upgrade={'proposalId':h(p.proposal_id),**public_bill(p.bill)}
            if pending_upgrade is None:
                raise ValueError('pending registry upgrade has no confirmed proposal provenance')
        if gov.active:
            active = gov.active
            opening = next(t for t in self.governance.transitions
                           if t.action == 'OPEN' and t.after.active.proposal_id == active.proposal_id)
            proposal = {'proposalId':h(active.proposal_id),**public_bill(active.bill),'eligibleHoldingsRoot':h(active.snapshot.hash),
                'eligibleSupply':active.snapshot.eligible,'requiredVotes':active.required_votes,
                'yesWeight':active.yes_weight,'ledgerSequence':active.ledger_sequence,
                'publicationIssuedAt':opening.publication_issued_at,'publicationExpiresAt':opening.publication_expires_at,
                'openedAt':active.opened_at or None,'votingClosesAt':active.voting_closes_at,
                'stage':'VOTING' if active.opened_at else 'CONFIRMING_OPENING',
                'selectionRule':'Only complete, unspent holdings from the opening snapshot can vote. '
                    'Transferred, split, merged or newly delivered outputs become eligible at the next proposal.'}
        return {'generationId':h(gov.sgt.generation),'network':'testnet11','checkedAt':checked_at,
            'active':bool(gov.active or registry.pending or registry.reopening),
            'exchangeFees':fees,
            'statutesWitnesses':statutes_witnesses,
            'rewardAuthorities':reward_authorities,
            'stateProof':{'supported':gov.version>=2 and gov.module_hash==load_puzzle('generation_extension_v2.clsp').get_tree_hash(),
                'componentId':h(gov.component_id),'moduleHash':h(gov.module_hash),'version':gov.version,
                'stateHash':h(gov.state().get_tree_hash())},
            'closedStakes':closed_stakes[:32],'closedStakeCount':len(closed_stakes),
            'closedStakesTruncated':len(closed_stakes)>32,
            'supply':{'total':tree.root.total,'distributed':tree.root.eligible,
                'reserve':totals[HoldingKind.RESERVE],'undeliveredEscrow':totals[HoldingKind.UNDELIVERED_ESCROW],
                'locked':totals[HoldingKind.LOCKED_HOLDER],
                'nextProposalQuorum':(tree.root.eligible+1)//2 if tree.root.eligible else None,
                'holdingsRoot':h(tree.root.hash),'sequence':sequence},
            'proposal':proposal,'closedProposalCount':len(gov.closed.keys),'approvedActionCount':len(gov.approved.keys),
            'approvedActions':approved[-32:],'approvedActionsTruncated':len(approved)>32,'pendingUpgrade':pending_upgrade,
            'componentEvidence':{h(identity):{'coinId':h(history.current.coin.name()),
                'confirmedHeight':history.current.confirmed_height,'transitions':len(history.transitions),
                'stateHash':h(history.state.state().get_tree_hash())} for identity,history in self.economic_components.items()},
            'components':[{'componentId':h(c.component_id),'launcherId':h(c.launcher_id),
                'kernelHash':h(c.kernel_hash),'moduleHash':h(c.module_hash),
                'version':c.version,'compatibility':c.compatibility} for c in registry.components],
            'pauseMask':registry.pause_mask,'pauseEpoch':registry.pause_epoch,'delays':list(self.tickets),
            'chainEvidence':{name:{'coinId':h(history.current.coin.name()),
                'confirmedHeight':history.current.confirmed_height,'transitions':len(history.transitions)}
                for name,history in [('registry',self.registry),('governance',self.governance),('holdings',self.holdings)]}}


async def _tickets(registry, provider):
    result = []
    for kind, pending in (('UPGRADE_ACTIVATION',registry.pending),('EMERGENCY_REOPENING',registry.reopening)):
        if not pending:continue
        commitment, identity = pending[:2]
        raw = await provider.get_coin_record_by_name_primary('0x'+identity.hex())
        if not isinstance(raw,dict):raise ValueError('delay ticket is unavailable')
        coin = Coin.from_json_dict(raw['coin'])
        if (coin.name()!=identity or coin.amount!=0 or coin.puzzle_hash!=registry.ticket_puzzle(commitment).get_tree_hash()
                or type(raw.get('timestamp')) is not int or raw['timestamp']<=0
                or type(raw.get('confirmed_block_index')) is not int or raw['confirmed_block_index']<=0
                or raw.get('spent_block_index')!=0 or raw.get('spent',False)):
            raise ValueError('delay ticket lacks exact unspent confirmation evidence')
        result.append({'kind':kind,'commitment':'0x'+commitment.hex(),'ticketId':'0x'+identity.hex(),
            'ratifiedAt':raw['timestamp'],'activationNotBefore':raw['timestamp']+86400,
            'confirmedHeight':raw['confirmed_block_index'],'scope':pending[2] if len(pending)==4 else None})
    return tuple(result)


async def current_evidence_unchanged(evidence: GenerationChainEvidence, *, provider) -> bool:
    """Cheap idle check: no puzzle downloads/replay when all tips are unchanged."""
    if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
        raise ValueError('generation reconciliation requires the primary Testnet11 node')
    if not await _records_unchanged(evidence.current_records,provider):return False
    return await _tickets(evidence.registry.state,provider)==evidence.tickets


async def _records_unchanged(records,provider):
    """Independent primary reads share a bounded pool; check every result."""
    capacity=asyncio.Semaphore(8)
    async def read(prior):
        async with capacity:
            raw=await provider.get_coin_record_by_name_primary('0x'+prior.coin.name().hex())
        return read_vault_coin(raw,prior.coin.name())==prior
    # TaskGroup propagates ExceptionGroup, which would hide the existing typed
    # ValueError/provider failures. Return exceptions and inspect every read.
    results=await asyncio.gather(*(read(record) for record in records),return_exceptions=True)
    for value in results:
        if isinstance(value,BaseException):raise value
    return all(results)


async def resolve_generation_chain(anchor: GenerationChainAnchor, *, provider) -> GenerationChainEvidence:
    async with asyncio.timeout(30):
        if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
            raise ValueError('generation reconciliation requires the primary Testnet11 node')
        def registry_project(state,spend):
            t=reconstruct_registry_successor(spend,state)
            return t.after,t.successor,t
        def governance_project(state,spend):
            t=reconstruct_governance_successor(spend,state)
            return t.after,t.successor,t
        snapshots={}
        def holdings_project(state,spend):
            tree,seq=state
            t=reconstruct_holdings_successor(spend,anchor.issuance.bindings(),tree,seq)
            if t.action=='INITIALIZE':
                _,_,inner=exact_list(Program.from_bytes(bytes(spend.solution)),3)
                if inner!=issue.ledger_initialization():
                    raise ValueError('holdings initialization differs from the fixed issuance')
            if t.action in ('SNAPSHOT','REWARD_SNAPSHOT'):
                _,_,inner=exact_list(Program.from_bytes(bytes(spend.solution)),3)
                _,args=exact_list(inner,2)
                _,proposal=exact_list(args,2)
                identity=bytes32(proposal.as_atom())
                if identity in snapshots:raise ValueError('duplicate proposal snapshot')
                snapshots[identity]=(tree,seq)
            return (t.tree,t.sequence),t.successor,t
        issue=build_initial_issuance(anchor.issuance)
        async def economic_history(initial):
            def economic_project(state,spend):
                transition=reconstruct_economic_successor(spend,state)
                return transition.after,transition.successor,transition
            return await _history(provider,initial.launcher_id,initial,lambda s:s.inner(),economic_project)
        histories=await asyncio.gather(
            _history(provider,anchor.registry.launcher_id,anchor.registry,lambda s:s.inner(),registry_project),
            _history(provider,anchor.governance.sgt.governance_launcher_id,anchor.governance,lambda s:s.inner(),governance_project),
            _history(provider,anchor.issuance.ledger_launcher_id,(issue.holdings,0),lambda s:ledger_inner(anchor.issuance.bindings(),*s),holdings_project),
            *(economic_history(initial) for initial in anchor.economic_components),return_exceptions=True)
        for history in histories:
            if isinstance(history,BaseException):raise history
        registry,governance,holdings,*economic_histories=histories
        if not holdings.transitions or holdings.transitions[0].action!='INITIALIZE':
            raise ValueError('initial SGT issuance is not confirmed')
        component=next(c for c in registry.state.components if c.component_id==governance.state.component_id)
        if (component.module_hash!=governance.state.module_hash or component.version!=governance.state.version
                or component.compatibility!=governance.state.compatibility):
            raise ValueError('registry and governance tips disagree; reconcile again')
        for transition in governance.transitions:
            if transition.action=='OPEN':
                active=transition.after.active
                snapshot=snapshots.get(active.proposal_id)
                if snapshot is None or snapshot[0].root!=active.snapshot or snapshot[1]!=active.ledger_sequence:
                    raise ValueError('governance opening does not match the authenticated holdings snapshot')
        economic={}
        for initial,history in zip(anchor.economic_components,economic_histories,strict=True):
            registered=next(c for c in registry.state.components if c.component_id==initial.component_id)
            if history.state.component()!=registered:
                raise ValueError('economic authority and registry tips disagree; reconcile again')
            economic[initial.component_id]=history
        # Re-read the complete proof on replay to reject a concurrent transition
        # or reorg. Idle polling subsequently needs only the three tip records.
        records=tuple(record for history in (registry,governance,holdings,*economic.values()) for record in history.records)
        if not await _records_unchanged(records,provider):raise ValueError('generation history changed during reconciliation')
        result=GenerationChainEvidence(registry,governance,holdings,snapshots,await _tickets(registry.state,provider),economic)
        if not await current_evidence_unchanged(result,provider=provider):
            raise ValueError('generation tips changed during reconciliation')
        return result
