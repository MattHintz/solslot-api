"""Current-chain mint publication context and owner-plus-one authorization.

HTTP operation approvals and CHIP-0037 identity approvals are distinct. The
identity actions below additionally bind the exact wallet-authorized mint
bundle and every current singleton input. No company-reserve spend is used.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v3_driver import (
    AUTHORITY_LAUNCHER_AMOUNT, IDENTITY_LAUNCHER_AMOUNTS,
    build_authority_operational_mips_spend, build_identity_operational_action,
    build_identity_operational_solution, build_operational_solution,
)
from solslot_puzzles.eip712_helpers import build_eip712_member_solution
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.protocol_statutes_driver import (
    build_governance_evidence_spend, make_inner_puzzle as make_statutes_inner,
)
from solslot_puzzles.sgt_driver import (
    proposal_tracker_v2_inner_puzzle, sgt_free_inner_mod, sgt_locked_inner_mod,
)

from .admin_authority_v3 import build_admin_authority_v3_snapshot, load_live_singleton_context
from .admin_key_changes import (
    _assert_full_puzzle_hash, _authority_inner_from_snapshot, _current_identity_vaults,
    _genesis_authority_from_artifact, _singleton_spend, _verified_evidence_context,
)
from .governance_publisher import (
    _action, _b32, _hex32, _idle_tracker_from_parent, _mapping,
    _publication_delegated_puzzle,
)
from .sols_market import _artifact_permanent_rules, _statutes_snapshot
from .sols_swaps import _required_singleton_tip


@dataclass(frozen=True)
class MintPublicationContext:
    artifact: Mapping[str, Any]
    snapshot: Any
    authority: Any
    authority_inner: Program
    identities: tuple[Any, ...]
    authority_context: Any
    identity_contexts: tuple[Any, ...]
    tracker_launcher: bytes32
    tracker_context: Any
    tracker_inner: Program
    statutes_context: Any
    statutes_inner: Program
    statutes: Any

    @property
    def evidence(self) -> Program:
        return Program.to([self.authority_inner.get_tree_hash(),
            self.statutes_inner.get_tree_hash(), list(self.statutes.parameters.as_tuple())])

    @property
    def commitment(self) -> bytes32:
        return bytes32(Program.to([
            b'SOLSLOT_MINT_CONTEXT_V1', self.authority_context.coin.name(),
            [item.coin.name() for item in self.identity_contexts],
            self.tracker_context.coin.name(), self.statutes_context.coin.name(),
            self.evidence,
        ]).get_tree_hash())

    def to_wire(self, *, deadline: int) -> dict:
        lineage = lineage_proof_for_coinsol(self.tracker_context.parent_spend)
        coin = self.tracker_context.coin
        return {
            'contextHash': _hex32(self.commitment),
            'trackerLauncherId': _hex32(self.tracker_launcher),
            'trackerCoin': {'parentCoinInfo': _hex32(coin.parent_coin_info),
                            'puzzleHash': _hex32(coin.puzzle_hash), 'amount': str(coin.amount)},
            'trackerInnerPuzzleHex': '0x' + bytes(self.tracker_inner).hex(),
            'lineageProof': {'parentName': _hex32(lineage.parent_name),
                'amount': str(lineage.amount),
                **({'innerPuzzleHash': _hex32(lineage.inner_puzzle_hash)}
                   if lineage.inner_puzzle_hash is not None else {})},
            'proposalEvidenceHex': '0x' + bytes(self.evidence).hex(),
            'parameters': [str(value) for value in self.statutes.parameters.as_tuple()],
            'votingDeadline': deadline,
        }


async def load_mint_publication_context(*, provider, settings, genesis_store) -> MintPublicationContext:
    artifact, evidence, _ = await _verified_evidence_context(settings)
    plan = _mapping(artifact.get('genesisPlan', artifact), 'genesisPlan')
    snapshot = await build_admin_authority_v3_snapshot(artifact=artifact, provider=provider)
    if not snapshot.chain_verified or snapshot.current_coin_id is None:
        raise ValueError('Authority V3 is not confirmed on Testnet11')
    if snapshot.pending:
        raise ValueError('administrator key recovery is active; protocol writes are frozen')
    authority = _genesis_authority_from_artifact(artifact)
    identities = _current_identity_vaults(artifact=artifact, evidence=evidence,
        store=genesis_store, authority=authority)
    authority_inner = _authority_inner_from_snapshot(snapshot)
    authority_context = await load_live_singleton_context(provider=provider,
        launcher_id=snapshot.launcher_id)
    identity_contexts = tuple([await load_live_singleton_context(provider=provider,
        launcher_id=snapshot.identities[slot].launcher_id) for slot in range(3)])
    _assert_full_puzzle_hash(context=authority_context,
        launcher_id=authority.authority_launcher_id, inner_puzzle=authority_inner, label='Authority V3')
    for slot, identity in enumerate(identities):
        _assert_full_puzzle_hash(context=identity_contexts[slot], launcher_id=identity.launcher_id,
            inner_puzzle=identity.custody_reveal, label=f'administrator identity {slot + 1}')
    launchers = _mapping(plan.get('launcherIds'), 'launcherIds')
    puzzles = _mapping(plan.get('puzzleHashes'), 'puzzleHashes')
    parameters = _mapping(plan.get('protocolParameters'), 'protocolParameters')
    governance = _mapping(artifact.get('governanceStruct'), 'governanceStruct')
    tracker_launcher = _b32(launchers.get('governance'), 'governance launcher')
    statutes_launcher = _b32(launchers.get('statutes'), 'statutes launcher')
    statutes_tip = await _required_singleton_tip(provider, _hex32(statutes_launcher), 'protocol statutes')
    statutes = await _statutes_snapshot(provider, statutes_tip, artifact)
    statutes_inner = make_statutes_inner(singleton_struct=singleton_struct(statutes_launcher),
        governance_singleton_struct=singleton_struct(tracker_launcher),
        permanent_rules=_artifact_permanent_rules(artifact), state=statutes.state)
    statutes_context = await load_live_singleton_context(provider=provider,
        launcher_id=_hex32(statutes_launcher))
    if _hex32(statutes_context.coin.name()) != statutes.live_coin_id:
        raise ValueError('statutes changed during mint publication review')
    _assert_full_puzzle_hash(context=statutes_context, launcher_id=statutes_launcher,
        inner_puzzle=statutes_inner, label='protocol statutes')
    sgt_tail = _b32(artifact.get('sgtTailHash') or
        _mapping(plan.get('permanentRules'), 'permanentRules').get('sgtTailHash'), 'SGT tail')
    tracker_inner = proposal_tracker_v2_inner_puzzle(singleton_struct(tracker_launcher),
        sgt_free_inner_mod().get_tree_hash(), sgt_locked_inner_mod().get_tree_hash(),
        CAT_MOD.get_tree_hash(), sgt_tail, _b32(puzzles.get('didFull'), 'DID full puzzle hash'),
        singleton_struct(_b32(launchers.get('pool'), 'pool launcher')),
        singleton_struct(_b32(launchers.get('adminAuthority'), 'authority launcher')),
        singleton_struct(statutes_launcher), int(parameters.get('quorumBps')),
        int(parameters.get('votingWindowSeconds')), int(parameters.get('sgtTotalSupply')),
        int(parameters.get('minProposalStake')),
        bytes.fromhex(str(governance.get('mintExecuteCosignerPubkey')).removeprefix('0x')))
    if tracker_inner.get_tree_hash() != _b32(puzzles.get('governanceInner'), 'governance inner hash'):
        raise ValueError('governance tracker does not match signed release evidence')
    tracker_context = await load_live_singleton_context(provider=provider,
        launcher_id=_hex32(tracker_launcher))
    tracker_inner = _idle_tracker_from_parent(tracker_context, tracker_inner, tracker_launcher)
    _assert_full_puzzle_hash(context=tracker_context, launcher_id=tracker_launcher,
        inner_puzzle=tracker_inner, label='idle governance tracker')
    return MintPublicationContext(artifact, snapshot, authority, authority_inner, identities,
        authority_context, identity_contexts, tracker_launcher, tracker_context, tracker_inner,
        statutes_context, statutes_inner, statutes)


def mint_authorization_actions(context: MintPublicationContext, *, owner_bundle: SpendBundle,
    proposal_hash: bytes32, deadline: int):
    original = _publication_delegated_puzzle(proposal_hash, deadline)
    conditions = list(original.rest().as_iter())
    binding = hashlib.sha256(b'SOLSLOT_MINT_PUBLICATION_V1' + bytes(context.commitment)
        + bytes(owner_bundle.name())).digest()
    delegated = Program.to((1, [*conditions, [62, binding]]))
    actions = tuple(_action(slot=slot, identity=context.identities[slot],
        coin_id=context.identity_contexts[slot].coin.name(),
        delegated_puzzle_hash=build_identity_operational_action(identity=context.identities[slot],
            current_authority_inner_puzzle=context.authority_inner,
            authority_delegated_puzzle=delegated).get_tree_hash(),
        proposal_hash=proposal_hash, voting_deadline=deadline, purpose='MINT_PUBLICATION') for slot in range(3))
    return delegated, actions


def build_mint_authorization_spends(context: MintPublicationContext, *, delegated: Program,
    actions, signatures: Mapping[int, Mapping[str, str]], coadmin_slot: int):
    if coadmin_slot not in (1, 2):
        raise ValueError('mint requires the owner and one coadministrator')
    mips = build_authority_operational_mips_spend(authority=context.authority,
        current_authority_inner_puzzle=context.authority_inner, current_identities=context.identities,
        current_identity_coin_ids=tuple(item.coin.name() for item in context.identity_contexts),
        authority_delegated_puzzle=delegated, coadmin_slot=coadmin_slot)
    solution = build_operational_solution(my_amount=AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=context.snapshot.authority_version + 1,
        mips_reveal=mips.reveal, mips_solution=mips.solution,
        authority_delegated_puzzle=delegated, identity_records=mips.identity_records)
    spends = [_singleton_spend(context=context.authority_context, inner_puzzle=context.authority_inner,
        inner_solution=solution, amount=AUTHORITY_LAUNCHER_AMOUNT)]
    for slot in mips.selected_slots:
        action = actions[slot]
        signed = signatures.get(slot)
        if signed is None or signed['action_id'] != action.action_id:
            raise ValueError('mint identity approval is missing or stale')
        member = build_eip712_member_solution(network='testnet11',
            coin_id=context.identity_contexts[slot].coin.name(),
            delegated_puzzle_hash=_b32(action.delegated_puzzle_hash, 'identity delegated hash'),
            compressed_pubkey=context.identities[slot].daily_compressed_pubkey,
            signature=bytes.fromhex(signed['signature'].removeprefix('0x')))
        spends.append(_singleton_spend(context=context.identity_contexts[slot],
            inner_puzzle=context.identities[slot].custody_reveal,
            inner_solution=build_identity_operational_solution(identity=context.identities[slot],
                current_authority_inner_puzzle=context.authority_inner,
                current_identity_coin_id=context.identity_contexts[slot].coin.name(),
                daily_member_solution=member, authority_delegated_puzzle=delegated),
            amount=IDENTITY_LAUNCHER_AMOUNTS[slot]))
    statutes = build_governance_evidence_spend(my_id=context.statutes_context.coin.name(),
        my_inner_puzzle_hash=context.statutes_inner.get_tree_hash(),
        my_amount=int(context.statutes_context.coin.amount), parameters=context.statutes.parameters)
    spends.append(_singleton_spend(context=context.statutes_context, inner_puzzle=context.statutes_inner,
        inner_solution=statutes.inner_solution, amount=int(context.statutes_context.coin.amount)))
    return spends


@dataclass(frozen=True)
class MintAuthorizationBuild:
    context: MintPublicationContext
    owner_bundle: SpendBundle
    canonical: Any
    delegated: Program
    actions: tuple[Any, ...]
    body: Any


async def prepare_mint_authorization(*, binding: Mapping[str, Any], created_by: str,
    provider, settings, genesis_store, now: int | None = None) -> MintAuthorizationBuild:
    """Re-derive an HTTP-approved wallet package against current confirmed inputs."""
    import time
    from types import SimpleNamespace
    from chia.wallet.wallet_spend_bundle import WalletSpendBundle
    from solslot_puzzles.mint_publish_driver import build_tracker_propose_coin_spend
    from solslot_puzzles.vault_v2_driver import SPEND_AUTHORIZE_SGT_LOCK
    from .mint_endpoints import (
        PublishMintBundleRequest, get_mint_proposal_store, require_mint_writes,
        _parse_spend_bundle, _parse_bytes32, _validate_collection_publish_context,
    )
    from .mint_chain_validation import validate_publish_bundle, _single_spend_for_launcher, _parse_tracker_propose
    from .mint_stake import build_mint_stake
    from .sols_swaps import _require_inputs_clear, _verify_aggregate_signature

    require_mint_writes(settings)
    body = PublishMintBundleRequest.model_validate(binding.get('body'))
    proposal_id = body.proposal_id
    if (not proposal_id or binding.get('method') != 'POST' or binding.get('query')
        or binding.get('ifMatch') or binding.get('path') not in
        ('/admin/committee/propose', f'/admin/mint/{proposal_id}/publish')):
        raise ValueError('mint approval must bind the exact publication route and proposal')
    if body.stake_vault_launcher_id is None or body.publication_context_hash is None:
        raise ValueError('mint approval requires a prepared vault stake and current publication context')
    context = await load_mint_publication_context(provider=provider, settings=settings,
        genesis_store=genesis_store)
    if context.commitment != _b32(body.publication_context_hash, 'mint publication context'):
        raise ValueError('mint publication package is stale; prepare and review it again')
    bundle = _parse_spend_bundle(body.spend_bundle)
    metadata = body.proposal_metadata
    proposal = get_mint_proposal_store(settings).get(proposal_id)
    if proposal is None:
        # Preparation does not import or mutate the draft. Submission retains the
        # existing authenticated import and sealed collection checks.
        proposal = SimpleNamespace(id=proposal_id, state='DRAFT', owner_pubkey=created_by,
            par_value=metadata.par_value_mojos, asset_class=metadata.asset_class_name,
            property_id=metadata.property_id, collection_id=metadata.collection_id,
            share_ppm=metadata.share_ppm,
            jurisdiction=bytes.fromhex(metadata.jurisdiction.removeprefix('0x')).decode('utf-8'),
            royalty_puzhash=_parse_bytes32(metadata.royalty_puzhash, 'royalty puzzle hash'),
            royalty_bps=metadata.royalty_bps, quorum_required=metadata.quorum_threshold)
    if proposal.state != 'DRAFT' or proposal.owner_pubkey.lower() != created_by.lower():
        raise ValueError('only the original proposer can prepare this draft for publication')
    canonical = validate_publish_bundle(bundle=bundle, metadata=metadata, proposal=proposal,
        artifact=dict(context.artifact), authenticated_owner=created_by,
        stake_vault_launcher_id=_b32(body.stake_vault_launcher_id, 'stake vault'), owner_package=True,
        current_admin_pubkeys=tuple(bytes(identity.daily_compressed_pubkey) for identity in context.identities))
    _validate_collection_publish_context(settings=settings, metadata=metadata,
        claims=SimpleNamespace(sub=created_by), canonical=canonical,
        proposal_id=proposal_id, artifact=dict(context.artifact))
    timestamp = int(time.time()) if now is None else now
    if not timestamp < canonical.voting_deadline <= timestamp + context.statutes.parameters.voting_window_seconds:
        raise ValueError('mint publication deadline is expired or exceeds current statutes')
    tracker_spend = _single_spend_for_launcher(bundle, context.tracker_launcher)
    proposal_hash, bill, amount, deadline = _parse_tracker_propose(tracker_spend)
    vault_launcher = _b32(body.stake_vault_launcher_id, 'stake vault')
    vault_spend = _single_spend_for_launcher(bundle, vault_launcher)
    outer = list(Program.from_bytes(bytes(vault_spend.solution)).as_iter())
    inner = list(outer[2].as_iter()) if len(outer) == 3 else []
    if len(inner) != 5 or inner[3].as_int() != SPEND_AUTHORIZE_SGT_LOCK:
        raise ValueError('mint vault spend must authorize only the exact SGT lock')
    params = list(inner[4].as_iter())
    if len(params) != 5:
        raise ValueError('mint vault SGT authorization is malformed')
    signature_data = params[4].as_atom()
    stake = await build_mint_stake(context=context, provider=provider, settings=settings,
        vault_launcher_id=body.stake_vault_launcher_id, stake_amount=amount,
        proposal_hash=proposal_hash, deadline=deadline, signature_data=signature_data or None)
    if stake.vault_auth_type == 'chia_bls' and signature_data:
        raise ValueError('BLS vault owner signature belongs in the aggregate signature')
    actual = {bytes(spend.coin.name()): spend for spend in bundle.coin_spends}
    if any(actual.get(bytes(spend.coin.name())) != spend for spend in stake.bundle.coin_spends):
        raise ValueError('mint stake spends differ from the exact current vault and CAT lineage')
    expected_tracker = build_tracker_propose_coin_spend(tracker_coin=context.tracker_context.coin,
        tracker_inner_puzzle=context.tracker_inner, tracker_launcher_id=context.tracker_launcher,
        lineage_proof=lineage_proof_for_coinsol(context.tracker_context.parent_spend),
        proposal_hash=proposal_hash, bill_operation=bill, voter_inner_puzzle_hash=stake.owner_inner_hash,
        first_vote_amount=amount, voting_deadline=deadline, proposal_evidence=context.evidence)
    if tracker_spend != expected_tracker:
        raise ValueError('mint tracker spend differs from current authority, statutes or vault stake')
    _verify_aggregate_signature(WalletSpendBundle(bundle.coin_spends, bundle.aggregated_signature), settings.network)
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
    await _require_inputs_clear(provider, tuple(spend.coin for spend in bundle.coin_spends
        if spend.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH))
    delegated, actions = mint_authorization_actions(context, owner_bundle=bundle,
        proposal_hash=proposal_hash, deadline=deadline)
    return MintAuthorizationBuild(context, bundle, canonical, delegated, actions, body)
