"""Recover application records from exact accepted funded MINT transactions.

This worker neither signs nor broadcasts. The endpoint saved its fully
validated completion instructions before any RPC write. Only canonical exact
spends (or that exact mempool bundle) can authorize recording the result.
"""
import asyncio
import json
import logging
from chia_rs import SpendBundle
from .mint_proposals import InvalidTransition

logger = logging.getLogger(__name__)
PUBLISH_BYTES = ('smart_deed_inner_puzhash', 'eve_inner_puzhash', 'deed_full_puzhash',
    'proposal_hash', 'proposal_tracker_coin_id', 'sgt_lock_coin_id',
    'proposal_singleton_launcher_id', 'property_registry_coin_id',
    'property_registry_puzzle_hash', 'deed_launcher_id')
COLLECTION_BYTES = ('proposal_hash', 'proposal_launcher_id', 'deed_launcher_id', 'output_coin_id')


def restore_bytes(values, names):
    result = dict(values)
    for key in names:
        value = bytes.fromhex(result[key])
        if len(value) != 32:
            raise ValueError('Invalid saved MINT commitment')
        result[key] = value
    return result


def record_completion(payload, proposals, collection_factory):
    if payload['schema'] != 'solslot.mint-completion.v1' or payload['phase'] not in ('publish', 'execute'):
        raise ValueError('Unknown saved MINT completion')
    proposal_id, bundle_id = payload['proposalId'], payload['bundleId']
    proposal = proposals.get(proposal_id)
    if proposal is None or proposal.owner_pubkey.lower() != payload['owner'].lower():
        raise ValueError('Saved MINT owner or proposal differs')
    if payload['phase'] == 'publish':
        args = restore_bytes(payload['publication'], PUBLISH_BYTES)
        if proposal.state == 'DRAFT':
            try:
                proposals.set_published(proposal_id, **args, published_bundle_id=bundle_id)
            except InvalidTransition:
                pass  # The original request or another recovery may have won.
        proposal = proposals.get(proposal_id)
        if proposal.published_bundle_id != bundle_id:
            raise ValueError('MINT publication has a different recorded transaction')
        if any(getattr(proposal, key) != args[key] for key in PUBLISH_BYTES):
            raise ValueError('MINT publication has different recorded commitments')
        collection = payload.get('collection')
        if collection is not None:
            collection_factory().record_proposal_publication(
                **restore_bytes(collection, COLLECTION_BYTES), publish_bundle_id=bundle_id)
    else:
        if proposal.state in ('PROPOSED', 'VOTING', 'PASSED'):
            try:
                proposals.set_chain_executed(proposal_id, executed_bundle_id=bundle_id)
            except InvalidTransition:
                pass
        proposal = proposals.get(proposal_id)
        if proposal.executed_bundle_id != bundle_id:
            raise ValueError('MINT execution has a different recorded transaction')
        if payload.get('collectionEnabled'):
            collection_factory().record_proposal_execution(proposal_id,
                execute_bundle_id=bundle_id, actor_subject=payload['actor'])


class MintRecoveryWorker:
    def __init__(self, *, submitter, proposals, collection_factory, artifact_hash):
        self.submitter = submitter
        self.proposals = proposals
        self.collection_factory = collection_factory
        self.artifact_hash = artifact_hash
        self.task = None
        self.lock = asyncio.Lock()

    async def once(self):
        async with self.lock:
            journal = self.submitter.funding_store
            network = self.submitter.faucet.network
            after = ''
            while rows := journal.pending_completions(network, after=after):
                # A failed or old-genesis row cannot starve later work.
                after = rows[-1]['original_id']
                for row in rows:
                    await self.reconcile(row, journal, network)

    async def reconcile(self, row, journal, network):
        try:
            payload, document = json.loads(row['payload']), json.loads(row['document'])
            if payload['artifactHash'] != self.artifact_hash():
                raise ValueError('Saved MINT belongs to another genesis')
            bundle = SpendBundle.from_json_dict(document['spendBundle'])
            if payload['bundleId'] != '0x' + bundle.name().hex() or payload['bundleId'] != document['spendBundleId']:
                raise ValueError('Saved MINT bundle differs')
            observation = await self.submitter.provider.observe_exact_protocol_bundle(document['spendBundle'])
            if observation is None:
                return  # Never create or rebroadcast a transaction here.
            if observation.get('status') not in ('MEMPOOL', 'CONFIRMED'):
                raise ValueError('Saved MINT is not accepted by the source node')
            record_completion(payload, self.proposals, self.collection_factory)
            journal.complete(network, row['original_id'])
            journal.event(network, row['original_id'], 'application_recorded')
        except Exception:
            journal.event(network, row['original_id'], 'application_reconciliation_required', 'MINT_RECORDING_UNAVAILABLE')
            logger.warning('Saved MINT application recording awaits canonical source or matching application state')

    async def start(self):
        self.task = asyncio.create_task(self._run())

    async def _run(self):
        while True:
            try:
                await self.once()
            except Exception:
                logger.warning('MINT reconciliation pass unavailable; saved work retained')
            await asyncio.sleep(15)

    async def stop(self):
        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            self.task = None
