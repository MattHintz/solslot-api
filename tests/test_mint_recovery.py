from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from solslot_api.mint_proposals import MintProposalStore
from solslot_api.mint_recovery import MintRecoveryWorker, PUBLISH_BYTES, record_completion
from solslot_api.protocol_funding_store import ProtocolFundingStore
from tests.test_collection_store import verified_store
from tests.test_mint_proposals import _new_args, _publish_args
from tests.test_protocol_submission import protocol_bundle


@pytest.fixture
def saved(tmp_path):
    proposals = MintProposalStore(str(tmp_path / 'proposals.sqlite3'))
    proposal = proposals.create(**_new_args())
    bundle = protocol_bundle()
    bundle_id = '0x' + bundle.name().hex()
    journal = ProtocolFundingStore(str(tmp_path / 'funding.sqlite3'))
    document = {'spendBundle': bundle.to_json_dict(), 'spendBundleId': bundle_id}
    journal.reserve('testnet11', bundle_id, {}, document)
    publication = _publish_args()
    publication.pop('published_bundle_id')
    payload = dict(schema='solslot.mint-completion.v1', phase='publish', proposalId=proposal.id,
        owner=proposal.owner_pubkey, bundleId=bundle_id, artifactHash='synthetic-artifact',
        publication={key: value.hex() if key in PUBLISH_BYTES else value for key, value in publication.items()})
    node = SimpleNamespace(observe_exact_protocol_bundle=AsyncMock(return_value={'status': 'CONFIRMED'}))
    worker = MintRecoveryWorker(submitter=SimpleNamespace(funding_store=journal, provider=node,
        faucet=SimpleNamespace(network='testnet11')), proposals=proposals,
        collection_factory=lambda: pytest.fail('unexpected collection'), artifact_hash=lambda: 'synthetic-artifact')
    yield SimpleNamespace(payload=payload, proposals=proposals, journal=journal, node=node,
        worker=worker, bundle_id=bundle_id)
    journal.close()
    proposals.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['clear', 'transport', 'artifact', 'bundle', 'owner', 'rejected'])
async def test_unproven_or_mismatched_completions_remain_pending(saved, failure):
    if failure == 'clear':
        saved.node.observe_exact_protocol_bundle.return_value = None
    elif failure == 'transport':
        saved.node.observe_exact_protocol_bundle.side_effect = RuntimeError('private transport detail')
    elif failure == 'artifact':
        saved.payload['artifactHash'] = 'another-genesis'
    elif failure == 'owner':
        saved.payload['owner'] = '0xanother'
    elif failure == 'rejected':
        saved.node.observe_exact_protocol_bundle.return_value = {'status': 'REJECTED'}
    saved.journal.save_completion('testnet11', saved.bundle_id, saved.payload)
    if failure == 'bundle':
        # Simulate corrupt runtime storage; observation cannot authorize it.
        saved.journal.db.execute("UPDATE funded_protocol_bundles SET document=json_set(document, '$.spendBundleId', 'different')")
    await saved.worker.once()
    assert saved.proposals.get(saved.payload['proposalId']).state == 'DRAFT'
    assert len(saved.journal.pending_completions('testnet11')) == 1
    assert 'private transport detail' not in str([tuple(row) for row in saved.journal.db.execute('SELECT * FROM funded_protocol_events')])


def test_completion_cannot_replace_authorized_instructions_or_change_bundle(saved):
    with pytest.raises(ValueError, match='different funded bundle'):
        saved.journal.save_completion('testnet11', saved.bundle_id, {**saved.payload, 'bundleId': 'different'})
    saved.journal.save_completion('testnet11', saved.bundle_id, saved.payload)
    with pytest.raises(ValueError, match='immutable'):
        saved.journal.save_completion('testnet11', saved.bundle_id, {**saved.payload, 'owner': 'different'})
    with pytest.raises(ValueError, match='durable funded bundle'):
        saved.journal.save_completion('testnet11', 'missing', saved.payload)


@pytest.mark.asyncio
async def test_partial_collection_write_recovers_and_later_states_never_regress(saved):
    collection, _ = verified_store()
    collection.seal('HARBOR-17', expected_revision=2, actor_subject='0xowner')
    saved.payload['collection'] = dict(collection_id='HARBOR-17', deed_id='HARBOR-17-A',
        actor_subject='0xowner', proposal_id=saved.payload['proposalId'],
        **{key: bytes([i]).hex() * 32 for i, key in enumerate(
            ('proposal_hash', 'proposal_launcher_id', 'deed_launcher_id', 'output_coin_id'), 1)})
    saved.journal.save_completion('testnet11', saved.bundle_id, saved.payload)
    def unavailable():
        raise RuntimeError('database temporarily unavailable')
    saved.worker.collection_factory = unavailable
    await saved.worker.once()
    assert saved.proposals.get(saved.payload['proposalId']).state == 'PROPOSED'
    assert len(saved.journal.pending_completions('testnet11')) == 1
    saved.worker.collection_factory = lambda: collection
    await saved.worker.once()
    assert saved.journal.pending_completions('testnet11') == []
    proposal_id = saved.payload['proposalId']
    execution = {**saved.payload, 'phase': 'execute', 'bundleId': 'synthetic-execute',
        'actor': '0xreviewer', 'collectionEnabled': True}
    record_completion(execution, saved.proposals, lambda: collection)
    saved.proposals.set_minted(proposal_id, deed_launcher_id=bytes.fromhex(saved.payload['publication']['deed_launcher_id']))
    before = collection.get('HARBOR-17')
    record_completion(saved.payload, saved.proposals, lambda: collection)
    record_completion(execution, saved.proposals, lambda: collection)
    assert saved.proposals.get(proposal_id).state == 'MINTED'
    assert collection.get('HARBOR-17') == before
    with pytest.raises(ValueError, match='different recorded transaction'):
        record_completion({**execution, 'bundleId': 'different-execute'}, saved.proposals, lambda: collection)
    collection.close()
