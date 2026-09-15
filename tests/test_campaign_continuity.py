"""Offline campaign recovery: real SQLite, BLS and CLVM; synthetic authority/RPC.

No deployed genesis, public-chain inclusion, or admin-approval ceremony is claimed.
"""
import asyncio
from copy import deepcopy
from types import SimpleNamespace

import pytest
from chia_rs import AugSchemeMPL, Coin, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from fastapi import HTTPException

from solslot_api import presale_endpoints as p, validator_service as signer
from solslot_api.campaign_runtime import resume_campaign
from solslot_api.validator_ledger import ValidatorLedger
from solslot_api.validator_quorum import ValidatorQuorumResult
from solslot_api.voucher_issuance_worker import VoucherIssuanceWorker, VoucherIssuanceWorkerConfig
from solslot_api.faucet import Faucet
from tests.test_current_base_voucher_delivery import consensus


def hx(n):
    return '0x' + bytes([n] * 32).hex()


class CampaignNode:
    def __init__(self, faucet):
        self.records, self.spends, self.accepted = {}, {}, []
        self.lose_reply = False
        self.chain_time = 0
        self.peak_height = 30
        for n in (90, 91, 92):
            self.add(Coin(bytes32(bytes([n] * 32)), faucet.address_puzzle_hash, uint64(10)), 1)

    def add(self, coin, height):
        self.records['0x' + coin.name().hex()] = dict(coin=coin.to_json_dict(), confirmed_block_index=height,
                                                   spent_block_index=0, spent=False)

    async def get_coin_records_by_puzzle_hash(self, puzzle, **kwargs):
        return [r for r in self.records.values() if not r['spent'] and '0x' + Coin.from_json_dict(r['coin']).puzzle_hash.hex() == puzzle]

    async def get_coin_record_by_name(self, name):
        return self.records.get(name)

    async def get_puzzle_and_solution(self, name, height):
        return self.spends.get((name, height))

    def rpc(self, method, args):
        if method == 'get_network_info':
            return dict(success=True, network_name='testnet11')
        if method == 'get_blockchain_state':
            return dict(success=True, blockchain_state=dict(sync=dict(synced=True, sync_mode=False),
                peak=dict(height=self.peak_height, header_hash=hx(200+self.peak_height))))
        if method == 'get_block_record':
            height = bytes.fromhex(args['header_hash'][2:])[0] - 200
            return dict(success=True, block_record=dict(height=height, header_hash=hx(200+height),
                prev_hash=hx(199+height), timestamp=self.chain_time-(self.peak_height-height)))
        if method == 'get_coin_record_by_name':
            return dict(success=True, coin_record=self.records.get(args['name']))
        raise AssertionError(method)

    async def get_network_info(self):
        return self.rpc('get_network_info', {})

    async def get_blockchain_state(self):
        return self.rpc('get_blockchain_state', {})

    async def get_block_record(self, digest):
        return self.rpc('get_block_record', dict(header_hash=digest))

    async def push_tx(self, payload):
        bundle = SpendBundle.from_json_dict(payload)
        error, message, _ = consensus(bundle)
        assert error is None, (error, message)
        self.accepted.append(deepcopy(payload))
        if self.lose_reply:
            self.lose_reply = False
            raise TimeoutError('synthetic accepted push lost response')
        return dict(success=True, status='SUCCESS')

    def mine(self, payload, height):
        bundle = SpendBundle.from_json_dict(payload)
        for coin in bundle.additions():
            self.add(coin, height)
        for spend in bundle.coin_spends:
            name = '0x' + spend.coin.name().hex()
            self.records[name].update(spent=True, spent_block_index=height)
            self.spends[name, height] = dict(puzzle_reveal='0x' + bytes(spend.puzzle_reveal).hex(),
                                            solution='0x' + bytes(spend.solution).hex())


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    keys = [AugSchemeMPL.key_gen(bytes([n] * 32)) for n in (1, 2, 3)]
    artifact = dict(artifactHash=hx(7), puzzleHashes={'protocolTreasuryPuzzleHash': hx(5)},
                    validatorSet=dict(threshold=2, pubkeys=['0x' + bytes(k.get_g1()).hex() for k in keys]))
    monkeypatch.setattr(p, 'load_signed_public_artifact', lambda _: artifact)
    monkeypatch.setattr(p, 'load_omnichain_evidence', lambda *a, **k: SimpleNamespace(return_puzzle_hash=hx(6)))
    faucet = Faucet.from_seed_hex('01' * 32, 'testnet11')
    node = CampaignNode(faucet)
    settings = SimpleNamespace(network='testnet11', runtime_environment='test', faucet_max_spend_mojos=1000,
        zkpassport_validator_threshold=2, payment_evm_usdc_tokens={'84532': '0x' + '33' * 20},
        payment_omnichain_gateway_profile='fixture', admin_db_path=str(tmp_path / 'campaign.sqlite'))
    collection = dict(id='fixture-governed-collection', state='PUBLISHED', metadataRoot=hx(3), metadataAnchorId=hx(4),
        dossier={'offering': dict(currency='USD', royaltyPuzhash=hx(5), targetRaiseMinor=2000, royaltyBps=250)},
        deeds=[dict(deedId='fixture-deed-' + str(n), ordinal=n, deedLauncherId=hx(10+n),
                    proposalId='proposal-' + str(n), sharePpm=500000, parValueMojos=1) for n in range(2)])
    body = p.PresaleCreateRequest(collectionId=collection['id'], saleOpen=100, saleClose=200, refundDeadline=300, launchDeadline=400)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(faucet=faucet, coinset=node)))
    store = p.PresaleStore(settings.admin_db_path)
    stores = [store]
    def restart():
        fresh = p.PresaleStore(settings.admin_db_path)
        stores.append(fresh)
        return fresh
    c = SimpleNamespace(body=body, settings=settings, store=store, node=node, request=request, faucet=faucet,
                        collection=collection, collections=SimpleNamespace(get=lambda identity: dict(collection, id=identity)),
                        restart=restart, artifact=artifact, keys=keys, path=tmp_path)
    yield c
    for item in stores:
        item._conn.close()


async def create(c, store=None, body=None):
    return await p.create_presale(body or c.body, c.request, c.settings, store or c.store, c.collections)


def worker(c, store=None, authorize=None):
    return VoucherIssuanceWorker(settings=c.settings, faucet=c.faucet, coinset=c.node,
        presales=store or c.store, purchases=None, config=VoucherIssuanceWorkerConfig(enabled=True), authorize_dispatch=authorize)


def test_creation_loss_restart_replays_original_and_confirms_while_paused(campaign):
    c = campaign
    async def run():
        c.node.lose_reply = True
        with pytest.raises(HTTPException) as exc:
            await create(c)
        assert exc.value.status_code == 502
        original = c.node.accepted[0]
        series = c.store.list()[0]
        assert series['singletonLaunch']['status'] == 'AWAITING_CONFIRMATION'
        assert c.store.pending_campaign_funding_coin_ids()
        fresh = c.restart()
        resumed = await create(c, fresh)
        assert resumed['termsHash'] == series['termsHash']
        assert c.node.accepted == [original, original]
        with pytest.raises(HTTPException) as changed:
            await create(c, fresh, c.body.model_copy(update={'launch_deadline': 401}))
        assert changed.value.status_code == 409
        assert len(c.node.accepted) == 2
        c.node.mine(original, 10)
        def paused():
            raise RuntimeError('dispatch paused')
        result = await worker(c, fresh, paused).reconcile_once()
        assert result == [dict(termsHash=series['termsHash'], status='CREATION_CONFIRMED')]
        assert not fresh.pending_campaign_funding_coin_ids()
        assert fresh.get(series['termsHash'])['singletonLaunch']['status'] == 'CONFIRMED'
        assert len(c.node.accepted) == 2
        await create(c, fresh)
        assert len(c.node.accepted) == 2
    asyncio.run(run())


def test_creation_original_control_and_coin_exclusion(campaign):
    c = campaign
    async def run():
        first = await create(c)
        second = await create(c, body=c.body.model_copy(update={'collection_id': 'second-campaign'}))
        assert first['termsHash'] != second['termsHash']
        a, b = [SpendBundle.from_json_dict(x) for x in c.node.accepted]
        assert set(a.removals()).isdisjoint(b.removals())
        c.node.mine(c.node.accepted[0], 10)
        await worker(c).reconcile_once()
        await worker(c).reconcile_once()
        assert c.store.campaign_operation(first['termsHash'], 'creation')['confirmedHeight'] == 10
    asyncio.run(run())


def test_funding_exclusions_are_atomic_across_independent_store_connections(campaign):
    c = campaign
    async def run():
        series = await create(c)
        original = c.node.accepted[0]
        fresh = c.restart()
        with pytest.raises(ValueError, match='cannot compete'):
            fresh.retain_voucher_execution(series['termsHash'], 0, dict(kind='funding', spendBundle=original))
        assert fresh.pending_voucher_execution(series['termsHash'], 0) is None
        # The inverse race is rejected inside the same database write boundary.
        c.node.mine(original, 10)
        await worker(c).reconcile_once()
        # A retained fixture execution represents a competing funding claim;
        # this test does not claim to issue a voucher using a singleton launch.
        fresh.retain_voucher_execution(series['termsHash'], 0, dict(kind='funding', spendBundle=original))
        with pytest.raises(ValueError, match='retained for voucher funding'):
            fresh.retain_campaign_execution(series['termsHash'], 'creation',
                fresh.campaign_operation(series['termsHash'], 'creation')['execution'])
    asyncio.run(run())


def test_phase_refuses_unconfirmed_creation_active_lease_and_pending_execution(campaign, monkeypatch):
    c = campaign
    q = install_phase_signers(c, monkeypatch)
    async def run():
        series = await create(c)
        c.node.mine(c.node.accepted[0], 10)
        async def phase():
            return await p._submit_series_phase_transition(request=c.request, settings=c.settings, store=c.store,
                series=c.store.get(series['termsHash']), transition=p.SeriesTransition.CANCEL)
        with pytest.raises(ValueError, match='creation is not yet confirmed'):
            await phase()
        lease = c.store.claim_voucher_work('campaign', 'fixture-observer', p.time.time())
        await resume_campaign(settings=c.settings, store=c.store, node=c.node, series=c.store.get(series['termsHash']))
        with pytest.raises(ValueError, match='unfinished voucher work'):
            await phase()
        c.store.finish_voucher_work(lease, p.time.time(), 'CREATION_CONFIRMED')
        c.store.retain_voucher_execution(series['termsHash'], 0, dict(kind='issuance', fixturePending=True))
        with pytest.raises(ValueError, match='unfinished voucher work'):
            await phase()
        assert q.seen == [] and c.store.campaign_operation(series['termsHash'], 'phase') is None
        c.store.confirm_voucher_execution(series['termsHash'], 0, 'issuance')
        await phase()
        assert len(q.seen) == 1
    try:
        asyncio.run(run())
    finally:
        for ledger in q.ledgers:
            ledger.close()


def test_unconfirmed_creation_cannot_fall_through_to_ordinary_purchase(campaign, monkeypatch):
    from solslot_api.protocol_artifacts import _active_presale_terms_for_deed
    from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError
    c = campaign
    monkeypatch.setattr(p, 'get_presale_store', lambda _: c.store)
    async def run():
        series = await create(c)
        deed = bytes32.from_hexstr(series['terms']['deeds'][0]['deedLauncherId'])
        with pytest.raises(PaymentArtifactError, match='awaiting chain confirmation'):
            _active_presale_terms_for_deed(c.settings, deed)
        c.node.mine(c.node.accepted[0], 10)
        await worker(c).reconcile_once()
        assert _active_presale_terms_for_deed(c.settings, deed) == series['termsHash']
    asyncio.run(run())


@pytest.mark.parametrize('mutation', ['environment', 'genesis', 'spend', 'height'])
def test_creation_rejects_mismatched_recovery_evidence(campaign, mutation):
    c = campaign
    async def run():
        series = await create(c)
        c.node.mine(c.node.accepted[0], 10)
        if mutation == 'environment':
            c.settings.runtime_environment = 'production'
        elif mutation == 'genesis':
            c.artifact['artifactHash'] = hx(99)
        elif mutation == 'spend':
            next(iter(c.node.spends.values()))['solution'] = '0x80'
        else:
            bundle = SpendBundle.from_json_dict(c.node.accepted[0])
            c.node.records['0x' + bundle.additions()[-1].name().hex()]['confirmed_block_index'] = 11
        result = await worker(c).reconcile_once()
        assert result[0]['status'] == 'ERROR'
        assert c.store.campaign_operation(series['termsHash'], 'creation')['confirmedHeight'] is None
        assert len(c.node.accepted) == 1
    asyncio.run(run())


def install_phase_signers(c, monkeypatch):
    from chia.types.blockchain_format.program import Program
    from chia.types.coin_spend import make_spend
    ledgers = [ValidatorLedger(str(c.path / ('validator-' + str(i) + '.sqlite'))) for i in range(2)]
    monkeypatch.setattr(signer, 'load_validator_artifact', lambda _: (c.artifact, None))
    monkeypatch.setattr(signer, 'load_validator_private_key', lambda settings: c.keys[settings.signer_index])
    def fetch(settings, name, label, require_unspent=True):
        record = c.node.records[name]
        if require_unspent and record['spent']:
            raise signer.ValidatorEvidenceError('spent input')
        return record
    def spend(settings, coin, height, label):
        proof = c.node.spends['0x' + coin.name().hex(), height]
        return make_spend(coin, Program.from_bytes(bytes.fromhex(proof['puzzle_reveal'][2:])),
                          Program.from_bytes(bytes.fromhex(proof['solution'][2:])))
    monkeypatch.setattr(signer, '_fetch_coin', fetch)
    monkeypatch.setattr(signer, '_fetch_coin_spend', spend)
    seen, lose, limit = [], [False], [2]
    def settings(i):
        return SimpleNamespace(network='testnet11', roster_pubkeys=c.artifact['validatorSet']['pubkeys'], signer_index=i,
                               coinset_base_url='https://private-fixture.invalid')
    async def quorum(config, claim):
        from chia_rs import G2Element
        seen.append(claim)
        signatures = [G2Element.from_bytes(bytes.fromhex(signer.sign_voucher_series_phase_claim(
            settings(i), ledger, claim, claim.canonical_hash())[2:])) for i, ledger in enumerate(ledgers[:limit[0]])]
        if lose[0]:
            lose[0] = False
            raise TimeoutError('synthetic lost quorum response')
        return ValidatorQuorumResult((0, 1), AugSchemeMPL.aggregate(signatures), claim.canonical_hash())
    monkeypatch.setattr(p, 'collect_voucher_series_phase_quorum', quorum)
    return SimpleNamespace(ledgers=ledgers, seen=seen, lose=lose, settings=settings, limit=limit)


def test_phase_creation_through_private_signing_loss_restart_and_atomic_confirmation(campaign, monkeypatch):
    c = campaign
    q = install_phase_signers(c, monkeypatch)
    async def run():
        series = await create(c)
        c.node.mine(c.node.accepted[0], 10)
        await worker(c).reconcile_once()
        q.lose[0] = True
        with pytest.raises(TimeoutError):
            await p._submit_series_phase_transition(request=c.request, settings=c.settings, store=c.store,
                series=c.store.get(series['termsHash']), transition=p.SeriesTransition.CANCEL, cancel_reason='campaign withdrawn')
        original = c.store.campaign_operation(series['termsHash'], 'phase')
        assert original['execution'] is None
        assert c.store.get(series['termsHash'])['phaseTransition']['status'] == 'PREPARING'
        fresh = c.restart()
        c.node.lose_reply = True
        result = await worker(c, fresh).reconcile_once()
        assert result[0]['status'] == 'TIMED_OUT'
        assert q.seen[0] == q.seen[1]
        retained = fresh.campaign_operation(series['termsHash'], 'phase')['execution']
        assert retained['spendBundle'] == c.node.accepted[-1]
        assert fresh.get(series['termsHash'])['state'] == 'PRESALE'
        c.node.mine(retained['spendBundle'], 11)
        # Direct recovery bypasses only the worker retry backoff, not validation.
        result = await resume_campaign(settings=c.settings, store=fresh, node=c.node, series=fresh.get(series['termsHash']))
        assert result['status'] == 'PHASE_CONFIRMED'
        assert fresh.get(series['termsHash'])['state'] == 'CANCELED'
        assert fresh.campaign_operation(series['termsHash'], 'phase')['confirmedHeight'] == 11
        assert not fresh.pending_campaign_funding_coin_ids()
        assert len(c.node.accepted) == 2
        with pytest.raises(ValueError, match='cannot be replaced'):
            await p._submit_series_phase_transition(request=c.request, settings=c.settings, store=fresh,
                series=fresh.get(series['termsHash']), transition=p.SeriesTransition.CANCEL, cancel_reason='changed reason')
    try:
        asyncio.run(run())
    finally:
        for ledger in q.ledgers:
            ledger.close()


def install_governed_deeds(c, monkeypatch):
    """Synthetic executed governance records with real DID-bound launcher spends."""
    from chia.types.blockchain_format.program import Program
    from solslot_puzzles import load_puzzle
    from solslot_puzzles.protocol_deployment import singleton_struct
    from solslot_api import mint_endpoints
    c.artifact['launcherIds'] = {'did': hx(8)}
    puzzle = load_puzzle('singleton_launcher_with_did.clsp').curry(singleton_struct(bytes32.from_hexstr(hx(8))))
    proposals = {}
    for n, deed in enumerate(c.collection['deeds']):
        coin = Coin(bytes32.from_hexstr(hx(30+n)), puzzle.get_tree_hash(), uint64(1))
        name, child_hash = '0x' + coin.name().hex(), hx(40+n)
        c.node.add(coin, 2)
        c.node.records[name].update(spent=True, spent_block_index=3)
        c.node.spends[name, 3] = dict(puzzle_reveal='0x' + bytes(puzzle).hex(),
            solution='0x' + bytes(Program.to([bytes32.from_hexstr(hx(60)), bytes32.from_hexstr(child_hash), 1, []])).hex())
        deed.update(deedLauncherId=name, proposalState='EXECUTED', executeBundleId=hx(50+n))
        proposals[deed['proposalId']] = SimpleNamespace(state='EXECUTED', deed_launcher_id=coin.name(),
            deed_full_puzhash=bytes32.from_hexstr(child_hash), executed_bundle_id=hx(50+n))
    monkeypatch.setattr(mint_endpoints, 'get_mint_proposal_store', lambda _: SimpleNamespace(get=proposals.get))


def test_launch_recovers_exact_private_signatures_after_freshness_expires(campaign, monkeypatch):
    c = campaign
    install_governed_deeds(c, monkeypatch)
    q = install_phase_signers(c, monkeypatch)
    clock = [250]
    monkeypatch.setattr(p.time, 'time', lambda: clock[0])
    async def run():
        series = await create(c)
        c.node.mine(c.node.accepted[0], 10)
        await worker(c).reconcile_once()
        c.collection['state'] = 'EXECUTED'
        q.lose[0] = True
        with pytest.raises(TimeoutError):
            await p._submit_series_phase_transition(request=c.request, settings=c.settings, store=c.store,
                series=c.store.get(series['termsHash']), transition=p.SeriesTransition.LAUNCH, collection=c.collection)
        claim = q.seen[0]
        clock[0] = 370
        fresh = ValidatorLedger(str(c.path / 'unsigned-validator.sqlite'))
        try:
            with pytest.raises(signer.ValidatorEvidenceError, match='stale'):
                signer.sign_voucher_series_phase_claim(q.settings(0), fresh, claim, claim.canonical_hash())
        finally:
            fresh.close()
        outcome = await worker(c, c.restart()).reconcile_once()
        assert outcome[0]['status'] == 'PHASE_SUBMITTED'
        assert q.seen == [claim, claim]
        c.node.mine(c.node.accepted[-1], 11)
        outcome = await worker(c).reconcile_once()
        assert outcome[0]['status'] == 'PHASE_CONFIRMED'
        assert c.store.get(series['termsHash'])['launchedAt'] == 250
        assert c.store.get(series['termsHash'])['state'] == 'LIVE'
        # Exact signatures remain retrievable after the input is spent. Neither
        # altered evidence nor corrupted signatures can use this recovery path.
        signature = signer.sign_voucher_series_phase_claim(q.settings(0), q.ledgers[0], claim, claim.canonical_hash())
        assert signature
        altered = claim.model_copy(update={'launch_anchor': 251})
        with pytest.raises(signer.ValidatorEvidenceError, match='canonical'):
            signer.sign_voucher_series_phase_claim(q.settings(0), q.ledgers[0], altered, claim.canonical_hash())
        q.ledgers[0]._conn.execute('UPDATE voucher_series_phase_signatures SET signature=?', ('0x'+'00'*96,))
        with pytest.raises(signer.ValidatorEvidenceError, match='recovery failed'):
            signer.sign_voucher_series_phase_claim(q.settings(0), q.ledgers[0], claim, claim.canonical_hash())
    try:
        asyncio.run(run())
    finally:
        for ledger in q.ledgers:
            ledger.close()


@pytest.mark.parametrize('signed_count,lost_push', [(0, False), (1, False), (2, False), (2, True)])
def test_expired_launch_is_preserved_and_fresh_cancel_recovers_without_reusing_authority(campaign, monkeypatch, signed_count, lost_push):
    import json
    import httpx
    from solslot_api import campaign_expiry
    c = campaign
    install_governed_deeds(c, monkeypatch)
    q = install_phase_signers(c, monkeypatch)
    clock = [250]
    monkeypatch.setattr(p.time, 'time', lambda: clock[0])
    client = httpx.Client
    transport = httpx.MockTransport(lambda request: httpx.Response(200,
        json=c.node.rpc(request.url.path[1:], json.loads(request.content))))
    monkeypatch.setattr(campaign_expiry.httpx, 'Client', lambda **kwargs: client(transport=transport, **kwargs))
    async def run():
        series = await create(c)
        c.node.mine(c.node.accepted[0], 10)
        await worker(c).reconcile_once()
        c.collection['state'] = 'EXECUTED'
        q.limit[0], q.lose[0], c.node.lose_reply = signed_count, not lost_push, lost_push
        with pytest.raises(TimeoutError):
            await p._submit_series_phase_transition(request=c.request, settings=c.settings, store=c.store,
                series=c.store.get(series['termsHash']), transition=p.SeriesTransition.LAUNCH, collection=c.collection)
        original = c.store.campaign_operation(series['termsHash'], 'phase')
        original_signatures = [l.recover_voucher_series_phase(q.seen[0].canonical_hash(), signer.canonical_voucher_series_phase_claim_json(q.seen[0])) for l in q.ledgers]
        assert sum(value is not None for value in original_signatures) == signed_count
        assert bool(original['execution']) == lost_push
        # No local clock jump can authorize a new attempt. The private and
        # coordinator observers require the same mature canonical clock.
        clock[0] = 852
        c.node.chain_time = 851  # Three-deep transaction time is only 849.
        q.limit[0] = 2
        outcome = await worker(c).reconcile_once()
        assert c.store.campaign_operation(series['termsHash'], 'phase') is not None
        assert c.store._conn.execute('SELECT COUNT(*) FROM campaign_phase_history').fetchone()[0] == 0
        c.node.chain_time = 852
        result = await resume_campaign(settings=c.settings, store=c.store, node=c.node,
                                       series=c.store.get(series['termsHash']))
        assert result['status'] == 'PHASE_EXPIRED'
        assert c.store.pending_campaign_operation(series['termsHash']) is None
        archived = c.store._conn.execute('SELECT * FROM campaign_phase_history').fetchone()
        # A quorum may have become recoverable while the chain was before
        # expiry. The archive must preserve whichever exact bytes were sealed.
        saved = json.loads(archived['operation_json'])
        assert saved['preparation'] == original['preparation'] and saved['intent'] == original['intent']
        assert json.loads(archived['expiry_proof_json'])['consensusDeadline'] == 850
        if lost_push:
            assert saved['execution'] == original['execution']
        assert [l.recover_voucher_series_phase(q.seen[0].canonical_hash(), signer.canonical_voucher_series_phase_claim_json(q.seen[0])) for l in q.ledgers] == original_signatures
        # Fresh governance cancellation can now sign the still-unspent input.
        await p._submit_series_phase_transition(request=c.request, settings=c.settings, store=c.store,
            series=c.store.get(series['termsHash']), transition=p.SeriesTransition.CANCEL, cancel_reason='Fresh authorized cancellation')
        c.node.mine(c.node.accepted[-1], 31)
        result = await resume_campaign(settings=c.settings, store=c.store, node=c.node,
                                       series=c.store.get(series['termsHash']))
        assert result['status'] == 'PHASE_CONFIRMED' and c.store.get(series['termsHash'])['state'] == 'CANCELED'
        assert [l._conn.execute('SELECT COUNT(*) FROM voucher_series_phase_retry_signatures').fetchone()[0] for l in q.ledgers] == [int(i < signed_count) for i in range(2)]
    try:
        asyncio.run(run())
    finally:
        for ledger in q.ledgers:
            ledger.close()
