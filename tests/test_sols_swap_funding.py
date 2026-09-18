"""Private fee holds and exact promotion before any provider broadcast."""
from dataclasses import replace
import json
import hashlib
import sqlite3
from types import SimpleNamespace

import pytest
from chia_rs import Coin, SpendBundle
from fastapi import HTTPException

from solslot_api import sols_swaps as swaps
from solslot_api import sols_swap_store as stores
from solslot_api import sols_swap_funding as funding
from solslot_api.sols_swap_store import SolsSwapStore
from solslot_api.sols_swaps import _funding_binding as real_binding
from tests import test_sols_swaps as fixtures
from tests.test_sols_swaps import funding_runtime
from tests.test_sols_swap_execution import signed_case, consensus

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('evm', [False, True])
async def test_hold_precedes_owner_completion_and_only_exact_funding_is_pushed(monkeypatch, tmp_path, reverse, evm):
    request, body, path, loader = await signed_case(monkeypatch, tmp_path, reverse=reverse, evm=evm)
    store = SolsSwapStore(path)
    held = store.funding(body.operation_hash)
    review = held['review']
    private = SpendBundle.from_json_dict(held['fundingBundle'])
    assert store.get(body.operation_hash).transaction_id is None
    assert store.reserved_input_coin_ids() == (review['feeCoinId'],)
    context = await getattr(swaps, loader)()
    again = await swaps.prepare_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER),
        swaps.PrepareSolsSwapRequest(direction=body.direction, deedLauncherId=body.deed_launcher_id), request, fixtures._settings())
    public = again.model_dump(by_alias=True)
    assert public['fundingEvidence'] == {**review, 'reservationHash': held['reservationHash'],
        'reservationReviewJson': funding.canonical(review)}
    assert json.loads(public['fundingEvidence']['reservationReviewJson']) == review
    assert '0x'+hashlib.sha256(public['fundingEvidence']['reservationReviewJson'].encode()).hexdigest() == held['reservationHash']
    assert held['fundingBundle']['aggregated_signature'].removeprefix('0x') not in json.dumps(public)
    assert 'fundingBundle' not in json.dumps(public)
    assert public['fundingEvidence']['fundingCoinSpend']['coin']['amount'].isdecimal()
    assert review['costUpperBound'] == 11_000_000_000
    assert review['ownerAuthorization'] == 'PENDING' and review['consensusValidated'] is False
    assert review['backingMojos'] == str(context.receipt.deed_to_sols_quote.fresh_sols_mojos_minted if reverse else 0)
    async def forbidden(*args, **kwargs):
        raise AssertionError('completion cannot select a replacement funding coin')
    monkeypatch.setattr(request.app.state.protocol_submitter, '_select_fee_coin', forbidden)
    monkeypatch.setattr(request.app.state.protocol_submitter.faucet, 'sign_delegated_spend', forbidden)
    completed = await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    bundle = SpendBundle.from_json_dict(request.app.state.protocol_submitter.provider.pushed)
    consensus(bundle)
    estimates = request.app.state.protocol_submitter.provider.estimates
    assert len(estimates) == 2
    assert all(item == dict(cost=11_000_000_000, require_primary=True) for item in estimates)
    assert private.coin_spends[0] in bundle.coin_spends
    assert completed.fee_mojos == review['feeMojos']
    assert SolsSwapStore(path).execution(body.operation_hash)['fundingReservationHash'] == body.funding_reservation_hash


@pytest.mark.parametrize('mutation', ['missing-hash', 'wrong-hash', 'session', 'release', 'policy', 'candidate'])
async def test_changed_review_is_rejected_before_dispatch(monkeypatch, tmp_path, funding_runtime, mutation):
    request, body, path, loader = await signed_case(monkeypatch, tmp_path, evm=True)
    if mutation == 'missing-hash':
        body = body.model_copy(update={'funding_reservation_hash': None})
    elif mutation == 'wrong-hash':
        body = body.model_copy(update={'funding_reservation_hash': '0x'+'f'*64})
    elif mutation == 'session':
        request.app.state.funding_session = 'another-session'
    elif mutation == 'release':
        monkeypatch.setattr(swaps, '_funding_binding', lambda *args: {**funding_runtime(*args), 'apiCommit':'c'*40})
    elif mutation == 'policy':
        submitter = request.app.state.protocol_submitter
        submitter.policy = replace(submitter.policy, target_seconds=900)
    else:
        context = await getattr(swaps, loader)()
        changed = replace(context, vault_coin=Coin(fixtures._b32(191), context.vault_coin.puzzle_hash, context.vault_coin.amount))
        async def changed_context(**kwargs): return changed
        monkeypatch.setattr(swaps, loader, changed_context)
    with pytest.raises(HTTPException) as error:
        await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    assert error.value.status_code == 409
    assert not hasattr(request.app.state.protocol_submitter.provider, 'pushed')
    assert SolsSwapStore(path).execution(body.operation_hash) is None


async def test_fee_increase_rejects_without_changing_reserved_input_or_fee(monkeypatch, tmp_path):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    before = SolsSwapStore(path).funding(body.operation_hash)
    async def higher(*, target_times, **kwargs): return dict(target_times=target_times, estimates=[421])
    request.app.state.protocol_submitter.provider.get_fee_estimate = higher
    with pytest.raises(HTTPException, match='reserved fee is insufficient'):
        await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    assert SolsSwapStore(path).funding(body.operation_hash) == before
    assert not hasattr(request.app.state.protocol_submitter.provider, 'pushed')


async def test_policy_change_across_estimate_await_rejects_promotion(monkeypatch, tmp_path):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    submitter = request.app.state.protocol_submitter
    async def changed(*, target_times, **kwargs):
        submitter.policy = replace(submitter.policy, maximum_mojos=999)
        return dict(target_times=target_times, estimates=[420])
    submitter.provider.get_fee_estimate = changed
    with pytest.raises(HTTPException, match='authorization changed'):
        await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    assert SolsSwapStore(path).execution(body.operation_hash) is None
    assert not hasattr(submitter.provider, 'pushed')


@pytest.mark.parametrize('expired', [False, True])
async def test_replacement_defeats_stale_in_memory_completion(monkeypatch, tmp_path, expired):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    original = swaps._seal_swap_execution
    held = SolsSwapStore(path).funding(body.operation_hash)
    # Keep the independently longer-lived authenticated session unchanged
    # while advancing only the quote/hold clock.
    monkeypatch.setattr(swaps, '_funding_binding', lambda *args: held['review']['binding'])
    replacement = []
    def race(*args, **kwargs):
        promote = original(*args, **kwargs)
        async def before_push(prepared):
            # The original complete coroutine already holds valid signatures
            # and exact fee bytes. Expiry/reallocation occurs before SQL promotion.
            now = body.quote_expires_at + 1 if expired else body.quote_expires_at - 10
            monkeypatch.setattr(stores, 'time', lambda: now)
            monkeypatch.setattr(funding, 'time', lambda: now)
            assert SolsSwapStore(path).reserved_input_coin_ids() == (() if expired else (held['review']['feeCoinId'],))
            monkeypatch.setattr(fixtures, 'QUOTE_EXPIRES', now + 60)
            new_context = fixtures._fixture().context
            # Use the same canonical fee builder without trying to reacquire
            # the already held in-process funding guard; a second coordinator
            # has its own guard and must still contend through SQLite.
            other = fixtures.FakeProtocolSubmitter()
            other_request = fixtures._request(fixtures.FakeNode(), other)
            other_request.app.state.sols_swap_store = SolsSwapStore(path)
            fresh = await fixtures._prepare(monkeypatch, SimpleNamespace(context=new_context), other_request)
            replacement.append(fresh)
            assert fresh.funding_evidence['feeCoinId'] == held['review']['feeCoinId']
            await promote(prepared)
        return before_push
    monkeypatch.setattr(swaps, '_seal_swap_execution', race)
    with pytest.raises(HTTPException, match='expired before exact execution promotion'):
        await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    assert not hasattr(request.app.state.protocol_submitter.provider, 'pushed')
    assert SolsSwapStore(path).execution(body.operation_hash) is None
    assert SolsSwapStore(path).funding(replacement[0].operation_hash) is not None


@pytest.mark.parametrize('reverse', [False, True])
async def test_fresh_quote_reuses_only_unsealed_fee_after_fee_increase(monkeypatch, tmp_path, reverse):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path, reverse=reverse)
    store = SolsSwapStore(path)
    prior = store.funding(body.operation_hash)
    monkeypatch.setattr(swaps, '_funding_binding', lambda *args: prior['review']['binding'])
    async def higher(*, target_times, **kwargs): return dict(target_times=target_times, estimates=[421])
    request.app.state.protocol_submitter.provider.get_fee_estimate = higher
    with pytest.raises(HTTPException, match='reserved fee is insufficient'):
        await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    monkeypatch.setattr(fixtures, 'QUOTE_EXPIRES', body.quote_expires_at + 1)
    context = (fixtures._reverse_fixture(request.app.state.faucet) if reverse else fixtures._fixture().context)
    async def loader(**kwargs): return context
    monkeypatch.setattr(swaps, '_load_reverse_swap_context' if reverse else '_load_swap_context', loader)
    fresh = await swaps.prepare_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER),
        swaps.PrepareSolsSwapRequest(direction=body.direction, deedLauncherId=body.deed_launcher_id), request, fixtures._settings())
    assert fresh.operation_hash != body.operation_hash
    assert fresh.funding_evidence['feeCoinId'] == prior['review']['feeCoinId']
    assert fresh.funding_evidence['feeMojos'] == '421'
    assert store.funding(body.operation_hash) is None
    assert store.funding(fresh.operation_hash) is not None


async def test_replacement_never_releases_a_sealed_execution(monkeypatch, tmp_path):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    store = SolsSwapStore(path)
    execution, holds = store.execution(body.operation_hash), store.reserved_input_coin_ids()
    record = store.get(body.operation_hash)
    operation = '0x'+'e'*64
    store.record_prepared(operation_hash=operation, direction=record.direction,
        vault_launcher_id=record.vault_launcher_id, deed_launcher_id=record.deed_launcher_id,
        quote_expires_at=record.quote_expires_at, pool_input_coin_id=record.pool_input_coin_id,
        expected_pool_output_coin_id=record.expected_pool_output_coin_id,
        destination_puzzle_hash=record.destination_puzzle_hash)
    store.supersede_unsealed_funding(operation, record.vault_launcher_id)
    assert store.execution(body.operation_hash) == execution
    assert store.reserved_input_coin_ids() == holds
    assert store.funding(body.operation_hash) is not None


async def test_restarted_disabled_funding_still_excludes_private_hold(monkeypatch, tmp_path):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    held = SolsSwapStore(path).funding(body.operation_hash)
    submitter = fixtures.FakeProtocolSubmitter()
    submitter.policy = replace(submitter.policy, enabled=False)
    submitter.add_fee_coin_reservation_source(SolsSwapStore(path).reserved_input_coin_ids)
    submitter.faucet.add_coin_reservation_source(SolsSwapStore(path).reserved_input_coin_ids)
    assert bytes.fromhex(held['review']['feeCoinId'][2:]) in submitter.reserved_funding_coin_ids()
    records = await submitter.provider.get_coin_records_by_puzzle_hash('', include_spent=False)
    assert submitter.faucet.select_coin(records, min_amount=1) is None


@pytest.mark.parametrize('field', ['feeMojos', 'backingMojos', 'fundingCoinSpend'])
async def test_private_record_tampering_never_reaches_provider(monkeypatch, tmp_path, field):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    held = SolsSwapStore(path).funding(body.operation_hash)
    if field == 'fundingCoinSpend': held['review'][field]['coin']['amount'] = '1'
    else: held['review'][field] = '999'
    with sqlite3.connect(path) as db:
        db.execute('UPDATE sols_swap_funding_reviews SET reservation_json=? WHERE operation_hash=?',
            (funding.canonical(held), body.operation_hash))
    with pytest.raises(HTTPException, match='record changed'):
        await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    assert not hasattr(request.app.state.protocol_submitter.provider, 'pushed')


async def test_real_binding_requires_verified_session_and_current_release(monkeypatch):
    context = fixtures._fixture().context
    context = replace(context, artifact={**context.artifact, 'sourceShas': dict(api='a'*40, protocol='b'*40)})
    session = SimpleNamespace(session_id='one-session', owner_key='0x'+bytes(context.vault_record.owner_pubkey).hex(), auth_type='chia_bls',
        expires_at=fixtures.QUOTE_EXPIRES, network='testnet11')
    monkeypatch.setattr(swaps, '_authorize_swap', lambda *args: None)
    monkeypatch.setattr(swaps, 'verify_vault_session', lambda *args: session)
    monkeypatch.setattr(swaps, 'load_signed_public_artifact', lambda *args: context.artifact)
    monkeypatch.setattr(swaps, 'read_release_metadata', lambda *args: SimpleNamespace(apiCommit='a'*40, protocolCommit='b'*40))
    first = real_binding(None, fixtures._settings(), context)
    assert first['sessionFingerprint'] == funding.digest('one-session')
    session.session_id = 'two-session'
    assert real_binding(None, fixtures._settings(), context) != first
    session.session_id = ''
    with pytest.raises(ValueError, match='session-bound'): real_binding(None, fixtures._settings(), context)
    session.session_id = 'two-session'
    monkeypatch.setattr(swaps, 'read_release_metadata', lambda *args: None)
    with pytest.raises(ValueError, match='release identity'): real_binding(None, fixtures._settings(), context)
    monkeypatch.setattr(swaps, 'read_release_metadata', lambda *args: SimpleNamespace(apiCommit='c'*40, protocolCommit='b'*40))
    with pytest.raises(ValueError, match='signed artifact'): real_binding(None, fixtures._settings(), context)
    session.owner_key = 'changed-owner'
    with pytest.raises(ValueError, match='ownership changed'): real_binding(None, fixtures._settings(), context)


@pytest.mark.parametrize('kind', ['coin', 'vault'])
async def test_separate_connections_reject_fee_and_vault_hold_conflicts(monkeypatch, tmp_path, kind):
    from chia.wallet.trading.offer import Offer
    from chia_rs import G2Element
    request, body, path, loader = await signed_case(monkeypatch, tmp_path)
    original = SolsSwapStore(path).funding(body.operation_hash)
    payload = json.loads(json.dumps(original))
    other = SolsSwapStore(path)
    record = other.get(body.operation_hash)
    operation = '0x'+'d'*64
    vault = record.vault_launcher_id if kind == 'vault' else '0x'+'e'*64
    other.record_prepared(operation_hash=operation, direction=record.direction,
        vault_launcher_id=vault, deed_launcher_id=record.deed_launcher_id,
        quote_expires_at=record.quote_expires_at, pool_input_coin_id=record.pool_input_coin_id,
        expected_pool_output_coin_id=record.expected_pool_output_coin_id,
        destination_puzzle_hash=record.destination_puzzle_hash)
    payload['review']['operationHash'] = operation
    payload['review']['binding']['vaultLauncherId'] = vault
    if kind == 'vault':
        context = await getattr(swaps, loader)()
        evidence = swaps.prepare_unsigned_sols_to_deed_swap(buyer_offer=Offer.from_bech32(body.buyer_offer),
            **swaps._protocol_offer_arguments(context))
        submitter = request.app.state.protocol_submitter
        coin = Coin(fixtures._b32(192), submitter.faucet.address_puzzle_hash, 10**12)
        spend, conditions = funding.funding_spend(submitter, evidence, coin, 420, record.quote_expires_at)
        private = SpendBundle([spend], G2Element.from_bytes(submitter.faucet.sign_delegated_spend(coin, conditions)))
        payload['fundingBundle'] = private.to_json_dict()
        payload['review'].update(feeCoinId=fixtures._hex32(coin.name()), fundingCoinSpend=funding.public_spend(spend))
    payload['reservationHash'] = funding.digest(payload['review'])
    with pytest.raises(ValueError, match='active reservation'):
        other.reserve_funding(operation, payload)
    assert other.funding(body.operation_hash) == original
    assert other.funding(operation) is None


async def test_same_operation_cannot_overwrite_review_for_another_session(monkeypatch, tmp_path):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    before = SolsSwapStore(path).funding(body.operation_hash)
    request.app.state.funding_session = 'replacement-session'
    with pytest.raises(HTTPException, match='session, release or policy'):
        await swaps.prepare_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER),
            swaps.PrepareSolsSwapRequest(deedLauncherId=body.deed_launcher_id), request, fixtures._settings())
    assert SolsSwapStore(path).funding(body.operation_hash) == before


async def test_sealed_execution_is_never_relabelled_as_pending_owner_review(monkeypatch, tmp_path):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    with pytest.raises(HTTPException, match='already has an exact execution'):
        await swaps.prepare_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER),
            swaps.PrepareSolsSwapRequest(deedLauncherId=body.deed_launcher_id), request, fixtures._settings())
    assert SolsSwapStore(path).execution(body.operation_hash) is not None


@pytest.mark.parametrize('mutation', ['session', 'policy'])
async def test_prepare_rechecks_binding_after_estimate_before_reserving(monkeypatch, mutation):
    submitter = fixtures.FakeProtocolSubmitter()
    request = fixtures._request(fixtures.FakeNode(), submitter)
    fixture = fixtures._fixture()
    async def changed(*, target_times, **kwargs):
        if mutation == 'session': request.app.state.funding_session = 'new-session'
        else: submitter.policy = replace(submitter.policy, maximum_mojos=999)
        return dict(target_times=target_times, estimates=[420])
    submitter.provider.get_fee_estimate = changed
    with pytest.raises(HTTPException, match='authorization or quote expired'):
        await fixtures._prepare(monkeypatch, fixture, request)
    assert request.app.state.sols_swap_store.reserved_input_coin_ids() == ()


@pytest.mark.parametrize('mutation', ['missing', 'spent', 'pending'])
async def test_unavailable_primary_fee_input_never_promotes(monkeypatch, tmp_path, mutation):
    request, body, path, _ = await signed_case(monkeypatch, tmp_path)
    provider = request.app.state.protocol_submitter.provider
    original = provider.get_coin_record_by_name_primary
    async def changed(coin_id):
        if mutation == 'missing': return None
        raw = await original(coin_id)
        if mutation == 'spent': raw.update(spent=True, spent_block_index=1)
        return raw
    provider.get_coin_record_by_name_primary = changed
    if mutation == 'pending': provider.pending = True
    with pytest.raises(HTTPException):
        await swaps.complete_sols_swap(fixtures._hex32(fixtures.VAULT_LAUNCHER), body, request, fixtures._settings())
    assert SolsSwapStore(path).execution(body.operation_hash) is None
    assert not hasattr(provider, 'pushed')
