"""Native current vault, owner HTTP cookie and deployed-gate parity regression."""
from copy import deepcopy

import httpx
import pytest
from chia_rs.sized_bytes import bytes32
from eth_account import Account

from solslot_api.collection_store import get_collection_store
from solslot_api.generation_customer_portfolio import read_current_portfolio
from solslot_api.generation_customer_portfolio_routes import router
from solslot_api.generation_customer_store import read_consent
from solslot_api.generation_operations import reconcile_saved_operation
from tests.test_generation_customer_routes import customer, core, BASE
from tests.test_generation_customer_launch import sign


async def connected(p):
    key = Account.from_key(b'z'*32)
    generation = p.settings.deployment_generation_id
    saved = (await p.client.post(BASE+'/reviews', json={
        'generationId': generation, 'owner': key.address, 'authType': 'evm'})).json()
    path = BASE+'/reviews/'+saved['registrationId']
    approved = await p.client.post(path+'/authorize', json={
        'generationId': generation, 'signature': sign(read_consent(saved['review']), key)})
    assert approved.status_code == 200, approved.text
    submitted = await p.client.post(path+'/submit', json={'generationId': generation})
    assert submitted.status_code == 200, submitted.text
    await p.c.sim.farm_block()
    await reconcile_saved_operation(p.journal, approved.json()['operationId'], p.node, clock=lambda: p.now[0])
    await p.runtime.reconcile_once()
    from hashlib import sha256
    from solslot_api.generation_customer_routes import _cookie_name
    token = p.client.cookies.get(_cookie_name(p.settings))
    browser = sha256((generation+':'+token).encode()).hexdigest()
    await p.runtime.verified_registration_owner(saved['registrationId'], browser)
    response = await p.client.post(path+'/connect', json={'generationId': generation})
    assert response.status_code == 200, response.text
    # Exactly the production cookie scope: the retired /sols route cannot
    # borrow it. Public users do not need Cloudflare administrator access.
    p.client.cookies.clear()
    from solslot_api.credential_auth import VAULT_SESSION_COOKIE
    cookie = response.cookies.get(VAULT_SESSION_COOKIE)
    p.client.cookies.set(VAULT_SESSION_COOKIE, cookie, path='/protocol-api/next/customer')
    async def primary_puzzle(puzzle, **kwargs):
        return [r.to_json_dict() for r in await p.c.client.get_coin_records_by_puzzle_hash(
            bytes32.from_hexstr(puzzle), include_spent_coins=False)]
    p.node.get_coin_records_by_puzzle_hash_primary = primary_puzzle
    return saved


@pytest.mark.asyncio
async def test_current_owner_dashboard_native_empty_outage_auth_and_gate(customer, monkeypatch):
    p = customer
    saved = await connected(p)
    inner = p.app.routes[-1].app
    inner.include_router(router)
    inner.dependency_overrides[get_collection_store] = lambda: object()
    from solslot_api.generation_customer_read_gate import CurrentCustomerReadGate
    async def retained_closed(scope, receive, send):
        # All routes outside the current read contract go to the retained gate.
        await send({'type':'http.response.start','status':503,'headers':[]})
        await send({'type':'http.response.body','body':b'closed'})
    gated = CurrentCustomerReadGate(inner, retained=retained_closed)
    async def origin_proxy(scope, receive, send):
        # Existing Apache ProxyPass strips this public prefix before the
        # gate/API receive a request; browser cookies use the full URL.
        if scope['type'] == 'http':
            scope = {**scope, 'path': scope['path'].removeprefix('/protocol-api/next'), 'root_path': ''}
        return await gated(scope, receive, send)
    p.app.routes[-1].app = origin_proxy
    path = '/protocol-api/next/customer/vaults/'+saved['vaultLauncherId']+'/journey'
    pushes, selections = p.node.pushes, p.node.selections
    def never(*a, **kw):
        raise AssertionError('portfolio status must not sign, fund, reserve or submit')
    monkeypatch.setattr(p.runtime.faucet, 'sign_delegated_spend', never)
    monkeypatch.setattr(p.runtime.submitter, 'submit', never, raising=False)
    for _ in range(3):
        response = await p.client.get(path)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result['holdings'] == []
        assert result['balances']['solsMojos'] == result['balances']['sgtMojos'] == '0'
        assert result['verification']['generationId'] == p.settings.deployment_generation_id
        assert result['verification']['holdingsSource'] == 'CURRENT_GENERATION_PRIMARY_NODE'
        assert not any(value['available'] for value in result['capabilities'].values())
        assert result['vault']['identityConfirmed'] is False
        assert response.headers['cache-control'] == 'no-store'
        assert not response.headers.get('set-cookie')
    assert (p.node.pushes, p.node.selections) == (pushes, selections)
    # Negative parity: exact read only, no new financial route is exposed.
    assert (await p.client.post(path, json={})).status_code == 503
    assert (await p.client.get(path.replace('/customer', '/sols'))).status_code == 503
    assert (await p.client.post('/protocol-api/next/customer/purchases', json={})).status_code == 503
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=p.app), base_url='https://test') as stranger:
        assert (await stranger.get(path)).status_code == 401
    assert (await p.client.get(path.replace(saved['vaultLauncherId'], '0x'+'dd'*32))).status_code == 403
    original = p.node.get_coin_records_by_puzzle_hash_primary
    async def offline(*a, **kw):
        raise OSError('synthetic primary outage, never a zero balance')
    p.node.get_coin_records_by_puzzle_hash_primary = offline
    unavailable = await p.client.get(path)
    assert unavailable.status_code == 503
    assert unavailable.json()['detail']['code'] == 'CURRENT_PORTFOLIO_UNAVAILABLE'
    assert 'holdings' not in unavailable.json()
    assert 'synthetic primary' not in unavailable.text
    p.node.get_coin_records_by_puzzle_hash_primary = original
    assert (await p.client.get(path)).status_code == 200
    # Stale in-process custody cannot hydrate an earlier generation or borrow
    # a stored ID check, even if the browser still has an owner cookie.
    p.now[0] += 61
    assert (await p.client.get(path)).status_code == 503


@pytest.mark.asyncio
async def test_primary_query_inconsistency_never_becomes_empty(customer):
    p = customer
    saved = await connected(p)
    snapshot = p.runtime.current_vault_snapshot(saved['vaultLauncherId'])
    original = p.node.get_coin_records_by_puzzle_hash_primary
    async def inconsistent(*args, **kwargs):
        return [await p.node.get_coin_record_by_name_primary(snapshot['vault']['currentCoinId'])]
    p.node.get_coin_records_by_puzzle_hash_primary = inconsistent
    with pytest.raises(ValueError, match='inconsistent custody'):
        await read_current_portfolio(snapshot=snapshot, evidence=p.index.evidence,
            sgt_bindings=p.index.anchor.issuance.bindings(), provider=p.node,
            metadata_for_edition=lambda _: pytest.fail('no owned deed metadata'))
    p.node.get_coin_records_by_puzzle_hash_primary = original
    previous = p.index.evidence
    p.index.evidence.registry.state.generation  # real reconstructed native state
    wrong = deepcopy(snapshot)
    wrong['generationId'] = '0x'+'ee'*32
    with pytest.raises(ValueError, match='generation'):
        await read_current_portfolio(snapshot=wrong, evidence=previous,
            sgt_bindings=p.index.anchor.issuance.bindings(), provider=p.node,
            metadata_for_edition=lambda _: pytest.fail('not reached'))
    # A checkpoint missing earlier mint transitions must not claim there are
    # no owned deeds just because its in-memory transition list is empty.
    from dataclasses import replace
    from solslot_puzzles.generation_mint import GenerationMint
    components = dict(previous.economic_components)
    key = next(key for key, history in components.items() if isinstance(history.state, GenerationMint))
    components[key] = replace(components[key], state=replace(components[key].state, issued_count=1))
    with pytest.raises(ValueError, match='minted universe'):
        await read_current_portfolio(snapshot=snapshot,
            evidence=replace(previous, economic_components=components),
            sgt_bindings=p.index.anchor.issuance.bindings(), provider=p.node,
            metadata_for_edition=lambda _: pytest.fail('incomplete history cannot load metadata'))


@pytest.mark.asyncio
async def test_sgt_is_scoped_to_exact_current_vault_not_matching_browser_owner(customer):
    from solslot_api.generation_holder_evidence import preparation_custody_anchors, resolve_holder_custody
    p = customer
    saved = await connected(p)
    fresh = p.runtime.current_vault_snapshot(saved['vaultLauncherId'])
    custody = preparation_custody_anchors(p.c.prep)[0]
    native = await resolve_holder_custody(custody, provider=p.node)
    record = native.current
    registered = {**fresh, 'vault': {
        'vaultLauncherId':'0x'+custody.launcher_id.hex(), 'currentCoinId':'0x'+record.coin.name().hex(),
        'currentPuzzleHash':'0x'+record.coin.puzzle_hash.hex(), 'confirmedHeight':record.confirmed_height,
        'identityVerified':False}}
    # The reader uses authenticated native ownership, not a prior EVM address
    # lookup. The fresh customer's portfolio above still has zero SGT.
    result = await read_current_portfolio(snapshot=registered, evidence=p.index.evidence,
        sgt_bindings=p.index.anchor.issuance.bindings(), provider=p.node,
        metadata_for_edition=lambda _: pytest.fail('no deed held'))
    assert result['balances']['sgtMojos'] == '10000'
    result = await read_current_portfolio(snapshot=fresh, evidence=p.index.evidence,
        sgt_bindings=p.index.anchor.issuance.bindings(), provider=p.node,
        metadata_for_edition=lambda _: pytest.fail('no deed held'))
    assert result['balances']['sgtMojos'] == '0'
