"""Real coin/key encoding at the public-key-only primary read boundary."""
from types import SimpleNamespace
import pytest
from chia_rs import AugSchemeMPL,Coin
from chia_rs.sized_bytes import bytes32
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk, calculate_synthetic_public_key, DEFAULT_HIDDEN_PUZZLE_HASH
from solslot_api import generation_customer_purchase_execution as execution

@pytest.fixture
def setup(monkeypatch):
    public=AugSchemeMPL.key_gen(b'P'*32).get_g1();puzzle=puzzle_for_pk(public).get_tree_hash()
    coin=Coin(bytes32(b'A'*32),puzzle,1000)
    raw={'coin':coin.to_json_dict(),'confirmed_block_index':10,'spent_block_index':0,'spent':False}
    state=SimpleNamespace(network='testnet11',records=[raw],reads=0,now=100)
    class Primary:
        async def get_network_info_primary(self):return {'network_name':state.network}
        async def get_coin_records_by_puzzle_hash_primary(self,ph,*,include_spent):
            assert ph=='0x'+puzzle.hex() and include_spent is False
            state.reads+=1;return state.records
    service=object.__new__(execution.CurrentNativePurchaseExecution)
    service.provider=Primary();service.store=SimpleNamespace(generation_id='0x'+'01'*32)
    service.policy=SimpleNamespace(issued_at=1,expires_at=1000,buyer_vault=bytes32(b'V'*32))
    service.clock=lambda:state.now
    service._saved=lambda *a:{'reservationClaim':SimpleNamespace(purchase_artifact={})}
    monkeypatch.setattr(execution,'purchase_artifact_v3_from_json',lambda value:SimpleNamespace(rail_amount=500,quote_expires_at=400))
    async def call(keys=None):return await service.payer_coins('0x'+'02'*32,
        ['0x'+bytes(public).hex()]if keys is None else keys,browser_hash='synthetic')
    return SimpleNamespace(state=state,call=call,coin=coin,raw=raw,public='0x'+bytes(public).hex(),service=service)

@pytest.mark.asyncio
async def test_primary_confirmed_coin_is_public_only_and_no_transaction_prepared(setup):
    s=setup;value=await s.call()
    assert value['candidates']==[{'paymentCoinId':'0x'+s.coin.name().hex(),'paymentPublicKey':s.public,
        'paymentPublicKeyKind':'raw','amountMojos':'1000','confirmedHeight':10}]
    assert value['receivingVaultLauncherId']!='0x'+s.coin.name().hex()
    assert s.state.reads==1
    assert value['diagnostic']=={'status':'eligible_found','keysChecked':1}

@pytest.mark.asyncio
async def test_batch_requires_one_coin_covering_every_selected_deed(setup,monkeypatch):
    from solslot_api.generation_customer_purchase_batch import CurrentReservationBatch
    s=setup
    # The existing payer reader sees an already validated saved batch. Its
    # public coin query must use the full total, never the first child's price.
    claim=CurrentReservationBatch.model_construct()
    monkeypatch.setattr(execution,'artifacts',lambda _:tuple(SimpleNamespace(
        rail_amount=600,quote_expires_at=400)for _ in range(2)))
    s.service._saved=lambda *a:{'reservationClaim':claim}
    value=await s.call()
    assert value['amountMojos']=='1200'and value['candidates']==[]
    assert value['diagnostic']=={'status':'no_eligible_coin','keysChecked':1}
    assert s.state.reads==1

@pytest.mark.asyncio
@pytest.mark.parametrize('patch',[{'confirmed_block_index':0},{'coin':{'parent_coin_info':'0x'+'00'*32,'puzzle_hash':'0x'+'11'*32,'amount':1000}},
    {'spent_block_index':1,'spent':True}])
async def test_unconfirmed_redirected_and_inconsistent_coin_records_abort(setup,patch):
    setup.state.records=[{**setup.raw,**patch}]
    with pytest.raises((ValueError,TypeError)):await setup.call()

@pytest.mark.asyncio
async def test_spent_insufficient_and_noncanonical_requests_do_not_become_funding(setup):
    s=setup;s.state.records=[{**s.raw,'spent_block_index':11,'spent':True}]
    assert (await s.call())['candidates']==[]
    for keys in ([],[s.public]*2,['0x'+'00'*48],[s.public.upper()]):
        before=s.state.reads
        with pytest.raises(ValueError):await s.call(keys)
        assert s.state.reads==before

@pytest.mark.asyncio
async def test_expired_quote_and_wrong_network_never_query_coins(setup):
    s=setup;s.state.now=400
    with pytest.raises(ValueError,match='WINDOW_CLOSED'):await s.call()
    s.state.now=100;s.state.network='mainnet'
    with pytest.raises(ValueError,match='NETWORK_CHANGED'):await s.call()
    assert s.state.reads==0

@pytest.mark.asyncio
async def test_primary_unavailable_has_sanitized_code_and_no_false_empty_result(setup):
    async def failed(*args,**kwargs):raise RuntimeError('private endpoint and details')
    setup.service.provider.get_network_info_primary=failed
    with pytest.raises(ValueError,match='^CURRENT_PAYMENT_PRIMARY_UNAVAILABLE$'):
        await setup.call()
    setup.service.provider.get_network_info_primary=lambda: network()
    setup.service.provider.get_coin_records_by_puzzle_hash_primary=failed
    async def network():return {'network_name':'testnet11'}
    with pytest.raises(ValueError,match='^CURRENT_PAYMENT_PRIMARY_UNAVAILABLE$'):
        await setup.call()

@pytest.mark.asyncio
async def test_sage_synthetic_key_finds_same_coin_without_double_derivation(setup):
    from chia_rs import G1Element
    raw=G1Element.from_bytes(bytes.fromhex(setup.public[2:]))
    synthetic=calculate_synthetic_public_key(raw,DEFAULT_HIDDEN_PUZZLE_HASH)
    value=await setup.service.payer_coins('0x'+'02'*32,['0x'+bytes(synthetic).hex()],
        browser_hash='synthetic',public_key_kind='synthetic')
    assert value['candidates'][0]['paymentCoinId']=='0x'+setup.coin.name().hex()
    assert value['candidates'][0]['paymentPublicKeyKind']=='synthetic'
    with pytest.raises(ValueError,match='KIND_INVALID'):
        await setup.service.payer_coins('0x'+'02'*32,[setup.public],browser_hash='synthetic',public_key_kind='invalid')
