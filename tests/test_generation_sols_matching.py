from solslot_api.generation_sols_matching import suggest_matches


def order(i,amount,asset=None,stage='WAITING_FOR_MATCH'):
    return {'orderId':str(i),'paymentAmount':str(amount),'paymentAsset':asset,'stage':stage}


def inventory(n=8):return [{'inventoryId':str(i),'subtotalUsdMinor':'303000'} for i in range(n)]


PRICE={'round':{'assetId':'0x'+'00'*32,'assetDecimals':0,'priceUsdMinorPerAsset':1}}


def test_whole_offer_group_reaches_one_or_multiple_deeds_without_resizing():
    orders=[order(1,101000),order(2,202000),order(3,7000)]
    result=suggest_matches(orders,inventory(),PRICE,limit=1)
    assert result[0]['orderIds']==['1','2'] and result[0]['primaryCoinIds']==['0']
    assert result[0]['paymentAmount']=='303000'
    assert suggest_matches([order(4,606000)],inventory(),PRICE,limit=1)[0]['sourceCount']==2
    assert orders[0]['paymentAmount']=='101000' and orders[2]['paymentAmount']=='7000'


def test_cancellation_other_rail_and_excess_budget_never_fund_an_invented_match():
    assert not suggest_matches([order(1,303001)],inventory(),PRICE)
    assert not suggest_matches([order(1,303000,stage='INPUT_SPENT')],inventory(),PRICE)
    assert not suggest_matches([order(1,303000,asset='unapproved-USDC')],inventory(),PRICE)
    # The native contract cannot fit more than 32 whole original offers.
    assert not suggest_matches([order(i,303000//33) for i in range(33)],inventory(1),PRICE)


def test_deterministic_search_remains_bounded_with_512_very_different_orders():
    orders=[order(i,i+1) for i in range(512)]
    a=suggest_matches(orders,inventory(),PRICE)
    assert a==suggest_matches(orders,inventory(),PRICE)
    assert all(len(row['orderIds'])<=32 and len(row['primaryCoinIds'])<=8 for row in a)
