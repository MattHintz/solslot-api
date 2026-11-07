"""Bounded candidate matching of whole original offers; no custody or signing.

The native builder still verifies sources, signed minima and every output.
Matching does not call a wallet or create a transaction during a status read.
"""
MAX_STATES=4096


def suggest_matches(orders,inventory,price,*,limit=4):
    if not 1<=limit<=4 or not isinstance(price,dict):raise ValueError('MATCH_LIMIT_INVALID')
    rail=price['round'];asset=rail['assetId'];decimals=rail['assetDecimals'];rate=rail['priceUsdMinorPerAsset']
    rate=int(rate)
    if type(decimals) is not int or not 0<=decimals<=18 or rate<=0:raise ValueError('MATCH_PRICE_INVALID')
    payment_asset=None if asset=='0x'+'00'*32 else asset
    candidates=[o for o in orders[:512] if o['stage']=='WAITING_FOR_MATCH' and o['paymentAsset']==payment_asset]
    sources=inventory[:100]
    if not candidates or not sources:return []
    # One bounded window of at most eight whole sources. Try each successive
    # total, so a large single offer may acquire more than one whole deed.
    costs=[(int(row['subtotalUsdMinor'])*10**decimals+rate-1)//rate for row in sources[:8]]
    targets=[];total=0
    for count,cost in enumerate(costs,1):
        total+=cost;targets.append((total,count))
    maximum=targets[-1][0];states={0:()}
    for order in candidates:
        amount=int(order['paymentAmount']);identity=order['orderId']
        if amount<=0 or amount>maximum:continue
        updates={}
        for subtotal,selection in tuple(states.items()):
            next_sum=subtotal+amount
            if next_sum>maximum or len(selection)>=32:continue
            if next_sum not in states and next_sum not in updates:updates[next_sum]=selection+(identity,)
        # Keep the earliest exact sums. The bound is a search limit, never
        # permission to resize an offer or route excess to a matcher.
        room=MAX_STATES-len(states)
        for subtotal,selection in list(updates.items())[:max(0,room)]:states[subtotal]=selection
    result=[];used=set()
    for amount,count in targets:
        ids=states.get(amount)
        if not ids or used.intersection(ids):continue
        result.append({'orderIds':list(ids),'primaryCoinIds':[s['inventoryId'] for s in sources[:count]],
            'paymentAsset':payment_asset,'paymentAmount':str(amount),'sourceCount':count,
            'stage':'CANDIDATE_REQUIRES_NATIVE_REVIEW'})
        used.update(ids)
        if len(result)==limit:break
    return result
