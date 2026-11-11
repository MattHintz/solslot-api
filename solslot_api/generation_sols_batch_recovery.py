"""Explicit expiry reconciliation; no repricing, signing or submission."""
from chia_rs import SpendBundle
from .generation_operations import bundle_id
from .protocol_submission import PreparedProtocolBundle


async def release_batch_quote(book,journal,identity,submitter,*,clock):
    book.repair_saved_links(journal)
    saved=journal.status(identity)
    if saved['kind']!='PRIMARY_SOLS_BATCH' or saved['generationId']!=book.generation_id:
        raise ValueError('SAVED_BATCH_GENERATION_CHANGED')
    if saved['stage']=='CONFIRMED':return saved
    if saved['stage']=='EXPIRED_RECONCILED':
        book.repair_saved_links(journal)
        return saved
    protocol=journal.protocol_bundle(identity)
    store=submitter.funding_store
    if store is None:raise ValueError('SAVED_BATCH_FUNDING_JOURNAL_REQUIRED')
    backing=int(saved['review']['issuanceBackingMojos'])
    document=store.lookup('testnet11',bundle_id(protocol),{'feeTill':submitter.faucet.address_hex,
        'purpose':None,'backingMojos':backing})
    if document:
        funded=PreparedProtocolBundle(SpendBundle.from_json_dict(document['spendBundle']),
            int(document['feeMojos']),document['feeCoinId'],int(document['backingMojos']))
        journal.save_funded(identity,funded,int(clock()))
        if not store.is_released('testnet11',bundle_id(protocol)):
            from .chia_provider import ChiaProviderError
            try:observed=await submitter.provider.observe_exact_protocol_bundle(document['spendBundle'])
            except ChiaProviderError:observed=None
            if observed:
                journal.observed(identity,transaction_id=document['spendBundleId'],status=observed['status'],
                    confirmed_height=observed.get('confirmed_height'),now=int(clock()))
                return journal.status(identity)
        proof=await submitter.release_expired_saved(bundle_id(protocol),expected_backing_mojos=backing,
            allow_confirmed_conflicts=True)
    else:
        if journal.saved_funding(identity) is not None:raise ValueError('SAVED_BATCH_FUNDING_EVIDENCE_MISSING')
        async with submitter.funding_guard:
            proof=await submitter.prove_expired_bundle(protocol,allow_confirmed_conflicts=True)
    journal.record_batch_expiry(identity,proof,now=int(clock()))
    book.repair_saved_links(journal)
    for order in saved['review']['orderIds']:
        await book.check_inputs(order,provider=submitter.provider,journal=journal,now=int(clock()))
    return journal.status(identity)
