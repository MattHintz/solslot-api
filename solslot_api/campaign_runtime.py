"""Recover original campaign executions without allocating replacement identities."""
from __future__ import annotations

from chia_rs import Coin, SpendBundle


def campaign_context(settings):
    from . import presale_endpoints as p
    artifact = p.load_signed_public_artifact(settings)
    # Loading the signed artifact also verifies runtime and source commitments.
    identity = p._hex32(p._b32(artifact["artifactHash"], nonzero=True))
    return dict(genesisArtifactHash=identity, network=settings.network,
                environment=settings.runtime_environment)


def funding_guard(store, submitter):
    if submitter is not None:
        submitter.add_fee_coin_reservation_source(store.pending_campaign_funding_coin_ids)
        submitter.add_fee_coin_reservation_source(store.pending_voucher_funding_coin_ids)
        return submitter.funding_guard
    return store.campaign_funding_guard


async def create_campaign(body, request, settings, store, collections):
    from . import presale_endpoints as p
    from fastapi import HTTPException
    faucet, node = request.app.state.faucet, request.app.state.coinset
    if faucet is None or node is None:
        raise HTTPException(status_code=503, detail='signed singleton launch service is unavailable')
    submitter = getattr(request.app.state, 'protocol_submitter', None)
    intent, context = body.model_dump(mode='json'), campaign_context(settings)
    async with funding_guard(store, submitter):
        try:
            series = store.get(body.collection_id)
        except KeyError:
            series = None
        if series is not None:
            operation = store.campaign_operation(series['termsHash'], 'creation')
            if operation is None or operation['intent'] != intent or operation['context'] != context:
                raise ValueError('collection already has a different presale creation')
        else:
            reserved = store.pending_campaign_funding_coin_ids() | store.pending_voucher_funding_coin_ids()
            if submitter is not None:
                reserved |= {'0x' + bytes(name).hex() for name in submitter.reserved_funding_coin_ids()}
            records = await node.get_coin_records_by_puzzle_hash('0x' + faucet.address_puzzle_hash.hex(), include_spent=False)
            records = [r for r in records if (coin := p._coin_from_record(r)) is not None and '0x' + coin.name().hex() not in reserved]
            parent = faucet.select_coin(records, min_amount=1, max_amount=settings.faucet_max_spend_mojos)
            if parent is None:
                raise HTTPException(status_code=503, detail='faucet has no eligible one-mojo singleton funding coin')
            launcher_id = p.bytes32(p.launcher_coin_for_parent(parent).name())
            terms = p.build_series_terms(body, series_singleton_id=launcher_id,
                                        collection=collections.get(body.collection_id), settings=settings)
            program = p._series_program(terms)
            launched = p.build_and_sign_singleton_launch(
                faucet=faucet, parent_coin=parent,
                inner_puzzle_for_launcher=lambda identity: p._initial_series_inner(identity, expected_launcher_id=launcher_id, terms=program),
                launcher_memos=(b'SOLSLOT_PRESALE_SERIES_V2', program.collection_id, program.terms_hash),
                eve_memos=(program.collection_id, program.terms_hash),
            )
            bindings = dict(parentCoinId='0x' + parent.name().hex(), fullPuzzleHash='0x' + launched.full_puzzle_hash.hex(),
                            spendBundleId=launched.spend_bundle_id)
            operation = dict(kind='creation', intent=intent, context=context, preparation=bindings,
                             execution=dict(spendBundleId=launched.spend_bundle_id, spendBundle=launched.spend_bundle.to_json_dict()))
            # Reserve collection, launcher, funding inputs and signed bytes in the
            # same SQLite transaction, before the first external push.
            series = store.create(terms, singleton_launch=bindings, campaign_operation=operation)
            operation = store.campaign_operation(series['termsHash'], 'creation')
    await resume_campaign(settings=settings, store=store, node=node, series=series, operation=operation)
    return store.get(series['termsHash'])


def execution_bundle(execution):
    bundle = SpendBundle.from_json_dict(execution['spendBundle'])
    if not bundle.coin_spends or execution['spendBundleId'] != '0x' + bundle.name().hex():
        raise ValueError('Original campaign bundle identity changed')
    return bundle


async def confirmed_execution_height(node, bundle):
    """Require canonical coins and exact spends at one atomic inclusion height."""
    height = None
    for spend in bundle.coin_spends:
        name = '0x' + spend.coin.name().hex()
        record = await node.get_coin_record_by_name(name)
        if not record or not record.get('spent_block_index'):
            return None
        if Coin.from_json_dict(record['coin']) != spend.coin:
            raise ValueError('Campaign removal record changed')
        spent = int(record['spent_block_index'])
        if spent <= 0 or (height is not None and height != spent):
            raise ValueError('Campaign removals are not atomic')
        height = spent
        proof = await node.get_puzzle_and_solution(name, height)
        if not proof:
            return None
        for field in ('puzzle_reveal', 'solution'):
            if bytes.fromhex(proof[field].removeprefix('0x')) != bytes(getattr(spend, field)):
                raise ValueError('Campaign confirmed spend differs from original execution')
    for coin in bundle.additions():
        record = await node.get_coin_record_by_name('0x' + coin.name().hex())
        if not record:
            return None
        if Coin.from_json_dict(record['coin']) != coin or int(record.get('confirmed_block_index') or 0) != height:
            raise ValueError('Campaign additions are not atomic')
    return height


def bind_phase(store, terms_hash, execution):
    bundle = execution_bundle(execution)
    if execution['bindings']['spend_bundle_id'] != execution['spendBundleId']:
        raise ValueError('Campaign phase binding changed')
    current = store._get_series(terms_hash)
    if not current['phaseTransition']['spendBundleId']:
        store.record_phase_submission(terms_hash, **execution['bindings'])
    elif current['phaseTransition']['spendBundleId'] != execution['spendBundleId']:
        raise ValueError('Campaign phase submission changed')
    return bundle


async def resume_campaign(*, settings, store, node, series, operation=None, authorize_dispatch=None):
    from . import presale_endpoints as p
    operation = operation or store.pending_campaign_operation(series['termsHash'])
    if operation is None:
        raise ValueError('No campaign operation to recover')
    if operation['context'] != campaign_context(settings):
        raise ValueError('Campaign recovery does not match the active environment and genesis')
    kind, terms_hash = operation['kind'], series['termsHash']
    if operation['confirmedHeight'] is not None:
        return dict(termsHash=terms_hash, status=kind.upper() + '_CONFIRMED')
    if kind == 'phase':
        from .campaign_expiry import launch_deadline, prove_expiry
        from chia.wallet.lineage_proof import LineageProof
        prep = operation['preparation']
        claim = p.VoucherSeriesPhaseClaim.model_validate(prep['claim'])
        coin = Coin.from_json_dict(prep['seriesCoin'])
        deadline = launch_deadline(claim, coin, LineageProof.from_json_dict(prep['lineage']))
        # Wall time only avoids needless RPC work. It is never expiry evidence.
        if deadline is not None and p.time.time() >= deadline:
            record = await node.get_coin_record_by_name(claim.series_coin_id)
            if record and record.get('spent') is False and record.get('spent_block_index') == 0:
                proof = await prove_expiry(node, settings.network, coin, deadline)
                if proof is not None:
                    store.archive_expired_campaign_phase(terms_hash, operation, proof)
                    return dict(termsHash=terms_hash, status='PHASE_EXPIRED',
                                detail='The expired attempt is preserved. A new launch or cancellation requires fresh admin approval.')
    if operation['execution'] is None:
        if kind != 'phase':
            raise ValueError('Campaign creation lost its original signed execution')
        if authorize_dispatch is not None:
            authorize_dispatch()
        await p._sign_retained_series_phase(settings, store, series, operation)
        operation = store.campaign_operation(terms_hash, kind)
    execution = operation['execution']
    bundle = bind_phase(store, terms_hash, execution) if kind == 'phase' else execution_bundle(execution)
    height = await confirmed_execution_height(node, bundle)
    if height is not None:
        # Phase state and its journal confirmation share one transaction. The
        # existing store method verifies the committed successor and counters.
        if kind == 'phase':
            b = execution['bindings']
            input_coin = bundle.coin_spends[0].coin
            store.confirm_phase_transition(terms_hash, p.VoucherSeriesPhaseChainEvidence(
                evidenceId='chia:' + execution['spendBundleId'], spendBundleId=execution['spendBundleId'],
                targetState=b['target_state'], seriesInputCoinId=b['series_input_coin_id'],
                seriesInputParentCoinId='0x' + input_coin.parent_coin_info.hex(),
                seriesOutputCoinId=b['series_output_coin_id'],
                seriesOutputInnerPuzzleHash=b['series_output_inner_puzzle_hash'],
                launchAnchor=b['launch_anchor'], confirmedHeight=height,
            ), include_vouchers=False)
        store.confirm_campaign_operation(terms_hash, kind, height)
        return dict(termsHash=terms_hash, status=kind.upper() + '_CONFIRMED')
    if authorize_dispatch is not None:
        authorize_dispatch()
    result = await node.push_tx(bundle.to_json_dict())
    if not result.get('success') and str(result.get('status') or '').upper() not in {'SUCCESS', 'PENDING'}:
        raise ValueError('Original campaign execution was rejected by the Chia node')
    return dict(termsHash=terms_hash, status=kind.upper() + '_SUBMITTED')
