"""Detached current inputs and executable refund effects, before owner signing."""
from fastapi import HTTPException
from chia.types.blockchain_format.program import Program

from .chia_provider import ChiaProviderError
from .chia_snapshot import PrimaryReadSnapshot
from .credential_auth import verify_vault_session, vault_session_fingerprint
from .public_artifact import load_signed_public_artifact
from .sols_swap_funding import digest, hx, public_spend
from .vault_eligibility import require_current_approved_vault


def refund_execution_evidence(context):
    roles = ('vault', 'series', 'voucher', 'payment')
    spends = (context.vault_spend, *context.provisional.coin_spends)
    candidate = Program.to([b'VRF1', [[role.encode(), bytes(spend)] for role, spend in zip(roles, spends)]])
    return dict(schemaVersion=1, action='VOUCHER_REFUND', status='OWNER_AND_VALIDATOR_AUTHORIZATION_PENDING',
        consensusValidated=False, candidateHash=hx(candidate.get_tree_hash()),
        termsProgram=hx(context.terms.to_program()),
        voucherProgram=hx(context.voucher.to_program(include_state=False)),
        purchaseProgram=hx(context.purchase.to_program()),
        coinSpends=[dict(role=role, **public_spend(spend)) for role, spend in zip(roles, spends)],
        protocolFeeMojos='1' if context.is_stripe else '0')


def refund_authority(request, settings, store, approved, voucher_json, series, serial, context, artifact, evidence, expires):
    from .state import get_registry
    session = verify_vault_session(settings, request, approved.launcher_id)
    if (session.auth_type != 'chia_bls' or session.owner_key.lower() != hx(context.vault_record.owner_pubkey)
            or not session.session_id or session.network != 'testnet11'
            or require_current_approved_vault(settings, approved.launcher_id) != approved
            or get_registry().get(context.vault_record.launcher_id) != context.vault_record
            or digest(load_signed_public_artifact(settings)) != digest(artifact)
            or store.get(series['termsHash']) != series
            or store.voucher(series['termsHash'], serial) != voucher_json):
        raise ValueError('Refund owner, purchase, series or release changed during review')
    return dict(action='VOUCHER_REFUND', vaultLauncherId=approved.launcher_id,
        ownerKey=session.owner_key.lower(), authType=session.auth_type, network=session.network,
        sessionFingerprint=vault_session_fingerprint(session.session_id), sessionExpiresAt=session.expires_at,
        artifactHash=digest(artifact), purchaseId=voucher_json['purchaseId'], termsHash=series['termsHash'],
        serial=serial, candidateHash=evidence['candidateHash'], quoteExpiresAt=expires)


async def prepare_refund_review(*, request, settings, store, approved, voucher_json, series, serial, current_timestamp):
    from .presale_endpoints import _load_refund_execution_context, PrepareVoucherRefundResponse, REFUND_AUTH_MAX_AGE_SECONDS, _coin_spend_json
    try:
        artifact = load_signed_public_artifact(settings)
        async with PrimaryReadSnapshot(request.app.state.coinset, settings.network) as snapshot:
            context = await _load_refund_execution_context(request=request, settings=settings, approved=approved,
                voucher_json=voucher_json, series=series, series_coin_id=series['chainState']['currentCoinId'],
                voucher_coin_id=voucher_json['voucherOutputCoinId'], current_timestamp=current_timestamp)
            evidence = refund_execution_evidence(context)
            expires = current_timestamp + REFUND_AUTH_MAX_AGE_SECONDS

            authority = lambda: refund_authority(request, settings, store, approved, voucher_json, series, serial,
                context, artifact, evidence, expires)
            binding = authority()
            snapshot.recheck(authority, binding)
            persistent = [(s['role'], spend.coin) for s, spend in
                zip(evidence['coinSpends'], (context.vault_spend, *context.provisional.coin_spends))]
            observation_binding = binding
            if context.is_stripe:
                from .voucher_refund_funding import reserve_refund_funding
                from chia_rs import Coin
                funding = await reserve_refund_funding(request.app.state.protocol_submitter,store,context,evidence,binding,authority)
                evidence['fundingEvidence'] = funding
                fee = funding['fundingCoinSpend']['coin']
                persistent.append(('fee',Coin.from_json_dict({'parent_coin_info':fee['parentCoinInfo'],
                    'puzzle_hash':fee['puzzleHash'],'amount':int(fee['amount'])})))
                observation_binding = {**binding,'fundingReservationHash':funding['reservationHash']}
            observation = await snapshot.finish(persistent, observation_binding)
        evidence['currentStateEvidence'] = observation
        return PrepareVoucherRefundResponse(termsHash=series['termsHash'], serial=serial,
            purchaseId=voucher_json['purchaseId'], paymentRail=voucher_json['paymentRail'], authType='chia_bls',
            action='REFUND_CANCELED' if series['state'] == 'CANCELED' else 'REFUND_PRESALE',
            vaultCoinId=hx(context.vault_coin.name()), voucherCoinId=hx(context.voucher_coin.name()),
            seriesCoinId=hx(context.series_coin.name()), currentTimestamp=current_timestamp, expiresAt=expires,
            coinSpends=[_coin_spend_json(context.vault_spend)], typedData=None, reviewEvidence=evidence)
    except (ChiaProviderError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
