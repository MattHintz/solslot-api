"""Export a public synthetic, production-signed HTTP envelope (no network)."""
import asyncio
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch
from dataclasses import replace

import httpx
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_api.faucet import Faucet
from solslot_api.kos_exact_execution import (ExactExecutionAction, ExactExecutionOutput,
    ExactExecutionRequest, KeyOfSolomonExactExecutor)
from solslot_api.protocol_submission import PreparedProtocolBundle
from solslot_api.voucher_refund_funding import fee_spend
from solslot_api.stripe_voucher_execution import _document
from solslot_api.stripe_refund_continuation import build_continuation
from solslot_api.refund_continuation import retime_native_refund


async def export(destination):
    data = json.loads((Path(__file__).parents[1] / 'tests/fixtures/stripe-refund-fee.json').read_text())
    protocol = SpendBundle.from_json_dict(data['spendBundle'])
    context = SimpleNamespace(vault_spend=protocol.coin_spends[0], vault_coin=protocol.coin_spends[0].coin,
        provisional=SimpleNamespace(coin_spends=protocol.coin_spends[1:]))
    faucet = Faucet.from_seed_hex('77'*32, 'testnet11')
    coin = Coin(bytes32(bytes([80])*32), faucet.address_puzzle_hash, 10000)
    deadline = data['reviewVector']['intent']['reviewEvidence']['fundingEvidence']['executionDeadline']
    spend, conditions = fee_spend(SimpleNamespace(faucet=faucet), context, coin, 100, deadline)
    bundle = SpendBundle.aggregate([protocol, SpendBundle([spend],
        G2Element.from_bytes(faucet.sign_delegated_spend(coin, conditions)))])
    outputs = [Coin.from_json_dict(c) for c in data['outputs'].values()]
    request = ExactExecutionRequest(ExactExecutionAction.VOUCHER_TERMINAL,
        bytes32.from_hexstr(data['purchaseId']), bytes32.from_hexstr(data['artifactHash']), bytes32(bytes([50])*32),
        tuple(ExactExecutionOutput(c.name(), c.puzzle_hash, c.amount) for c in outputs))
    executor = KeyOfSolomonExactExecutor.__new__(KeyOfSolomonExactExecutor)
    executor.url = 'https://synthetic-executor.invalid'
    executor.private_key = AugSchemeMPL.key_gen(b'public-synthetic-refund-handoff!!')
    executor.verify, executor.cert, executor.timeout_seconds = True, None, 1
    captured = []
    async def receive(request):
        captured.append(request.content)
        return httpx.Response(200)
    prepared=PreparedProtocolBundle(bundle,100,'0x'+coin.name().hex())
    original_client=httpx.AsyncClient
    with patch('solslot_api.kos_exact_execution.httpx.AsyncClient', side_effect=lambda **kwargs:original_client(transport=httpx.MockTransport(receive))):
        await executor.dispatch(request, prepared)
        document=_document(mode='REFUND_OWNER',voucher_action=1,request=request,prepared=prepared,signer_indices=(0,1),
            role_outputs={key:Coin.from_json_dict(value) for key,value in data['outputs'].items()},bindings=data['bindings'])
        document['refundProtocolSignature']='0x'+bytes(protocol.aggregated_signature).hex()
        # The chain clock has advanced past the original owner/fee window.
        continued=build_continuation(document,SimpleNamespace(faucet=faucet),deadline+1,
            data['reviewVector']['selected']['refundDeadline'])
        await executor.dispatch(replace(request,refund_continuation=tuple(bytes32.from_hexstr(v) for v in continued['request']['refundContinuation'])),
            PreparedProtocolBundle(SpendBundle.from_json_dict(continued['prepared']['spendBundle']),100,prepared.fee_coin_id))
    variant=retime_native_refund(protocol,data['bindings']['vaultInputCoinId'],
        data['reviewVector']['intent']['currentTimestamp']+1)
    variant=SpendBundle([*variant.coin_spends,spend],bundle.aggregated_signature)
    from solslot_api.wallet_offer_worker import run_offer_job
    from chia.wallet.wallet_spend_bundle import WalletSpendBundle
    await run_offer_job('swap_signature',bundle=WalletSpendBundle.from_bytes(bytes(variant)),network='testnet11')
    Path(str(destination)+'.observed-variant.json').write_text(json.dumps(variant.to_json_dict(),sort_keys=True)+'\n')
    assert len(captured) == 2
    Path(destination).write_bytes(captured[0])
    Path(str(destination)+'.continuation.json').write_bytes(captured[1])
    Path(str(destination)+'.metadata.json').write_text(json.dumps(dict(
        synthetic=True, source='API production dispatch through HTTPX MockTransport; no network',
        publicKey='0x'+bytes(executor.private_key.get_g1()).hex(), bodyBytes=len(captured[0])), indent=2)+'\n')


if __name__ == '__main__':
    asyncio.run(export(sys.argv[1]))
