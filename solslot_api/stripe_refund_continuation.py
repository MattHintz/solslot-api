"""Same-input, same-fee Stripe owner refund continuation; no claim release."""
from copy import deepcopy
from types import SimpleNamespace
import time

from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode as Op
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD
from chia_rs import AugSchemeMPL, G2Element, SpendBundle

from .refund_continuation import retime_native_refund, vault_refund_timestamp
from .sols_swap_execution import hx
from .voucher_refund_funding import fee_spend


def fee_deadline(spend):
    puzzle=Program.from_bytes(bytes(spend.puzzle_reveal))
    module,args=puzzle.uncurry()
    if module!=MOD or len(list(args.as_iter()))!=1:
        raise ValueError('Refund sponsor must use its original standard puzzle')
    solution=Program.from_bytes(bytes(spend.solution));top=list(solution.as_iter())
    if bytes(solution)!=bytes(spend.solution) or len(top)!=3 or top[0]!=Program.to(0) or top[2]!=Program.to(0):
        raise ValueError('Refund sponsor solution is not canonical')
    if top[1].first().as_int()!=1:
        raise ValueError('Refund sponsor must quote its conditions')
    rows=list(top[1].rest().as_iter()); found=[]
    for i,row in enumerate(rows):
        values=list(row.as_iter())
        if values[0].as_atom()==Op.ASSERT_BEFORE_SECONDS_ABSOLUTE.value:
            if len(values)!=2 or values[1]!=Program.to(values[1].as_int()):
                raise ValueError('Refund sponsor deadline is not canonical')
            found.append(values[1].as_int());rows[i]=Program.to([Op.ASSERT_BEFORE_SECONDS_ABSOLUTE,0])
    if len(found)>1 or any(not 0<n<2**63 for n in found):
        raise ValueError('Refund sponsor deadline is ambiguous')
    top[1]=Program.to((1,Program.to(rows)))
    return found[0] if found else None,Program.to(top)


def same_effects(previous,candidate):
    old=SpendBundle.from_json_dict(previous['prepared']['spendBundle'])
    new=SpendBundle.from_json_dict(candidate['prepared']['spendBundle'])
    if previous['mode']!='REFUND_OWNER' or len(old.coin_spends)!=5 or len(new.coin_spends)!=5:
        raise ValueError('Only an existing owner refund can continue')
    vault_id=previous['bindings']['vaultInputCoinId'];fee_id=previous['prepared']['feeCoinId']
    old_fee=next(s for s in old.coin_spends if hx(s.coin.name())==fee_id)
    new_fee=next(s for s in new.coin_spends if hx(s.coin.name())==fee_id)
    old_protocol=SpendBundle([s for s in old.coin_spends if s!=old_fee],old.aggregated_signature)
    new_protocol=[s for s in new.coin_spends if s!=new_fee]
    vault=next(s for s in new_protocol if hx(s.coin.name())==vault_id);now=vault_refund_timestamp(vault)
    expected_spends=retime_native_refund(old_protocol,vault_id,now).coin_spends
    if (new_protocol!=expected_spends or old_fee.coin!=new_fee.coin or old_fee.puzzle_reveal!=new_fee.puzzle_reveal
            or old.additions()!=new.additions() or old.removals()!=new.removals()):
        raise ValueError('Refund continuation changed its inputs, outputs or protocol')
    before,old_mask=fee_deadline(old_fee);after,new_mask=fee_deadline(new_fee)
    if old_mask!=new_mask or ((before is None)!=(after is None)):
        raise ValueError('Refund continuation changed sponsor conditions')
    if before is None:
        if old.aggregated_signature!=new.aggregated_signature:
            raise ValueError('Legacy refund authorization changed')
    elif not (before<after<=now+120 and now<after):
        raise ValueError('Refund sponsor deadline did not renew in its vault window')
    expected=deepcopy(previous);expected['prepared']['spendBundle']=new.to_json_dict()
    expected['prepared']['spendBundleId']=hx(new.name())
    expected['request']['refundContinuation']=[hx(old.name()),vault_id,fee_id]
    if candidate!=expected:
        raise ValueError('Refund continuation changed its immutable identity or fee')


def build_continuation(execution,submitter,timestamp,refund_deadline):
    old=SpendBundle.from_json_dict(execution['prepared']['spendBundle'])
    fee_id=execution['prepared']['feeCoinId'];vault_id=execution['bindings']['vaultInputCoinId']
    fee=next(s for s in old.coin_spends if hx(s.coin.name())==fee_id)
    old_deadline,_=fee_deadline(fee)
    protocol=SpendBundle([s for s in old.coin_spends if s!=fee],
        G2Element.from_bytes(bytes.fromhex(execution['refundProtocolSignature'][2:])) if old_deadline else old.aggregated_signature)
    renewed=retime_native_refund(protocol,vault_id,timestamp)
    if old_deadline is None:
        next_bundle=SpendBundle([*renewed.coin_spends,fee],old.aggregated_signature)
    else:
        total=int(execution['prepared']['feeMojos'])
        deadline=min(timestamp+120,refund_deadline) if int(execution['voucherAction'])==1 else timestamp+120
        context=SimpleNamespace(vault_spend=protocol.coin_spends[0],vault_coin=protocol.coin_spends[0].coin,
            provisional=SimpleNamespace(coin_spends=protocol.coin_spends[1:]))
        original,conditions=fee_spend(submitter,context,fee.coin,total,old_deadline)
        if original!=fee:
            raise ValueError('Refund sponsor key or retained protocol signature changed')
        context.vault_spend=renewed.coin_spends[0]
        spend,conditions=fee_spend(submitter,context,fee.coin,total,deadline)
        signature=G2Element.from_bytes(submitter.faucet.sign_refund_fee_deadline(old,protocol.aggregated_signature,fee_id,conditions,timestamp))
        next_bundle=SpendBundle([*renewed.coin_spends,spend],AugSchemeMPL.aggregate([protocol.aggregated_signature,signature]))
    document=deepcopy(execution);document['prepared']['spendBundle']=next_bundle.to_json_dict()
    document['prepared']['spendBundleId']=hx(next_bundle.name())
    document['request']['refundContinuation']=[hx(old.name()),vault_id,fee_id]
    same_effects(execution,document)
    return document


async def renew_stripe_refund(worker,series,voucher,execution):
    if execution['mode']!='REFUND_OWNER':return execution
    old=SpendBundle.from_json_dict(execution['prepared']['spendBundle'])
    vault=next(s for s in old.coin_spends if hx(s.coin.name())==execution['bindings']['vaultInputCoinId'])
    deadline=vault_refund_timestamp(vault)+120;now=int(time.time())
    if now<deadline:return execution
    from .chia_snapshot import PrimaryReadSnapshot
    submitter=worker.submitter
    async with submitter.funding_guard:
        async with PrimaryReadSnapshot(worker.coinset,'testnet11') as snapshot:
            if snapshot.transaction_time<deadline:return execution
            if int(execution['voucherAction'])==1 and now>=int(series['terms']['refundDeadline']):
                raise ValueError('Immutable presale refund deadline passed; retain authorization for reconciliation')
            if (not submitter.policy.enabled or submitter.faucet.network!='testnet11'
                    or not 1<=int(execution['prepared']['feeMojos'])<=submitter.policy.maximum_mojos):
                raise ValueError('Refund sponsor policy no longer permits the original fee')
            candidate=build_continuation(execution,submitter,now,int(series['terms']['refundDeadline']))
            from .wallet_offer_worker import run_offer_job
            from chia.wallet.wallet_spend_bundle import WalletSpendBundle
            await run_offer_job('swap_signature',bundle=WalletSpendBundle.from_json_dict(candidate['prepared']['spendBundle']),network='testnet11')
            worker._require_dispatch()
            observation=await snapshot.finish([(f'input_{i}',s.coin) for i,s in enumerate(old.coin_spends)],
                dict(action='VOUCHER_REFUND_CONTINUATION',previousBundleId=hx(old.name()),
                    nextBundleId=candidate['prepared']['spendBundleId'],quoteExpiresAt=now+90))
        worker.presales.advance_stripe_refund_attempt(series['termsHash'],voucher['serial'],execution,candidate,observation)
    return candidate
