"""Continue the same owner refund without releasing or changing its effects.

The legacy vault's m signature omits its timestamp. Renewal is therefore a
continuation of the existing authorization, never evidence it was revoked.
"""
from copy import deepcopy
import time

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import SpendBundle

from .sols_swap_execution import hx, _primary_peak, _record_height


def vault_refund_timestamp(spend):
    from solslot_puzzles import load_puzzle
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD
    puzzle = Program.from_bytes(bytes(spend.puzzle_reveal))
    if puzzle.get_tree_hash() != spend.coin.puzzle_hash or int(spend.coin.amount) != 1:
        raise ValueError('Refund continuation changed its vault')
    outer, args = puzzle.uncurry()
    args = list(args.as_iter())
    if outer != SINGLETON_MOD or len(args) != 2:
        raise ValueError('Refund continuation requires the pinned singleton')
    inner, _ = args[1].uncurry()
    if inner != load_puzzle('vault_singleton_inner_v2.clsp'):
        raise ValueError('Refund continuation requires the pinned m authorization')
    solution = Program.from_bytes(bytes(spend.solution))
    # Round-trip rejects trailing bytes and noncanonical serialization.
    if bytes(solution) != bytes(spend.solution):
        raise ValueError('Refund continuation solution is not canonical')
    top = list(solution.as_iter())
    inner = list(top[2].as_iter()) if len(top) == 3 else []
    action = list(inner[4].as_iter()) if len(inner) == 5 else []
    if (len(action) != 4 or inner[3].as_atom() != b'm' or action[3].as_atom() != b''
            or action[1].as_atom() != load_puzzle('voucher_burn_v2.clsp').get_tree_hash()):
        raise ValueError('Refund continuation must preserve the BLS voucher burn')
    stamp = action[2].as_int()
    if not 0 < stamp < 2**63 or Program.to(stamp) != action[2]:
        raise ValueError('Refund continuation has an invalid timestamp')
    return stamp


def retime_native_refund(bundle, vault_coin_id, timestamp):
    if len(bundle.coin_spends) != 4 or type(timestamp) is not int or not 0 < timestamp < 2**63:
        raise ValueError('Owner refund continuation requires four exact inputs')
    spends = list(bundle.coin_spends)
    indexes = [i for i,s in enumerate(spends) if hx(s.coin.name()) == vault_coin_id]
    if len(indexes) != 1:
        raise ValueError('Refund continuation vault input is missing')
    i = indexes[0]; spend = spends[i]
    old = vault_refund_timestamp(spend)
    if timestamp <= old:
        raise ValueError('Refund continuation must advance its timestamp')
    spends[i] = _vault_at_timestamp(spend,timestamp)
    result = SpendBundle(spends,bundle.aggregated_signature)
    if result.additions() != bundle.additions():
        raise ValueError('Refund continuation changed its outputs')
    return result


def _vault_at_timestamp(spend, timestamp):
    vault_refund_timestamp(spend)
    if type(timestamp) is not int or not 0 < timestamp < 2**63:
        raise ValueError('Refund timestamp is invalid')
    top = list(Program.from_bytes(bytes(spend.solution)).as_iter())
    inner = list(top[2].as_iter()); action = list(inner[4].as_iter())
    action[2] = Program.to(timestamp); inner[4] = Program.to(action); top[2] = Program.to(inner)
    return make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),Program.to(top))


def same_refund_spends(retained, actual):
    """Recognize on-chain m malleability, never relax another signed field.

    A public submitter can alter this historical timestamp in either direction.
    The fee spend, including its separately signed deadline, must remain exact.
    This comparison is only for already-confirmed primary-chain spends.
    """
    if retained.coin_spends == actual:
        return True
    if len(actual) != len(retained.coin_spends) or len(actual) not in (4,5):
        return False
    differences = [(a,b) for a,b in zip(retained.coin_spends,actual) if a!=b]
    if len(differences)!=1:
        return False
    before,after=differences[0]
    if before.coin!=after.coin or before.puzzle_reveal!=after.puzzle_reveal:
        return False
    try:
        expected=_vault_at_timestamp(before,vault_refund_timestamp(after))
        observed=SpendBundle(actual,retained.aggregated_signature)
        return expected==after and observed.additions()==retained.additions()
    except (ValueError,TypeError,IndexError):
        return False


async def confirmed_refund_attempt(node, executions, output_id):
    """One primary anchor, every actual spend and output, including sponsor fee."""
    if not executions:
        raise ValueError('Refund confirmation requires retained signed attempts')
    bundles = [SpendBundle.from_json_dict(e['spendBundle']) for e in executions]
    peak = await _primary_peak(node)
    output = next(c for c in bundles[0].additions() if hx(c.name()) == output_id)
    raw = await node.get_coin_record_by_name_primary(output_id)
    if raw is None:
        return None
    height, _ = _record_height(raw,output)
    if height > peak[0]:
        raise ValueError('Refund output is ahead of the primary chain')
    actual = []
    from chia.types.coin_spend import CoinSpend
    for expected in bundles[0].coin_spends:
        raw = await node.get_coin_record_by_name_primary(hx(expected.coin.name()))
        if raw is None:
            return None
        _,spent = _record_height(raw,expected.coin)
        if spent != height:
            raise ValueError('Refund inputs did not settle atomically')
        value = await node.get_puzzle_and_solution_primary(hx(expected.coin.name()),height)
        if value is None:
            return None
        actual.append(CoinSpend.from_json_dict(value))
    winners = [b for b in bundles if b.coin_spends == actual]
    exact=bool(winners)
    if not winners:
        winners=[b for b in bundles if same_refund_spends(b,actual)]
    if not winners:
        raise ValueError('Refund input changed its retained authorization or effects')
    winner = winners[0]
    for coin in winner.additions():
        raw = await node.get_coin_record_by_name_primary(hx(coin.name()))
        if raw is None:
            return None
        if _record_height(raw,coin)[0] != height:
            raise ValueError('Refund outputs did not settle atomically')
    if await _primary_peak(node) != peak:
        return None
    evidence=dict(kind='EXACT_RETAINED_SPENDS' if exact else 'EQUIVALENT_VAULT_TIMESTAMP',
        authorizationBundleId=hx(winner.name()),confirmedHeight=height,
        primaryAnchor=dict(height=peak[0],headerHash=hx(peak[1])),
        observedCoinSpends=[s.to_json_dict() for s in actual])
    # The chain does not expose a transaction's aggregate signature or full
    # aggregation boundaries. Do not invent a bundle ID for observed variants.
    return hx(winner.name()),height,evidence


async def renew_native_refund(worker, series, voucher, execution):
    vault_id = execution['bindings'].get('vault_input_coin_id')
    if not vault_id:
        return execution  # Automatic expiry refunds have no owner m branch.
    bundle = SpendBundle.from_json_dict(execution['spendBundle'])
    vault = next(s for s in bundle.coin_spends if hx(s.coin.name()) == vault_id)
    deadline = vault_refund_timestamp(vault)+120
    now = int(time.time())
    if now < deadline:
        return execution
    from .chia_snapshot import PrimaryReadSnapshot
    async with PrimaryReadSnapshot(worker.coinset,'testnet11') as snapshot:
        if snapshot.transaction_time < deadline:
            return execution
        if int(voucher['refundAction']) == 1 and now >= int(series['terms']['refundDeadline']):
            raise ValueError('Immutable presale refund deadline passed; retain authorization for reconciliation')
        updated = deepcopy(execution)
        candidate = retime_native_refund(bundle,vault_id,now)
        from .wallet_offer_worker import run_offer_job
        from chia.wallet.wallet_spend_bundle import WalletSpendBundle
        await run_offer_job('swap_signature',bundle=WalletSpendBundle.from_bytes(bytes(candidate)),network='testnet11')
        worker._require_dispatch()
        receipt = await snapshot.finish([(f'input_{i}',s.coin) for i,s in enumerate(bundle.coin_spends)],
            dict(action='VOUCHER_REFUND_CONTINUATION',previousBundleId=hx(bundle.name()),nextBundleId=hx(candidate.name()),
                quoteExpiresAt=now+90))
    updated['spendBundle'] = candidate.to_json_dict()
    updated['bindings']['spend_bundle_id'] = hx(candidate.name())
    worker.presales.advance_native_refund_attempt(series['termsHash'],voucher['serial'],execution,updated,receipt)
    return updated
