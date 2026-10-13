"""Exact pre-genesis custody launch assembly; no keys, selection or network I/O.

The explicit launch workflow supplies the spend of the already reserved parent.
This assembler cannot choose another coin, substitute a destination, issue SGT,
or treat local construction as confirmation. Native admission remains required.
"""
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import launch_conditions_and_coinsol
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_transactions import NativeOperation, SingletonTip
from .generation_preparation import GenerationPreparation


def build_recipient_launch(preparation: GenerationPreparation, slot: int, funding_spend: CoinSpend,
                           *, trusted_preparation_hash: str) -> NativeOperation:
    frozen=GenerationPreparation.model_validate_json(preparation.model_dump_json(by_alias=True))
    if frozen.manifest_hash!=trusted_preparation_hash:
        raise ValueError('recipient launch requires the exact reviewed preparation')
    if type(slot) is not int or slot not in (1,2,3):
        raise ValueError('recipient slot must be 1, 2 or 3')
    admin=frozen.administrators[slot-1]
    parent=funding_spend.coin
    reveal=Program.from_bytes(bytes(funding_spend.puzzle_reveal))
    if ('0x'+parent.name().hex()!=admin.custody.funding_coin_id or parent.amount<1
            or reveal.get_tree_hash()!=parent.puzzle_hash):
        raise ValueError('funding spend differs from the reserved recipient parent')
    _,launcher=launch_conditions_and_coinsol(parent,frozen.custody_inner(admin),[],uint64(1))
    if '0x'+launcher.coin.name().hex()!=admin.custody.launcher_id:
        raise ValueError('recipient launcher differs from the frozen destination')
    expected=[launcher.coin]
    if parent.amount>1:
        from chia.types.blockchain_format.coin import Coin
        expected.append(Coin(parent.name(),parent.puzzle_hash,uint64(int(parent.amount)-1)))
    additions,_=compute_additions_with_cost(funding_spend,max_cost=11_000_000_000)
    if sorted(additions,key=lambda c:c.name())!=sorted(expected,key=lambda c:c.name()):
        raise ValueError('recipient funding must create only its exact launcher and unchanged-owner change')
    children,_=compute_additions_with_cost(launcher,max_cost=5_000_000)
    if len(children)!=1:
        raise ValueError('recipient launcher has an unexpected output set')
    tip=SingletonTip(bytes32.from_hexstr(admin.custody.launcher_id),frozen.custody_inner(admin),children[0],launcher).validate()
    return NativeOperation(bytes32.from_hexstr(frozen.generation_id),'CREATE_RECIPIENT_VAULT',
        (funding_spend,launcher),(tip,))
