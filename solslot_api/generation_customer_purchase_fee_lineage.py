"""Conservative accounting for inherited and current fee exposure.

This is an arithmetic primitive, not a funding authority, evidence collector,
transaction submitter, persistent ledger, or cutover mechanism. Callers must
supply a complete independently reconciled snapshot under a durable all-role
fence before treating any result as an operational limit.
"""
from dataclasses import dataclass
import re

_ID=re.compile(r'^0x[0-9a-f]{64}$')
_STATES=frozenset(('CONFIRMED','SIGNED','FUNDED','PENDING','UNKNOWN','PREPARED'))


@dataclass(frozen=True)
class FeeExposure:
    # Stable identity of an exact funded transaction or one unfunded operation.
    identity: str
    maximum_mojos: int
    state: str


@dataclass(frozen=True)
class FeeLineageBalance:
    limit_mojos: int
    committed_mojos: int
    remaining_mojos: int
    distinct_exposures: int


def calculate_fee_lineage(limit_mojos, exposures):
    """Count all historic and in-flight exposure; never infer freed budget.

    Identical observations of the same exact item deduplicate. Conflicting
    amount observations fail closed instead of choosing a lower value. State
    differences can be independent observations of the same exact item and do
    not affect its reservation. Unknown and unbroadcast work count at maximum.
    """
    if type(limit_mojos) is not int or not 0<limit_mojos<2**64:
        raise ValueError('CURRENT_FEE_LINEAGE_FINITE_LIMIT_REQUIRED')
    if not isinstance(exposures,(list,tuple)):
        raise ValueError('CURRENT_FEE_LINEAGE_EXPOSURES_REQUIRED')
    amounts={}
    for item in exposures:
        if (not isinstance(item,FeeExposure) or not isinstance(item.identity,str)
                or not _ID.fullmatch(item.identity) or item.state not in _STATES
                or type(item.maximum_mojos) is not int or not 0<=item.maximum_mojos<2**64):
            raise ValueError('CURRENT_FEE_LINEAGE_EXPOSURE_INVALID')
        if item.identity in amounts and amounts[item.identity]!=item.maximum_mojos:
            raise ValueError('CURRENT_FEE_LINEAGE_CONFLICTING_EXPOSURE')
        amounts[item.identity]=item.maximum_mojos
    committed=sum(amounts.values())
    if committed>limit_mojos:
        raise ValueError('CURRENT_FEE_LINEAGE_LIMIT_EXCEEDED')
    return FeeLineageBalance(limit_mojos,committed,limit_mojos-committed,len(amounts))
