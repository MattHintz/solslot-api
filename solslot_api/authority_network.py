"""Authority network selection; historical enrollment retains its old domain."""

from typing import Any, Mapping


def authority_network_name(chain_id: int) -> str:
    if type(chain_id) is not int or chain_id not in (8453, 84532):
        raise ValueError("unsupported Authority V3 EVM chain")
    return {8453: "baseMainnet", 84532: "baseSepolia"}[chain_id]


def authority_chain_id(document: Mapping[str, Any]) -> int:
    """Read a verified artifact or protected ceremony draft, never wallet input."""
    activation = document.get("enrollmentActivation")
    chain = document.get("evmChainId", 11155111)
    if type(chain) is not int:
        raise ValueError("unsupported Authority V3 EVM chain")
    if activation is not None:
        from solslot_puzzles.enrollment_networks import enrollment_operational_chain_id

        if chain != enrollment_operational_chain_id(activation):
            raise ValueError("Authority V3 chain differs from enrollment activation")
    elif chain not in (11155111, 84532):
        raise ValueError("Authority V3 mainnet requires versioned enrollment activation")
    selected = 84532 if chain == 11155111 else chain
    if "paymentChainId" in document:
        selected = document["paymentChainId"]
        authority_network_name(selected)
    nested = document.get("genesisPlan")
    if isinstance(nested, Mapping) and (
        ("paymentChainId" in nested) != ("paymentChainId" in document)
        or nested.get("paymentChainId") != document.get("paymentChainId")
    ):
        raise ValueError("Authority V3 payment chain differs from the signed plan")
    authority_network_name(selected)
    return selected


def validate_authority_network(evidence: Mapping[str, Any], chain_id: int) -> None:
    if (type(evidence.get("chainId")) is not int
            or evidence.get("chainId") != chain_id
            or evidence.get("network") != authority_network_name(chain_id)):
        raise ValueError("Authority V3 evidence is on the wrong EVM network")


def ceremony_authority_document(record: Mapping[str, Any]) -> Mapping[str, Any]:
    """Use protected plan metadata once present; preserve pre-plan legacy behavior."""
    draft = record.get("draft") or {}
    plan = record.get("plan")
    if not isinstance(draft, Mapping):
        raise ValueError("Authority V3 ceremony draft is invalid")
    if not isinstance(plan, Mapping):
        return draft
    if plan.get("evmChainId", 11155111) != draft.get("evmChainId", 11155111):
        raise ValueError("Authority V3 plan identity chain differs from the ceremony")
    return plan
