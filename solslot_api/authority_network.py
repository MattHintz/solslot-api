"""Authority network selection; historical enrollment retains its old domain."""

from typing import Any, Mapping

from solslot_puzzles.enrollment_networks import enrollment_operational_chain_id


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
        if chain != enrollment_operational_chain_id(activation):
            raise ValueError("Authority V3 chain differs from enrollment activation")
    elif chain not in (11155111, 84532):
        raise ValueError("Authority V3 mainnet requires versioned enrollment activation")
    selected = 84532 if chain == 11155111 else chain
    authority_network_name(selected)
    return selected


def validate_authority_network(evidence: Mapping[str, Any], chain_id: int) -> None:
    if (type(evidence.get("chainId")) is not int
            or evidence.get("chainId") != chain_id
            or evidence.get("network") != authority_network_name(chain_id)):
        raise ValueError("Authority V3 evidence is on the wrong EVM network")
