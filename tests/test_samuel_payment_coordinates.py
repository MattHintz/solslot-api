"""Cross-chain replay boundaries for the pending native bridge coordinate schema."""
import copy
import pytest
from solslot_api.omnichain_evidence import OmnichainEvidenceError, _selected_samuel_base


def coordinates(chain):
    if chain == 84532:
        return {"schemaVersion": 3, "baseSepolia": {"chainId": 84532}}
    return {"schemaVersion": 4, "paymentChainId": 8453, "testOnly": True,
            "validatorIdentityDomain": "solslot-alpha-native-bridge-testnet11-base-mainnet",
            "baseMainnet": {"chainId": 8453}}


@pytest.mark.parametrize("chain", [84532, 8453])
def test_accepts_only_matching_network_projection(chain):
    value = coordinates(chain)
    assert _selected_samuel_base(value, chain_id=chain, chia_network="testnet11")["chainId"] == chain
    with pytest.raises(OmnichainEvidenceError):
        _selected_samuel_base(value, chain_id=8453 if chain == 84532 else 84532, chia_network="testnet11")
    with pytest.raises(OmnichainEvidenceError):
        _selected_samuel_base(value, chain_id=chain, chia_network="mainnet")


@pytest.mark.parametrize("overrides", [
    {"schemaVersion": 3}, {"paymentChainId": "8453"}, {"paymentChainId": 84532},
    {"testOnly": False}, {"testOnly": 1}, {"validatorIdentityDomain": "solslot-alpha-warp-testnet11-base-sepolia"},
    {"baseSepolia": {"chainId": 84532}}, {"baseMainnet": {"chainId": 84532}},
    {"baseMainnet": {"chainId": "8453"}}, {"baseMainnet": None},
])
def test_rejects_relabeling_or_ambiguous_base_coordinate_evidence(overrides):
    value = {**coordinates(8453), **copy.deepcopy(overrides)}
    with pytest.raises(OmnichainEvidenceError):
        _selected_samuel_base(value, chain_id=8453, chia_network="testnet11")


def test_legacy_schema_cannot_carry_an_unbound_mainnet_projection():
    for extra in ({"baseMainnet": {"chainId": 8453}}, {"paymentChainId": 8453}):
        with pytest.raises(OmnichainEvidenceError):
            _selected_samuel_base({**coordinates(84532), **extra}, chain_id=84532, chia_network="testnet11")
