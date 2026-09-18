"""Export real draft API preparation against synthetic provider/authority data."""
import argparse
import asyncio
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from pytest import MonkeyPatch
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH, SINGLETON_LAUNCHER_HASH
from solslot_puzzles import load_puzzle
from tests.test_redemption_review_execution import FIXTURE, decode, setup


async def export(genesis_path, output):
    base = json.loads(genesis_path.read_text())["vectors"][0]["artifact"]
    vectors = []
    with TemporaryDirectory(prefix="synthetic-redemption-export-") as directory:
        for evm in (False, True):
            args = decode(FIXTURE["vectors"][int(evm)]["args"])
            hx = lambda value: "0x" + bytes(value).hex()
            artifact = deepcopy(base)
            artifact["launcherIds"]["pool"] = hx(args["pool_launcher_id"])
            artifact["puzzleHashes"]["deedLauncherPuzzleHash"] = hx(args["deed_singleton_struct"].rest().rest().as_atom())
            artifact["permanentRules"]["zkPassportPolicyHash"] = hx(args["zkpassport_bridge_policy_hash"])
            tail = load_puzzle("pool_token_tail.clsp").curry(SINGLETON_MOD_HASH, args["pool_launcher_id"], SINGLETON_LAUNCHER_HASH)
            artifact["permanentRules"]["solsTailHash"] = hx(tail.get_tree_hash())
            artifact["puzzleHashes"]["poolTokenTailHash"] = hx(tail.get_tree_hash())
            artifact["genesisPlan"]["trustedAssets"] = {"wusdcBAssetId": hx(args["plan"].payment_asset_id)}
            artifact["sourceShas"] = {"api": "a" * 40, "protocol": "b" * 40}
            with MonkeyPatch.context() as monkeypatch:
                t = await setup(monkeypatch, Path(directory) / str(evm), evm, artifact)
                vectors.append({"name": "evm" if evm else "bls", "intent": t.prepared, "artifact": artifact,
                    "coordinates": {"poolLauncherId": hx(args["pool_launcher_id"]), "bridgePolicyHash": hx(args["zkpassport_bridge_policy_hash"])},
                    "session": {"authType": "evm" if evm else "chia_bls", "address": t.vector["ownerAddress"],
                        "compressedPubkey": hx(args["vault_owner_pubkey"]), "vaultLauncherId": hx(args["vault_launcher_id"]),
                        "network": "testnet11", "experienceMode": "testnet-alpha", "createdAt": t.prepared["currentStateEvidence"]["observedAt"] * 1000,
                        "walletSource": "evm" if evm else "google"},
                    "vault": {"confirmed": True, "current_coin_id": hx(args["vault_coin"].name()),
                        "vault_full_puzhash": hx(args["vault_coin"].puzzle_hash), "identity_attest_root": hx(args["identity_attest_root"])}})
    output.write_text(json.dumps({"synthetic": True, "nowSeconds": max(v["intent"]["currentStateEvidence"]["observedAt"] for v in vectors),
        "vectors": vectors}, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("genesis", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    asyncio.run(export(args.genesis, args.output))
