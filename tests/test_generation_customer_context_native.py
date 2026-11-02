"""Customer bindings require the actual complete native generation history."""
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs.sized_bytes import bytes32
from chia_rs import AugSchemeMPL
from chia.types.blockchain_format.program import Program

from solslot_api.generation_customer_context import (
    current_customer_launch_bindings, CustomerRegistrationUnavailable,
)
from solslot_api.generation_index import GenerationIndexReconciler, GenerationIndexStore
from solslot_api.generation_customer_launch import CustomerLaunchConsent, assemble_customer_launch
from solslot_api.singleton_launcher import launcher_coin_for_parent
from tests.test_generation_genesis_core import core
from tests.test_generation_genesis_launch import complete


@pytest.mark.asyncio
async def test_current_customer_bindings_follow_native_generation_and_close_on_stale_or_substituted_state(core, tmp_path):
    c = core
    _, _, built = complete(c)
    assert await c.client.push_tx(built.operation.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c.sim.farm_block()
    path = tmp_path / 'prep.json'
    path.write_text(c.prep.model_dump_json(by_alias=True))
    settings = SimpleNamespace(network='testnet11', deployment_generation_id=c.prep.generation_id,
        generation_preparation_path=str(path), generation_preparation_hash=c.prep.manifest_hash)
    store = GenerationIndexStore(str(tmp_path / 'index.db'), c.prep.generation_id, '0x' + '23' * 32)
    index = GenerationIndexReconciler(built.anchor, store, c.provider)
    now = int(time.time())
    with pytest.raises(CustomerRegistrationUnavailable):
        current_customer_launch_bindings(settings, index, now=now)
    await index.run_once()
    now = int(time.time())
    bindings = current_customer_launch_bindings(settings, index, now=now)
    assert bindings.generation == bytes32.from_hexstr(c.prep.generation_id)
    assert bindings.preparation_manifest == bytes32.from_hexstr(c.prep.manifest_hash)
    assert bindings.pool_launcher == bytes32.from_hexstr(c.prep.coordinates['pool'].launcher_id)
    assert bindings.bridge_policy == bytes32.from_hexstr(c.prep.bridge_policy_hash)

    # Create a genuinely new, previously unregistered customer vault using a
    # current unspent standard-p2 funding output and a fresh synthetic owner.
    # The native simulator verifies the entire signed transaction, not only
    # its expected outputs or an API response.
    funds = [r.coin for r in await c.client.get_coin_records_by_puzzle_hash(c.faucet.address_puzzle_hash)
             if not r.spent and r.coin.amount > 1]
    funding = min(funds, key=lambda coin: coin.name())
    owner_key = AugSchemeMPL.key_gen(b'new customer owner fixture only!!')
    consent = CustomerLaunchConsent(bindings, bytes32(b'n' * 32),
        '0x' + bytes(owner_key.get_g1()).hex(), 'chia_bls', funding.name(),
        launcher_coin_for_parent(funding).name(), now + 200)
    digest = bytes(Program.to(('Chia Signed Message', consent.bls_message())).get_tree_hash())
    signature = '0x' + bytes(AugSchemeMPL.sign(owner_key, digest)).hex()
    creation = assemble_customer_launch(bindings=bindings, consent=consent,
        signature=signature, funding_coin=funding, faucet=c.faucet, now=now)
    from chia_rs import SpendBundle
    # The funding signature must commit the ephemeral launcher to the exact
    # reviewed custody output. Removing or redirecting that spend must fail
    # consensus even when the original funding signature is retained.
    parent_only = SpendBundle([creation.spends[0]], creation.aggregated_signature)
    assert (await c.client.push_tx(parent_only))[0] != MempoolInclusionStatus.SUCCESS
    from chia.types.coin_spend import make_spend
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER
    redirected = make_spend(creation.spends[1].coin, SINGLETON_LAUNCHER,
        Program.to([Program.to(1).get_tree_hash(), 1, []]))
    diverted_bundle = SpendBundle([creation.spends[0], redirected], creation.aggregated_signature)
    assert (await c.client.push_tx(diverted_bundle))[0] != MempoolInclusionStatus.SUCCESS
    assert await c.client.push_tx(creation.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c.sim.farm_block()
    tip, = creation.successors
    confirmed = await c.client.get_coin_record_by_name(tip.coin.name())
    assert confirmed is not None and not confirmed.spent
    assert confirmed.coin == tip.coin
    assert (await c.client.push_tx(creation.bundle()))[0] != MempoolInclusionStatus.SUCCESS

    # A restarted process cannot use a persisted READY claim as authority.
    restarted = GenerationIndexReconciler(built.anchor, store, c.provider)
    with pytest.raises(CustomerRegistrationUnavailable):
        current_customer_launch_bindings(settings, restarted, now=now)
    with pytest.raises(CustomerRegistrationUnavailable):
        current_customer_launch_bindings(settings, index, now=now + 31)

    original = index.evidence
    pool_id = next(k for k, h in original.economic_components.items() if h.state.launcher_id == bindings.pool_launcher)
    history = original.economic_components[pool_id]
    changed_pool = replace(history.state, permanent=replace(history.state.permanent, vault_v2_mod_hash=bytes32(b'x' * 32)))
    index.evidence = replace(original, economic_components={**original.economic_components,
        pool_id: replace(history, state=changed_pool)})
    with pytest.raises(CustomerRegistrationUnavailable):
        current_customer_launch_bindings(settings, index, now=now)
    index.evidence = original
    store.fail('NODE_UNAVAILABLE', now + 1)
    with pytest.raises(CustomerRegistrationUnavailable):
        current_customer_launch_bindings(settings, index, now=now + 1)
