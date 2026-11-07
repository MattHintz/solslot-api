"""Native authority for fresh customer creation, never old-record admission.

Only an already verified background index supplies authority. This read performs
no network request, transaction construction, reservation or identity lookup.
It grants no public route or fee authority.
"""
from chia_rs.sized_bytes import bytes32
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.generation_statutes import GenerationStatutes
from solslot_puzzles.generation_mint import GenerationMint

from .generation_customer_launch import CustomerLaunchBindings
from .generation_preparation import read_generation_preparation


class CustomerRegistrationUnavailable(ValueError):
    pass


def current_customer_launch_bindings(settings, index, *, now: int) -> CustomerLaunchBindings:
    """Derive custody pins from the current confirmed pool, not an API payload.

    A process restart, stale chain, changed preparation or incompatible module
    closes registration. The same wallet's old vault and receipt are never read.
    """
    from .generation_index import GenerationIndexReconciler
    from .generation_chain_evidence import GenerationChainEvidence
    if (type(now) is not int or now <= 0 or settings.network != 'testnet11'
            or not isinstance(index, GenerationIndexReconciler) or not index.verified
            or not isinstance(index.evidence, GenerationChainEvidence)):
        raise CustomerRegistrationUnavailable('fresh primary-node generation evidence is required')
    preparation = read_generation_preparation(settings)
    generation = bytes32.from_hexstr(preparation.generation_id)
    manifest = bytes32.from_hexstr(preparation.manifest_hash)
    anchor, evidence = index.anchor, index.evidence
    status = index.store.status(now, verified_in_process=True)
    checked = status.get('lastCheckedAt')
    if (status.get('generationId') != preparation.generation_id or status.get('status') != 'READY'
            or type(checked) is not int or not 0 <= now - checked <= 30
            or anchor.issuance.generation != generation
            or anchor.issuance.preparation_manifest_hash != manifest
            or anchor.administrator is None
            or {type(v) for v in anchor.economic_components}
            != {GenerationPool, GenerationStatutes, GenerationMint}):
        raise CustomerRegistrationUnavailable('current complete generation authority is unavailable')
    result = customer_bindings_from_evidence(preparation, anchor, evidence)
    snapshot = status.get('snapshot') or {}
    recorded = (snapshot.get('chainEvidence') or {}).get('registry') or {}
    if recorded.get('coinId') != '0x' + evidence.registry.current.coin.name().hex():
        raise CustomerRegistrationUnavailable('registration index and native registry evidence differ')
    pool_history = next(h for h in evidence.economic_components.values() if isinstance(h.state, GenerationPool))
    recorded_pool = (snapshot.get('componentEvidence') or {}).get('0x' + pool_history.state.component_id.hex()) or {}
    if recorded_pool.get('coinId') != '0x' + pool_history.current.coin.name().hex():
        raise CustomerRegistrationUnavailable('registration index and native pool evidence differ')
    return result


def customer_bindings_from_evidence(preparation, anchor, evidence) -> CustomerLaunchBindings:
    """Share custody checks with an independent signer that has read the chain.

    This primitive consumes reconstructed native evidence, never a browser or
    database projection. Public customer routes still require the fresh,
    in-process index above; signers reconstruct their own evidence instead.
    """
    from .generation_chain_evidence import GenerationChainEvidence
    if not isinstance(evidence, GenerationChainEvidence):
        raise CustomerRegistrationUnavailable('native generation evidence is required')
    generation = bytes32.from_hexstr(preparation.generation_id)
    manifest = bytes32.from_hexstr(preparation.manifest_hash)
    if (anchor.issuance.generation != generation
            or anchor.issuance.preparation_manifest_hash != manifest
            or anchor.administrator is None
            or {type(v) for v in anchor.economic_components}
            != {GenerationPool, GenerationStatutes, GenerationMint}):
        raise CustomerRegistrationUnavailable('complete generation authority is required')
    registry = evidence.registry.state
    coordinate = lambda name: bytes32.from_hexstr(preparation.coordinates[name].launcher_id)
    if (registry.generation != generation or registry.launcher_id != coordinate('registry')
            or registry.governance_id != coordinate('governance')
            or registry.administrator_id != coordinate('authority')
            or anchor.registry.launcher_id != registry.launcher_id):
        raise CustomerRegistrationUnavailable('registration preparation differs from native authority')
    pools = [h for h in evidence.economic_components.values() if isinstance(h.state, GenerationPool)]
    if len(pools) != 1:
        raise CustomerRegistrationUnavailable('one current confirmed pool is required')
    history, = pools
    pool = history.state
    module = load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash()
    if (pool.generation != generation or pool.launcher_id != coordinate('pool')
            or pool.registry_id != registry.launcher_id or pool.governance_id != registry.governance_id
            or pool.component() not in registry.components
            or pool.permanent.permanent_rules.network_id != generation
            or pool.permanent.permanent_rules.zkpassport_policy_hash != bytes32.from_hexstr(preparation.bridge_policy_hash)
            or pool.permanent.vault_v2_mod_hash != module
            or pool.permanent.p2_vault_mod_hash != load_puzzle('p2_vault.clsp').get_tree_hash()):
        raise CustomerRegistrationUnavailable('current pool cannot admit the reviewed customer custody module')
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
    for chain_history, launcher, inner in (
            (evidence.registry, registry.launcher_id, registry.inner()),
            (history, pool.launcher_id, pool.inner())):
        record = chain_history.current
        if (record.spent_height or record.confirmed_height <= 0 or record.coin.amount != 1
                or record.coin.puzzle_hash != puzzle_for_singleton(launcher, inner).get_tree_hash()):
            raise CustomerRegistrationUnavailable('registration custody pins do not match confirmed native outputs')
    return CustomerLaunchBindings(generation, manifest, pool.launcher_id,
        pool.permanent.permanent_rules.zkpassport_policy_hash, module).validate()
