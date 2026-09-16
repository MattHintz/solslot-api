"""Off-chain reader for the on-chain vault-version registry singleton.

This is the API's binding point against ``vault_version_registry_inner.clsp``
(solslot_protocol Brick 2) — the singleton that publishes the *canonical
current vault descriptor* on-chain so any backend-free client can detect
outdated vaults and offer a decentralized upgrade.  See
``research/SOLSLOT_VAULT_UPGRADE_DESIGN.md``.

This module mirrors :mod:`solslot_api.protocol_config` (the A.3 reader) and
:mod:`solslot_api.singletons` (the A.1/A.4 reader):

  * It re-derives the static ``vault_version_registry_mod_hash`` and the
    *current* ``vault_inner_mod_hash`` (the live vault code) from the
    compiled solslot_puzzles bundle — these bump only on a breaking puzzle
    upgrade, so they are materialised once at import time (reading them from
    a request worker thread panics pyo3's ``LazyNode is unsendable``).
  * It computes the deterministic ``canonical_params_hash`` and
    ``content_hash`` from the operator's current ``Settings`` (pool launcher
    id + zkPassport bridge policy hash + vault version).  This is the SAME
    ``content_hash`` the on-chain registry commits to via its
    ``CREATE_PUZZLE_ANNOUNCEMENT`` on every publish spend — so a frontend
    can independently recompute it from the singleton's puzzle reveal on
    coinset.org and verify the operator's published descriptor matches.
  * It surfaces the registry launcher coin id when the operator has
    launched the singleton, so clients can locate it on-chain.

What this module does NOT do (and never should): submit chain spends, hold
keys, or act as the *source of truth*.  The portal reads the registry
directly from chain; this API surface is a verification aid only.

The matching cross-language contract is enforced by
``solslot_protocol/tests/test_vault_version_registry.py``: the off-chain
``compute_content_hash`` / ``compute_canonical_params_hash`` here must
exactly equal the on-chain CLVM behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_driver import VAULT_INNER_MOD
from solslot_puzzles.vault_version_registry_driver import (
    vault_version_registry_inner_mod_hash as _registry_inner_mod_hash,
)

from .clvm_hash import list_hash, positive_clvm_int
from .config import Settings


def _strip0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


# Pre-compute the static mod-hash hex strings at import time.  The driver
# helpers internally walk a chia ``Program`` (LazyNode); reading them from a
# request worker thread panics with
# ``chia_protocol::lazy_node::LazyNode is unsendable``.  Materialising them
# here, on the import thread, keeps ``build_*_snapshot`` a pure construction.
_VAULT_VERSION_REGISTRY_MOD_HASH_HEX: str = (
    "0x" + _registry_inner_mod_hash().hex()
)
_VAULT_INNER_MOD_HASH_HEX: str = (
    "0x" + VAULT_INNER_MOD.get_tree_hash().hex()
)


@dataclass(frozen=True)
class VaultVersionRegistrySnapshot:
    """Deterministic snapshot of the vault-version registry descriptor.

    All fields are hex-encoded (``0x``-prefixed) for direct JSON inclusion
    on the ``/protocol`` endpoint, without leaking chia / chia_rs types to
    API consumers.

    The ``content_hash_hex`` field is the canonical binding point: it equals
    ``sha256tree([vault_inner_mod_hash, canonical_params_hash, vault_version])``
    — the exact value the on-chain registry singleton publishes.  Frontends
    can recompute it from the registry's puzzle reveal and refuse to treat a
    vault as "current" if the two diverge.
    """

    vault_version_registry_launcher_id_hex: Optional[str]
    """``0x``-prefixed launcher coin id of the on-chain registry singleton,
    or ``None`` when ``SOLSLOT_VAULT_VERSION_REGISTRY_LAUNCHER_ID`` is unset
    (i.e. the registry has not been deployed yet)."""

    vault_version_registry_mod_hash_hex: str
    """``0x``-prefixed tree hash of the uncurried
    ``vault_version_registry_inner.clsp`` mod.  Static across deploys; bumps
    only when the registry puzzle source changes."""

    vault_inner_mod_hash_hex: str
    """``0x``-prefixed tree hash of the *current* uncurried
    ``vault_singleton_inner_v2.clsp`` mod — the live vault code this API build
    mints.  This is what the registry's ``VAULT_INNER_MOD_HASH`` should equal
    for an up-to-date deployment; a divergence means a vault-code upgrade has
    shipped on-chain that this API build predates."""

    vault_version: int
    """Monotonic vault descriptor version the operator stamps into the
    registry's curried state.  Default 1 = initial deployment."""

    canonical_params_hash_hex: Optional[str]
    """``0x``-prefixed ``sha256tree`` of the protocol-wide vault params
    (pool singleton mod hash, pool launcher id, pool launcher puzzle hash,
    zkPassport bridge policy hash).  ``None`` when ``pool_launcher_id`` is
    not configured — without it the params hash is undefined."""

    content_hash_hex: Optional[str]
    """``0x``-prefixed ``sha256tree`` of
    ``[vault_inner_mod_hash, canonical_params_hash, vault_version]``.
    ``None`` whenever ``canonical_params_hash_hex`` is ``None`` (no pool
    launcher configured); callers use this as the "registry descriptor not
    yet computable" signal."""


def build_vault_version_registry_snapshot(
    settings: Settings,
    *,
    pool_launcher_id_hex: Optional[str],
) -> VaultVersionRegistrySnapshot:
    """Construct a deterministic registry snapshot from the live settings.

    ``pool_launcher_id_hex`` is threaded in by the caller so the API can use
    either the deployment-manifest value (preferred — it reflects on-chain
    reality) or the fallback env-var value, without this module needing to
    know which source it received.

    The returned snapshot's ``content_hash_hex`` is non-``None`` iff
    ``pool_launcher_id_hex`` is present: the canonical params hash binds the
    pool launcher id, so without it there is no meaningful descriptor to
    publish.  Callers can therefore use ``snapshot.content_hash_hex is None``
    as the "registry descriptor not yet computable" signal.
    """
    vault_version = settings.vault_version_registry_version
    launcher_id_hex = settings.vault_version_registry_launcher_id

    if not pool_launcher_id_hex:
        return VaultVersionRegistrySnapshot(
            vault_version_registry_launcher_id_hex=launcher_id_hex,
            vault_version_registry_mod_hash_hex=_VAULT_VERSION_REGISTRY_MOD_HASH_HEX,
            vault_inner_mod_hash_hex=_VAULT_INNER_MOD_HASH_HEX,
            vault_version=vault_version,
            canonical_params_hash_hex=None,
            content_hash_hex=None,
        )

    pool_launcher_id = bytes32.fromhex(_strip0x(pool_launcher_id_hex))
    bridge_policy_hash = bytes32.fromhex(
        _strip0x(settings.zkpassport_bridge_policy_hash)
    )

    canonical_params_hash = list_hash(
        (
            bytes(SINGLETON_MOD_HASH),
            bytes(pool_launcher_id),
            bytes(SINGLETON_LAUNCHER_HASH),
            bytes(bridge_policy_hash),
        )
    )

    content_hash = list_hash(
        (
            bytes.fromhex(_strip0x(_VAULT_INNER_MOD_HASH_HEX)),
            bytes(canonical_params_hash),
            positive_clvm_int(vault_version),
        )
    )

    return VaultVersionRegistrySnapshot(
        vault_version_registry_launcher_id_hex=launcher_id_hex,
        vault_version_registry_mod_hash_hex=_VAULT_VERSION_REGISTRY_MOD_HASH_HEX,
        vault_inner_mod_hash_hex=_VAULT_INNER_MOD_HASH_HEX,
        vault_version=vault_version,
        canonical_params_hash_hex="0x" + canonical_params_hash.hex(),
        content_hash_hex="0x" + content_hash.hex(),
    )


__all__ = [
    "VaultVersionRegistrySnapshot",
    "build_vault_version_registry_snapshot",
]
