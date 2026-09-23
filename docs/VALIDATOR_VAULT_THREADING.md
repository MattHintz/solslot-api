# Vault stamp validation on ASGI worker threads

The disposable Testnet11 identity stamp reached the private validators but
failed before signing. `puzzle_for_vault_full` curried module-level Chia
`Program` objects containing Rust `LazyNode` values imported on another thread.
Hashing the resulting puzzle in FastAPI's synchronous worker raised a PyO3
thread-affinity panic.

The identity owner check now computes the same full singleton puzzle hash from
immutable module hashes with Chia's curry/tree-hash utilities. It retains owner
signature recovery, current-coin reconstruction, signed artifact checks,
timestamp bounds, canonical EVM evidence, bridge-coin lineage and the existing
validator ledger. No protocol puzzle bytes or signature threshold change.

Tests compare the worker-thread result to the protocol's full puzzle for all
supported owner encodings and each state field, including repeated concurrent
calls. EVM and BLS owner checks run on worker threads; a valid signature for a
different owner still fails to reconstruct the coin.

Operational activation uses a separate, checksummed API overlay over the signed
base validator release. Keep the base release and signed archive intact and
record both identities in the activation receipt. Rollback restores the prior
systemd working directory. A health response alone does not prove readiness:
exercise the saved claim through the full non-signing verification path on a
worker, recording any in-memory timestamp refresh as rehearsal only. Never
replace a frozen claim or sign it through this diagnostic.
