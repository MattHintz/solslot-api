# Safe recovery action binding

The API constructs the Safe transaction, its EIP-712 preimage and hash locally
using the pinned Base Sepolia chain ID, execution Safe and reviewed action.
Both RPC results must match: `getTransactionHash` must equal the local digest,
and `encodeTransactionData` must equal the complete canonical ABI encoding of
the local preimage. A consistent provider-supplied hash and preimage for a
different transaction is rejected. Malformed or extra encoding is rejected.

The shared context feeds Root Safe nested SafeMessage approvals and direct
Identity Safe approvals. Package retrieval, signature submission and recording
an already propagated transaction all reconstruct through this boundary.
Signature submission checks each required leaf and package hash before storage;
final assembly uses only signatures selected by the freshly rebuilt package
hash. Old substituted packages cannot satisfy the new canonical package hash.
The owner-plus-one topology and existing signature serialization are preserved.

Honest RPC encodings leave package hashes unchanged, so partial approvals can
resume. Mined transaction recording still uses the recorded approved nonce,
without substituting an advanced live nonce. Changed live nonces or current
owners generate a different package requiring the existing review/signature
flow. Provider disagreement returns the existing HTTP 409 error path before
new approval storage or a broadcast package is returned.

The local formula follows the repository's existing eth_account EIP-712 helper.
Regression fixtures independently calculate the domain and transaction hashes
with ABI encoding, using [Safe v1.4.1's reference implementation](https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol).
Fixtures use synthetic keys, a local SQLite ledger, and simulated RPC responses.
Deployment and roster evidence are mocked only in the focused package fixtures;
these tests do not establish live contract outcomes, provider truthfulness,
runtime identity, or current nonce/receipt truth. Existing deployment evidence,
runtime checks, current-authority gates and release approval remain required.

Scope: AUTH-RPC-SAFE-1. No omnichain contract or deployed service is changed.
