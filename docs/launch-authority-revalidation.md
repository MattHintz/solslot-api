# Launch administrator authority after key replacement

Launch slots are numbered 1–3; Authority V3 slots are numbered 0–2. Slot 1 is
the owner. Once the signed public artifact exists, launch sessions, login
challenges and action approvals resolve each slot from that artifact plus
completed cross-chain key-change receipts. Historical invitations remain
enrollment evidence and do not authorize retired keys. A key enrolled later
in another slot cannot reuse a cookie for its former role.

Before genesis, consumed invitations still authorize the bootstrap ceremony.
Missing signed evidence cannot reopen bootstrap after a recorded lock,
publication reservation, existing publication/lock path or completed key
change. Invalid or differently bound artifacts fail closed.

If publication was reserved but interrupted while the ceremony remains
`artifact_signed`, the reserved artifact is cryptographically verified and
bound to the recorded artifact hash, ceremony, network, EVM chain and lock.
Its current identities may log in, read launch status/audit and retry the
owner-only progress step. Other administrator routes, approvals and gate use
remain blocked until publication finishes. This preserves recovery without
returning to invitation-based authority or reopening bootstrap.

Schema 13 adds an activation approval snapshot to the launch-gate ledger.
Activation records the reviewed action, payload, time window and approving
identities. Every operation using a gate rechecks those identities against
the current exact slots. Approval signature expiry limits when activation
may occur; it does not shorten the separately approved gate duration.
Replacing a signer requires current owner-plus-one approval and explicit
reactivation before a gate relying on that signer can authorize work.

Superseded approvals and gate activation snapshots are preserved in audit
events before their active rows change. Original invitation signatures and
ceremony evidence are unchanged. Pending actions can receive a replacement
administrator's approval without overwriting the retired signature history.

Existing gate rows without activation snapshots cannot authorize operations
after this release. Operators must prepare/review the intended window and
obtain fresh current owner-plus-one approval. This includes replay of an
unconfirmed, preserved genesis bundle: only its exact existing reservation
can be replayed under a fresh authorized window. Finalized-bundle evidence
rematerialization keeps its existing behavior.

Before an approved rollout, back up the schema-12 database, verify current
signed artifact/receipt availability, and rehearse snapshot migration and
gate reapproval in isolation. Schema 13 cannot be opened by the prior binary;
rollback must use the matching pre-migration backup while preserving later
evidence. This document does not authorize service changes or network writes.
