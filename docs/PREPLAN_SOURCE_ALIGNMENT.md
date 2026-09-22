# Preserve enrollment when aligning pre-plan sources

`scripts/align_genesis_sources.py` is a local operator utility for the existing
Ethereum Sepolia / Chia Testnet11 ceremony. It changes only the draft's nine
source SHAs, release tag, evidence digest and update time. It appends an audit
event containing both drafts. It does not create a plan or supply approval.

The target evidence must pass the API's canonical release-evidence checks and
match the installed API/protocol build metadata. All three enrolled wallets,
their original signatures, recovery records, funding receipts and other related
records are fingerprinted and preserved. Completed offline recovery kits remain
completed; source alignment is not re-enrollment.

Preview is read-only. Supply `--database`, `--ceremony-id`, `--source-evidence`,
`--evidence-sha256`, `--release-tag`, `--release-metadata`, and `--action-envelope`.
Use the installed API interpreter so its schema and evidence validation apply.
Apply additionally requires `--apply-plan-hash` from that exact preview and a
new `--backup` path in a private operator directory. Stop the API during the
coordinated application/configuration change. The tool takes an SQLite writer
lock, rechecks all preconditions, creates a consistent mode-0600 database backup,
updates the draft and appends the event in one transaction. Any failure before
commit leaves the draft unchanged. A stale preview must be regenerated.

Only `draft` and `roster_open` are accepted. Existing plans, signatures, gates,
intents, finalization reservations, unexpired action approvals, another chain,
or permit-selected enrollment are rejected. Existing backups are never replaced.

Install the exact retained target source-evidence file and update the service's
release tag/path/checksum together with this operation. Preserve the previous
configuration. If activation fails, stop the service and restore the pre-change
database and configuration before accepting new writes; preserve the failed
attempt's database separately. Do not restore a whole database over later user
activity. A successful alignment is not authorization to roll back later plans.

Existing EVM deployment evidence, validator versions, review receipts and signed
artifacts are not rewritten by this utility. Their strict checks may still
report mismatches until the remaining coordinated work is complete. Original
contract receipts must retain the source revision that actually deployed them.
No human review, owner/coadministrator signature or launch approval is inferred.
