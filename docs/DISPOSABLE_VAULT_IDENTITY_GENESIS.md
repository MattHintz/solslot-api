# Disposable vault and identity genesis

This explicit operator profile is for one internal Testnet11 rehearsal. It is
unaudited and must be replaced before bridge or financial testing. It does not
claim to satisfy an independent review, EVM recovery deployment or payment handoff.

Set `SOLSLOT_DISPOSABLE_GENESIS_CEREMONY_ID` to the exact existing ceremony ID and
`SOLSLOT_LAUNCH_GENESIS_REVIEW_CLASS=internal-engineering-testnet`. All capability
flags listed in `solslot_api/disposable_genesis.py:CLOSED_FLAGS` must remain false.
Startup and preflight reject other networks, mismatched ceremonies/review classes,
or open financial capabilities. The default remains the fully protected release.

The operator may adopt a new frozen release only before this ceremony has ever
had a plan. `GenesisStore.adopt_disposable_release` is deliberately not exposed
as an HTTP endpoint. Stop the coordinator, take a protected SQLite backup, check
installed API/protocol against the complete nine-component release evidence, and
call it with the exact prior draft and authorization reference. The transaction
preserves the prior draft in the append-only audit ledger. It preserves enrolled
wallets, invitation signatures, recovery proofs, funding and the frozen roster.
After any plan exists, adoption is forbidden; use a replacement ceremony instead.

All three administrator recovery drills remain required. The normal Chia
Authority V4 coins, exact plan reproduction, live identity contract checks, three
validator health checks, owner-plus-one plan signatures, broadcast window,
fee-funded submission, chain confirmation and artifact signatures remain required.
Only the EVM authority deployment and independent recovery review are deferred.

The private archive saves `disposable_scope.json` in place of an independent
`authority_v3_review.json`. Its content explicitly says `unaudited`, identifies
the exact ceremony/plan/release and requires replacement before bridge testing.
The signed public artifact uses the existing `internal-engineering-testnet`
review class, `testOnly: true` and pending external review status. Administrators
see the disposable scope before approving the plan in the portal.

SGT allocation, SmartDeed minting, purchases, presales, distributions, liquidity,
payment rail ownership/activation and bridge routes stay disabled. Vault
registration and identity verification are the intended test operations, available
only after normal genesis confirmation and artifact activation. The inherited
SGT sale asset is a placeholder, not an authenticated bridge CAT binding.

Rollback before plan approval: preserve every resulting ledger entry and signed
record; restore prior runtime/configuration only under maintenance. Never restore
an old database over newer signatures or a broadcast reservation. After broadcast,
the Testnet11 result is irreversible and must be retained as evidence; replacement
uses a new ceremony and new funding inputs.
