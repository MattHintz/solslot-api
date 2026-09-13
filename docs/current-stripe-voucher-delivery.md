# Current Stripe voucher delivery

The current Stripe voucher worker consumes one confirmed PurchaseArtifactV3
reservation through the existing group loader. It rejects missing, expired,
spent or mismatched inventory, batches and mismatched paid commitments before
requesting validator signatures. It uses the existing V5 voucher builder.

Preparation derives the DID-authorized SmartDeed destination from canonical
inventory coordinates and requires that output to descend from the reserved
input in the complete bundle. Confirmation uses the signed public artifact's
DID and the retained exact execution. The bundle ID, purchase, paid artifact,
settlement evidence, input coins and output roles must match the independently
confirmed atomic coin set. Confirmation does not reload already-spent inventory
or require the original quote to remain live.

The exact-execution handoff continues to persist the signed, fee-funded bundle
before dispatch. Recovery first checks the exact confirmed chain outcome. It
can record delivery while the executor remains unavailable; incomplete or
inconsistent chain evidence cannot mark delivery. If still unconfirmed, a lost
executor response resumes those same bytes. A node transport outage preserves
that exact executor retry. Expiry does
not authorize a replacement purchase or a second terminal transaction.

## Evidence boundaries

`tests/test_current_stripe_voucher_delivery.py` exercises real purchase/presale
SQLite stores, the real inventory and lineage loaders, production V5 builders,
claim-message BLS signatures, the Chia consensus bundle evaluator and exact
execution persistence. It covers both supported inventory versions, delayed
delivery, restart, altered evidence, expiry, atomic confirmation and repeated
reconciliation. Raw CLVM and bundle mutations exercise mode/paid-transition
separation without relying on Python builder rejection.

Authority documents, chain records, Stripe evidence, validator transport,
fee funding and the executor are synthetic fixtures. The tests start from a
confirmed reservation snapshot; they do not prove customer payment collection,
independent live validator verification, public-chain inclusion, production
holdings visibility or an OS wallet journey. Nothing is deployed by this change.

## Presale lifecycle blocker

Initial reservation expiry cannot exceed quote or authorization expiry. This
is enforced by the validator, Python driver and both available-inventory CLSP
versions. Presale quotes end by the sale close, while paid voucher delivery
occurs after launch. The API now selects the earlier original quote or vault
authorization deadline for an initial reservation, retaining the existing
governed-series and delivery-window checks. The launch deadline does not grant
initial reservation authority. Confirmed reservation evidence is not rewritten.

`tests/test_presale_initial_reservation.py` exercises that initial path through
the real API loader, private validator verifier and SQLite signature ledger.
Local BLS signatures and the Chia consensus evaluator verify the resulting V2
reservation and its expiry; synthetic node records exercise confirmation and
store reopening. Both fresh inventory after authorization expiry and inventory
returned by timeout are covered, along with expired quotes, ended or mismatched
series, expired delivery windows, paused writes and missing service credentials.
Authority, registry, node and fee transport are fixtures. This proves neither
public-chain inclusion nor durable fee-funded submission or extension.

V5 contains a separately signed extension transition. The tests execute an
initial short V2 reservation and timely extension, check the resulting coin,
signatures and expiry conditions, and reject a raw long initial reservation.
The extension must occur before the current reservation expires. Its successor
has a different parent, coin ID and lineage. Current API orchestration,
independent authorization and durable successor reconciliation remain missing.
Payment eligibility for extension must be settled before implementing a new
signing path; the inspected documents do not authorize unpaid holds to renew.
The long-lived snapshot tests are not evidence that this upstream path works.
Presale alpha readiness remains blocked until that lifecycle is completed.

Historical V3/V4 finding45 is not closed by V5 mode tests. Current XCH's V2
transport, escrow launcher binding and V4 worker/validator integration remain
separate repair work. Base/omnichain integration remains deferred. Frozen puzzle
bytes, legacy-property redemption and retired SQL/KOS write boundaries are
unchanged. See the coordinated release packet for exact revisions and results.

The frozen available-inventory V1 initial-spend failure remains historical
evidence. V1 reserved-snapshot delivery compatibility does not prove V1 minting
or initial reservation works. New reachable reservation coverage uses V2.
