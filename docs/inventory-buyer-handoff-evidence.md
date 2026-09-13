# Inventory buyer handoff verification

The V2 authorization-expiry and confirmed timeout recovery methods already exist.
A fresh buyer uses the normal reservation route, a new quote, a distinct purchase
ID, their own vault and their current chain-bound credential. No legacy purchase,
mint, repricing, vault registration or KOS inventory worker is reactivated.

`tests/test_inventory_buyer_handoff.py` joins the real native context loader,
reservation endpoint, recovery helpers, purchase database, independent validator
claim verification, and validator replay ledger. It executes the V2 reservation
CLVM and verifies a two-validator aggregate signature generated from fixture keys.
The timeout case spends the recovered successor; authorization expiry reuses the
original, independently proven unspent available coin.

The suite covers a different vault, owner and credential root after both recovery
paths; an earlier partial validator quorum; a restart after the replacement quorum
but before API persistence; exact signature recovery; canonical reserved output
and normal API confirmation; preservation of the ended purchase and its evidence;
and refusal of an old purchase retry, wrong owner, spent source and stale quote.

These are offline integration tests. Authority documents, enrollment/registry,
collection/proposal stores and primary/validator RPC responses are controlled
fixtures. The signed offer-document rejection checker is replaced at the external
approval boundary. Fee funding/submission and chain confirmation are simulated.
Validator verification runs synchronously in the test process, not through an
mTLS deployment. The tests do not prove wallet signatures, production settings,
full consensus acceptance, public-chain settlement, holdings or delivery of an
investment. Public owner authentication and approval-document verification retain
their separate suites. No new recovery primitive or production behavior change
was required for this coverage.

Original finding 6 remains inconclusive for complete launch remediation until the
release-bound deployed journey supplies signed transaction receipts and canonical
outcomes, including supported lifecycle, device and failure coverage. This local
handoff evidence must not close that gate by itself.
