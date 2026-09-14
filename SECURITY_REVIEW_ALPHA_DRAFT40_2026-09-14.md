# Draft40: current Base voucher integration

API parent 9f8146ff89610933df48f49185944516d0cb366d. Coordinated protocol
cc47ccf979a12ee026ab2f93c458c3047b706cd6 is pinned in CI.

New Base Sepolia USDC presales use PurchaseArtifactV3 with the existing immutable
VoucherCommitmentV2. The payment callback and finalization route into the voucher
campaign, never the direct-delivery queue. Repeat payment events remain readable
after a phase change; new events require PRESALE inside the transaction.
Delivery loads one exact confirmed current reservation, checks paid commitments
and expiry, constructs existing V5 spends, and retains signed bytes before push.
Confirmation reconstructs the current DID-bound destination and verifies retained
inputs, outputs, payment evidence and atomic confirmation heights. Independent
validator reconstruction binds the reservation, deed and paid credential before
key access. Historical V2 quotes are not rehashed into V3; their issuance,
confirmation, refunds and retained execution recovery remain. New XCH vouchers
remain unavailable. Legacy SQL/KOS purchase/inventory writers remain retired.

Focused validation includes 108 passing tests across vouchers, quote construction,
validator reconstruction and XCH policy, plus both Base/evm_usdc callback routing
controls. Tests cover real SQLite, current inventory loading, CLVM conditions,
aggregate signatures, exact vault outputs, restart after lost responses, delayed
confirmation, refunds, provider refusal and tampered reservation/deed/credential.
The full API suite and exact PR/main CI are release gates recorded in the release
packet. Namespace, secret, runtime dependency, build dependency and the protocol
recovery/test-runner boundary checks passed locally. Synthetic fixture root and
confirmation height now match the committed artifact and SQLite inventory row.

Proof limits: synthetic payment/provider/authority and node fixtures are not live
chain outcomes. A pre-existing long reservation is the delivery test input;
initial reservation policy and the missing long-lived extension orchestration
still need end-to-end evidence. Late first Base webhook processing is also
constrained by the existing current-time quote verification gate and requires
separate reviewed recovery coverage. No release promotion or network action.
Agent capacity prevented fresh investigator/reviewer workers; separate parent
passes are not independent launch approval. Original46 remains 18 fixed_at_source,
26 still_vulnerable, 2 inconclusive; broader launch is NO-GO.
