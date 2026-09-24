# Protocol fee funding and recovery

Full Testnet11 preparation now uses a durable funding journal for ordinary
`ProtocolBundleSubmitter.submit` calls, including validated MINT publication
and execution. Genesis, vault stamps and other exact executors retain their
own dedicated journals and validation rules.

The journal is `<zkpassport_ledger_db_path>.protocol-funding.sqlite3`. It is
created before workers start, with private file permissions and SQLite FULL
synchronous WAL writes. Include the database and its live WAL in consistent
backups. Do not restore an old copy while its transactions may remain pending.

Before broadcasting, the coordinator saves the original protocol bundle ID,
funding context, complete signed funded bundle and every input reservation.
A retry checks exact canonical spends or the exact mempool bundle first. A
timeout does not authorize another fee coin, new signature or fresh quote.
The same saved bytes are resent only when the primary node proves that the
inputs are clear. A spent input alone is not evidence of success.

Every fee subsidy asserts the concurrent protocol inputs and their emitted
announcement commitments. Issuance backing additionally requires an explicit
deficit and announcement commitments. Ordinary fee-only transfers need not
emit announcements, but the fee spend cannot execute without their inputs.

Configure the reviewed fee floor/target/buffer and the maximum separately.
The intended test budget is a 100,000,000 mojo floor (0.0001 test-XCH), bounded
by 1,000,000,000 mojos (0.001 test-XCH) per funded action. The release must also
bind the maximum funding coin, issuance backing and aggregate operating
budget. A larger funding coin is not permission to spend it as a fee. Quotes
over the cap stop for operator attention; this code does not replace fees on
an already signed transaction.

The append-only event table records the original ID, lifecycle event, time and
classified error code. Transport text and private signed bytes do not enter
application logs. Full transaction bytes remain in the private journal for
reconciliation. Reservations are retained even after rejection; an operator
must establish the chain result before any separate recovery releases inputs.

MINT funding is available only after the exact owner-plus-one authorization
and semantic publication checks, or the exact KoS execution check. The public
structural committee-vote relay is not a sponsorship endpoint.

Before broadcasting a funded MINT, the validated endpoint also saves immutable
application completion instructions bound to the exact funded bundle and signed
genesis artifact. A Testnet11 observer reconciles pending instructions against
the primary node every 15 seconds. It checks the exact mempool transaction or
every canonical confirmed spend, then restores proposal and collection records.
It does not sign or broadcast. Failed rows remain pending and do not prevent
later rows from being checked. Old-genesis rows remain preserved for separate
reconciliation rather than being applied to a new release.

The proposal and collection writes are safe to replay after partial failure.
Conflicting transaction IDs or commitments stop recovery; matching retries
preserve later voting/execution states and do not duplicate collection audit
entries. Do not reset a proposal or sign a second mint to work around a delayed
application update. The API's existing accepted-versus-confirmed distinction
still applies: finding a mempool entry does not claim finality.

Local coverage includes restart after an ambiguous push, no new fee quote on
retry, persistence before RPC, input conflicts, pending/confirmed/clear source
observations, changed solutions/reorgs, detached sponsor rejection and a
funded property publication in the Chia simulator, including a crash after
acceptance and recovery from reopened databases using the production source
observer. Partial collection failures and mismatched genesis/owner/bundle
records are covered separately. Hosted fault injection is
still required for the exact release and runtime database paths.
