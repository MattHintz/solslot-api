# AE197 user journey diagnostics

Application scope: SOLSLOT on the existing shared Njalla coordinator. This package adds no analytics vendor, paid service, account permission or chain action. Deployment is R3 and requires the exact AE197 approval and a verified publication receipt for all three source branches.

## Coverage and privacy

Customer journey events require the revised optional analytics consent (privacy-v2-2026-10-07); Global Privacy Control and Do Not Track prevent this collection. Existing consent from the old public-page scope is not silently extended. Essential vault, signature and ID functions work without optional analytics. Administrator pages emit operational events. Source/actor are browser claims, not verified identity or proof of a human.

The new /alpha/journey-events intake accepts only the enumerated page/action/stage/phase/wallet/error categories, timing, status, retained source pin, diagnostics revision, random request receipt and temporary page-flow/event IDs. It rejects additional fields. There are no new analytics identity cookies, persistent flow IDs, raw paths, DOM text, form fields, property document contents, wallet addresses, public keys, proofs, signatures, IPs or error stacks in these events. A salted process-local daily source hash supports intake rate limits. Existing server access logs and existing Cloudflare/RUM deployment remain separate; this consent control does not change their configuration. Legacy explicit bug reports remain user submitted.

The transport is best effort: at most 200 events per page, 80 queued, batches of 20, a two-second flush, a five-second intake timeout and three attempts with bounded backoff. Duplicate event IDs cannot double-count a lost-response retry. Offline pages pause intake. Navigation and static data-ux-action markers record coarse clicks; handled wallet/ID stages and API writes/errors record outcomes. API request receipts match only same-origin requests with the transient flow header. There is no passive session replay or automatic collection of every API body.

## Read operational evidence

After approved deployment, use the existing coordinator SSH alias and system Python to read:

```sh
ssh solslot-coordinator 'python3 /opt/solslot/genesis-rc28/operations/AE197/recovery/journey-report.py --database /opt/solslot/genesis-rc28/state/admin_desk_v2.db.alpha-observability.db --hours 24'
ssh solslot-coordinator 'journalctl -u solslot-genesis-rc28.service --since "24 hours ago" --no-pager -o cat | rg "journey_api "'
```

The report opens the existing separate database in SQLite read-only mode. It outputs coarse group counts, p95 observed duration, temporary page-flow counts, unmatched waits over 60 seconds and retained row capacity. It excludes synthetic tests and legacy free-form rows. Page flows are not people: refreshes can create another flow, consent opt-outs are absent, and unmatched waits can mean closed tabs. Events have server receipt timestamps; offline uploads and lost batches prevent a precise conversion funnel. API journal receipts are stronger evidence of the server's result; a click alone is not proof that a signature or transaction occurred.

For a failed action, compare its safe request receipt to the journal category/status/latency. Then read the existing authorized runtime ledger for that action. Normal absent session/enrollment discovery reads (401/404) are suppressed. Native fee admission, definitive chain confirmation and authority checks remain the existing execution source of truth.

## Limits and review

The existing intake database is separate from the administrator ledger, with a 10,000-event cap, 1,000 explicit report cap and 64 MiB storage ceiling. It rejects further intake at capacity and retains originals. Rate limits are 600 records/minute globally and 60/source/minute; crowded/shared networks may lose optional diagnostics. At 80% retained row capacity, review an approved encrypted export/archiving policy before the cap. Do not delete or prune existing evidence without separate approval. Telemetry failure cannot block a vault, signature, authoring action or page.

No recurring exporter or additional timer is installed. Review the report during rollout and after a user reports a blocked step. Keep output as a restricted operational artifact; the business governance registry receives only references and freshness/results.

## Installation and rollback

The installer checks the exact approved package manifest, all held AE196/AE184 release pointers and factory pins, the unchanged 410-file protocol freeze, healthy Testnet11 and fresh verified recovery. It requires matching source publication receipts, stages new paths and retains previous hashed assets for open tabs. Only solslot-genesis-rc28.service restarts. A two-request synthetic intake check tests lost-response dedup without a wallet, and is excluded from the report. Both static pointers switch after API checks; exact origin HTML/release metadata is then checked.

Any failed postrestart check restores both previous static pointers and the prior runtime, leaving all data, signed journals, original releases and newly staged candidate files intact. Manual rollback uses the same frozen installer/package manifest with --rollback and the exact approval identifier. No approval renewal, grant, fee funding, mint, public property publication, document upload or chain submission is part of AE197. The existing 24-hour publication approval window and 0.001 TXCH cap remain; mint execution remains disabled.
