# Generation-only recovery — AE222 candidate

This package supplements the preserved AE181 collection recovery. It exports only
17 named SQLite databases in a separately configured generation journal namespace.
A live receipt requires all 17; a partial inventory cannot be reported healthy.
It never exports an old generation, credentials, arbitrary files or private plans.
The separate AE181 lane continues to preserve accepted property objects.

The source sets briefly acquire SQLite write reservations and pin read snapshots
before releasing the reservations. SQLite's backup API copies committed WAL pages.
Each database is capped at 256 MiB and the complete snapshot at 512 MiB. Unknown
files, mismatched generation markers, corrupt databases and busy sources fail
closed; no retained business or transaction evidence is pruned.

Changed database objects and the manifest are AES-256-GCM encrypted with the
existing versioned Azure Key Vault backup-key reference. AAD binds generation,
Testnet11, object kind, digest and AE222. Blob creation requires If-None-Match '*'.
Objects retain the existing container's locked 30-day retention. Restoring reads
all bytes independently through Blob GET and reconstructs isolated databases.
Health receipts expose commitments/counts only. Synthetic drill receipts, stale
receipts and wrong-generation/source commitments cannot admit live launch.

The worker is an unprivileged dedicated Linux account. A root pre-step writes
three short-lived, scope-checked managed-identity tokens to a separate private
runtime directory. This preserves the Azure host's root-only IMDS boundary and
does not reuse AE181's staged token file. Existing transport code is checksum
pinned. The existing backup key and SSH credential remain in Key Vault and worker
memory/tmpfs. Neither appears in a repository, receipt or command output.

## Verified evidence as of 2026-10-13

- `recovery-tests-v7.txt`: 59 local positive/adversarial checks passed.
- `application-restore-tests-v1.txt`: cold API reopen preserved the exact original
  offer, operation bundle, receipt and funding holds; retries did not rebuild.
- `azure-drill-result-v8.json`: the current snapshot/replication/health/token modules restored matching
  encrypted synthetic SQLite data on the existing Azure VM as an unprivileged
  account using separately root-staged tokens. Purpose is SYNTHETIC_RESTORE_DRILL.
- `export-permissions-tests-v1.txt`: the receipt publisher retains root ownership
  and explicitly grants the API group read access under a private umask. This
  permission refinement is locally verified; no live exporter was installed.
- API `test_generation_reward_progress_routes.py`: two real native-consensus HTTP
  prepare/submit/confirm/restart tests passed, for XCH and CAT reward pages.

The Azure drill is not an actual new-generation journal backup. No recurring
worker, new SSH export or candidate application has been installed. AE181's old
forced export, IAM grants, services and retained objects are unchanged. Early
failed drill/test receipts remain separate evidence, not successful checks.

## Installation requirements

The final reviewed deployment must supply the actual generation and runtime-source
commitment in root-owned `/etc/solslot-generation-recovery-AE222.json`:

- schema: `solslot.generation-recovery-config.v1`
- generationId: the concrete nonzero 32-byte deployment identifier
- sourceHash: the exact installed runtime-source commitment
- journalRoot: `/opt/solslot/generation-AE220/state/journals/generations/<generation>`

Configure all generation database settings with that isolated journal base; keep
public/source artifacts and non-database output in their separately pinned lanes.
The exporter deliberately refuses unexpected entries rather than omitting them.
Archive source manifests, public artifacts and chain anchors as release evidence;
this journal package is not a complete host disaster recovery or key-recovery kit.

Create the dedicated account `solslot-gen-recovery-ae222` on the two existing hosts.
On Njalla, its SSH key entry and sshd Match block must accept only 10.77.0.12,
disable terminals/forwarding, and force the root-owned generation exporter through
one narrow sudo rule. The reviewed public key from the existing versioned recovery
credential may be authorized for that *separate* generation-only account; this is
an explicit additional export capability, not a modification of AE181's account.
No secret value or new cloud IAM permission is required.

On Azure, install these root-owned sources under
`/opt/solslot/generation-recovery-AE222`, the reviewed coordinator host key, and
these service/timer units. Require systemd syntax checks, a fresh actual-generation
backup/restore and >=5 GiB/>=10% disk headroom before enabling application writes.
The timer runs every two minutes after the previous job finishes; failure leaves
the prior receipt to expire after ten minutes. An enabled timer alone is not health.

Rollback disables only the new timer/export account and preserves old units,
source releases, encrypted objects and chain evidence. Restore never automatically
replaces live journals or reverses chain history. Reconciling retained submissions
must precede a new transaction; actual sender and wallet authorizations remain
required.

## Open release gates

Whole-candidate security coverage, actual journal restore, source/build/configuration
certificate, all three real recipient acknowledgements, real one-hour voting and
24-hour activation/reopening, and the Eastmoreland native UI mint remain pending.
No mainnet, beta cutover or new subscription is included.
