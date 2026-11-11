# Generation-only recovery — AE222 candidate

This package supplements the preserved AE181 collection recovery. It exports only
21 named SQLite databases in a separately configured generation journal namespace.
A live receipt requires all 21; a partial inventory cannot be reported healthy.
Every journal must also carry the exact completed initialization commitment.
Live replication rejects absent or INITIALIZING markers before uploading any
objects. Independent restore compares that state against actual decrypted bytes;
caller-supplied READY metadata cannot replace a missing database marker.
It never exports an old generation, credentials, arbitrary files or private plans.
The separate AE181 lane continues to preserve accepted property objects.

The root forced command delegates SQLite capture to the existing unprivileged API
identity, and keeps only protected receipt publication privileged. Filesystem
replacement by the namespace owner therefore cannot grant root read/write access.
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

- `recovery-tests-v9.txt`: 100 local positive/adversarial checks passed.
- `runtime-full-inventory-tests-v6.txt`: 33 checks cover actual API startup,
  all21 genuine schemas, isolated restore, guarded first initialization,
  interrupted setup, lost journals, unsafe paths and retained-data rejection.
- `live-recovery-lost-journal-tests-v1.txt`: five current lost-journal checks
  passed, including a recreated empty preparation database rejected by live backup.
- `application-restore-tests-v1.txt`: cold API reopen preserved the exact original
  offer, operation bundle, receipt and funding holds; retries did not rebuild.
- `azure-drill-result-v10.json`: all21 current real empty API journal schemas
  (1,667,072 restored bytes) passed encrypted independent Blob restore on the
  existing Azure VM as an unprivileged account using separately root-staged
  tokens. Purpose remains SYNTHETIC_RESTORE_DRILL. The current exporter was
  hash-pinned but its Njalla forced-command/UID boundary was not exercised here.
- `privilege-and-inventory-tests-v3.txt`: 13 focused checks cover the child OS
  file-size bound and receipt permissions. The receipt publisher retains root ownership
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

Before first initialization, keep alpha writes, generation execution, final
launch and Sols ordering disabled, with no launch certificate/artifact or chain
anchor configured. Install the reviewed preparation manifest and private canonical
state directory with UMask=0077. Enable `generation_recovery_storage_enabled` for
startup schema preparation. This creates real empty schemas without inventing
orders, signatures, launch reviews, authority state or release certification.
All later authority constructors retain their original validation.

The initializer stores inventory phase commitments in every database and a
separate metadata guard under `journals/generation-recovery-initialization`.
Keep the guard and opt-in enabled for subsequent starts. Once initialized, a
missing file or marker stops startup; never remove a guard to create empty
replacement ledgers. An interrupted first setup can resume only behind paused
prelaunch gates. An independently verified complete restore can reconstruct the
metadata guard from all21 retained markers. The guard is not a key or business
ledger, and does not authorize a restore or chain operation.

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

Additional reviewed repairs flatten the collection store to one generation directory
and include stamp-funding, node-submission and telemetry journals. The actual API
lifespan plus all21 schema constructors now have a local recovery regression.
This uses a synthetic preparation with production configuration validation stubbed;
it does not certify a hosted configuration or actual user-state restoration.
The exporter applies its independent output
file-size limit in the child after dropping to the API user, because runuser resets
inherited file-size limits on the supported host.

Recovery health remains an explicit operator/deployment gate. This package does
not install an automatic backup-health guard into every API write route.

## Open release gates

Whole-candidate security coverage, actual journal restore, source/build/configuration
certificate, all three real recipient acknowledgements, real one-hour voting and
24-hour activation/reopening, and the Eastmoreland native UI mint remain pending.
No mainnet, beta cutover or new subscription is included.
