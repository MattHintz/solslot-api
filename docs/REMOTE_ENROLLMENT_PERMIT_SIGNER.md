# Private Azure enrollment permit signer

This optional transport moves the existing enrollment permit Key Vault call to
an isolated Azure process. Njalla remains the **only credential ledger writer**.
It retains authenticated owner sessions, live vault/bridge checks, durable
reservation, issuance attempts, immutable deadlines and first valid signature.
The remote process has no ledger, wallet, passport proof, BLS key or public API
route. Its capability label is `enrollment-permit-v1`; this is a version label,
not a secret or bearer credential.

This source change does not authorize deployment, replace the signed artifact,
change release pins, or unlock enrollment. All existing activation, review and
coordinator write gates still apply. Base **8453** is identity only; the artifact
and genesis signing chain remain Base Sepolia **84532**, and Chia is Testnet11.

## Transport and authority

Run only `python -m solslot_api.enrollment_signer_main`. The entry point mandates
mutual TLS, a dedicated issuer client CA, and the exact coordinator leaf
certificate SHA-256 over DER bytes. It derives the peer fingerprint from the
TLS transport, never a forwarded header. A second certificate issued by that CA
does not have signing authority. A plain ASGI deployment lacks this transport
identity and returns 403. Do not add this app to the public or validator app.

The standalone listener is `10.77.0.12:8793`; host firewall rules must permit only
the coordinator `10.77.0.1` on WireGuard. Never bind wildcard or public addresses.
The client validates the server CA and IP SAN and disables redirects and proxy
environment variables. Use a dedicated issuer CA, not the validator fleet CA.
Private keys must be absolute regular files without group/other permissions.
Root-owned source keys plus systemd `LoadCredential` are supported; a symlink or
0640 private key is rejected. Certificate rotation must update the pinned leaf.

The sole request route is `POST /v1/enrollment-permit/sign`. The exact body is:

```json
{"capability":"enrollment-permit-v1","artifactHash":"0x<64 lowercase hex>","permit":{"...":"exact EnrollmentPermit.to_wire() fields, including permitHash"}}
```

The permit object above is a schematic placeholder, not a usable payload. No
extra keys, digest, key URL, managed identity, network or activation are accepted.
The issuer verifies the local admin-signed artifact, expected artifact hash and
API/protocol source SHAs, and the exact local activation pins. It recomputes
the context and permit hash, requires `issuedAt <= now < expiresAt`, and requires
the exact signed activation lifetime. Only then may the existing fixed-purpose
Key Vault signer access IMDS and the activation's versioned ES256K key. The local
UAMI client ID must match the signed activation; there is no system-identity
fallback. The recovered signer must match the activation issuer. The deadline
is checked again after signing.

The response contains exactly `capability`, `requestHash`, `permitHash`, `issuer`
and `signature`. `requestHash` is SHA-256 of sorted, compact UTF-8 JSON for the
canonical request, prefixed `0x`. Njalla checks those bindings and recovers the
canonical low-s signature over the original saved permit. It never accepts a
replacement permit. Requests and responses are limited to 4096 bytes; request
body reads have a three-second limit and outbound calls have bounded timeouts.
Provider response bodies and exception messages are not returned to callers.

mTLS authenticates the authoritative coordinator, **not an end user's browser**.
End-user authorization remains the existing session and fresh coin checks on
Njalla. Remote retries may sign the identical still-live permit again, just as
the previous direct Key Vault transport could. They cannot renew its deadline
or create a replacement reservation. The first valid recorded signature wins.

## Coordinator configuration

The default remains `key_vault` for compatibility. To select the private role,
set all four remote values and select `remote` explicitly:

```text
SOLSLOT_ENROLLMENT_PERMIT_SIGNER_MODE=remote
SOLSLOT_ENROLLMENT_PERMIT_REMOTE_URL=https://10.77.0.12:8793/v1/enrollment-permit/sign
SOLSLOT_ENROLLMENT_PERMIT_REMOTE_CA_FILE=/etc/solslot/enrollment-issuer/issuer-ca.crt
SOLSLOT_ENROLLMENT_PERMIT_REMOTE_CERT_FILE=/etc/solslot/enrollment-issuer/coordinator.crt
SOLSLOT_ENROLLMENT_PERMIT_REMOTE_KEY_FILE=/run/credentials/solslot-api.service/enrollment-issuer-client-key
```

Retain the existing exact `SOLSLOT_ENROLLMENT_PERMIT_RELEASE_IDENTITY`,
`SOLSLOT_ENROLLMENT_PERMIT_ISSUER_KEY_REF`,
`SOLSLOT_ENROLLMENT_PERMIT_IDENTITY_CLIENT_ID`, identity RPC chain, network and
write-gate settings. The issuer metadata must agree with the selected signed
activation before any network call. Missing or mixed transport configuration
fails startup; transport failure has no local signing fallback.

## Isolated issuer configuration

All fields below use `SOLSLOT_ENROLLMENT_SIGNER_` as a prefix. There is no `.env`
auto-load in this role. Every value identifying the release or activation must
be taken from authenticated deployment evidence, not guessed or fabricated.

| Suffix | Required value / meaning |
| --- | --- |
| `SIGNING_ENABLED` | `false` for transport staging; `true` only after deployment authorization and complete signed evidence |
| `BIND_HOST` | `10.77.0.12` (loopback permitted for local tests) |
| `BIND_PORT` | `8793` only |
| `TLS_CERT_FILE` | Absolute server certificate path; serverAuth EKU, IP SAN 10.77.0.12 |
| `TLS_KEY_FILE` | Absolute private server key, preferably systemd credential path |
| `TLS_CLIENT_CA_FILE` | Dedicated enrollment issuer client CA certificate |
| `TLS_CLIENT_CERT_SHA256` | Exact coordinator leaf DER SHA-256, lowercase 64 hex characters |
| `PUBLIC_ARTIFACT_PATH` | Local, cryptographically admin-signed public artifact |
| `EXPECTED_ARTIFACT_HASH` | Exact signed artifact hash |
| `RELEASE_METADATA_PATH` | Immutable build's `release.json`; exact API/protocol source SHAs |
| `RUNTIME_ENVIRONMENT` | `production` for a production-alpha activation, otherwise `staging` |
| `NETWORK` | `testnet11` only |
| `ZKPASSPORT_EVM_CHAIN_ID` | `8453` only |
| `ENROLLMENT_PERMIT_RELEASE_IDENTITY` | Exact activation release identity |
| `ENROLLMENT_PERMIT_ISSUER_KEY_REF` | Exact versioned Key Vault key URL in the activation |
| `ENROLLMENT_PERMIT_IDENTITY_CLIENT_ID` | Exact dedicated enrollment UAMI client ID in the activation |
| `EXPECTED_CONTEXT_HASH` | Exact activation context hash |
| `EXPECTED_EMITTER` | Exact Base identity emitter address |
| `EXPECTED_ISSUER` | Exact recovered Key Vault issuer address |

Use separate Unix account `solslot-issuer`, an immutable release checkout and
read-only artifact/configuration. Do not mount validator BLS keys or coordinator
ledger state. On the shared Azure VM, the issuer unit must declare:

```ini
[Unit]
Requires=solslot-enrollment-isolation.service
After=network-online.target solslot-enrollment-isolation.service

[Service]
User=solslot-issuer
Group=solslot-issuer
EnvironmentFile=/etc/solslot/enrollment-issuer/issuer.env
LoadCredential=enrollment-issuer-server-key:/etc/solslot/enrollment-issuer/server.key
ExecStart=/opt/solslot-enrollment-issuer/venv/bin/python -m solslot_api.enrollment_signer_main
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
```

This is an integration excerpt, not a complete installed unit. The isolation
unit must restrict IMDS `169.254.169.254:80` to root and the issuer UID and permit
8793 only over WireGuard from the coordinator. Preserve the existing validator
service and its recovery permissions. The issuer must not start without that
boundary. Set `TLS_KEY_FILE` to the matching service credential path, and
install matching immutable release/artifact read permissions before enabling.

## Staging and readiness

`GET /health` is also mTLS and certificate-pin protected. With signing disabled
or no valid signed artifact/release pins, it returns 503 and
`{"capability":"enrollment-permit-v1","configurationReady":false}`. This lets
operators test the private certificate boundary **without a fake activation or
artifact**. A 200 indicates local configuration/evidence readiness only, not
Key Vault connectivity, successful signing, a live enrollment or launch approval.
The route exposes no issuer configuration, key URL or provider error.

Before authorized activation, verify valid coordinator TLS succeeds while
missing, foreign and same-CA wrong-leaf client certificates fail; confirm no
public route exists; compare source/artifact/context pins; and check isolation
health. A real permit test and real device proof remain distinct from these
offline tests. Do not lift the review or coordinator write gate to test transport.

To roll back a transport issue, keep enrollment writes closed, restore the
previous source/configuration, and preserve Njalla's ledger. Removing remote
configuration does not authorize in-process signing on a host that lacks the
approved identity/key. Never replace pending permit IDs or extend deadlines.

Offline regression coverage is in `test_enrollment_remote_signer.py` and
`test_enrollment_signer_transport.py`, alongside existing permit issuance,
signing and signed-artifact tests. Those tests use synthetic keys and loopback
TLS; they do not contact IMDS, Key Vault or any production signer.
