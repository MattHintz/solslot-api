# Existing-host collection media

The optional `filesystem` backend uses the Solslot host's existing disk and
ClamAV daemon. It requires no S3/R2 account or paid pinning subscription. The
S3 backend remains the default; existing objects and commitments are unchanged.

Only an authenticated administrator can issue an upload capability. The
capability binds a fresh opaque object key, exact SHA-256, MIME, byte length,
method, expiry and create-only condition. Its HMAC key is domain-separated from
the existing protected admin signing secret; no new signing credential is made.
Uploaded bytes are quarantined. The server validates every declared commitment
before atomic exclusive creation. Quota/free-space checks are serialized across
workers. Replays cannot overwrite even unverified originals. Private originals
are never sent to IPFS, promoted, or served from the public endpoint.

Public completion requires loaded ClamAV definitions less than 48 hours old,
the approved policy that alerts on encrypted files and exceeded scan limits,
an actual IPFS add and recursive-pin confirmation, gateway byte verification,
then public HTTPS byte verification. A queued provider response does not count
as a confirmed pin. IPFS RPC stays on loopback. Missing scanner/pin/storage or
unverified output stops completion; the same saved upload can be retried.

The raw media ASGI surface accepts only its scoped capability. It does not use
cookies or administrator JWTs as upload authority. The existing reviewed XSRF
boundary still wraps all ordinary auth, administration and chain-write routes.
The media body limit and concurrency are separate from JSON API limits.
Authorized private downloads expire and use no-store/attachment/no-referrer.
Access logs must exclude capability query strings before deployment.

For the synthetic Njalla rollout: 20 MiB per upload, 1 GiB staged storage, 5 GiB
free-space reserve, two concurrent media checks, a separate IPFS repository
with a 2 GB target and bounded CPU/memory. These are capacity controls, not a
high-availability guarantee. Keep actual property ingestion closed until the
existing recovery lane is verified. Local pin persistence and external IPFS
network availability are separate acceptance receipts.
