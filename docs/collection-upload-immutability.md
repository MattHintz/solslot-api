# Collection upload integrity

Reviewed September 6, 2026 (America/Chicago). Local remediation draft; no storage
or deployment change has been performed.

New uploads use `collections/v2/<exact-identity-hash>/<attempt-version>/asset`
(with an optional extension). Private originals retain the `private/collections/`
prefix. Exact collection and asset IDs determine the identity hash; each attempt
gets a fresh server-generated version. Historical keys, URLs, CIDs and metadata
commitments remain readable and are not rewritten or migrated.

PUT URLs sign `If-None-Match: *`. The browser must send the returned headers
unchanged. This prevents reuse of a URL from replacing an existing object on a
conforming storage service. AWS documents this conditional-write behavior;
Cloudflare lists the condition as supported for R2 PutObject.
([AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
[R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/))

The API reserves the object key against the declared asset revision before
returning the URL. It rejects a key already assigned elsewhere, changes to an
assigned key, and stale authorization/completion results. Collection mutations
use exact collection IDs; public reads and workspace retrieval still accept
slugs. A new ID cannot shadow an existing slug. A failed upload can be declared
again in a draft/review; a published collection requires a new asset ID and its
existing amendment process to change published references.

The completion endpoint checks the stored hash, size and MIME, malware result,
and public/IPFS availability. Repeating completion for an already verified asset
returns the saved result. Document views expose checked blob downloads, never
direct mutable storage links. File integrity and metadata-root verification are
shown separately.

Before enabling these uploads on an approved target:

- Confirm its S3-compatible provider actually enforces conditional PUTs. Using
  synthetic files in an isolated approved test prefix, prove first PUT succeeds,
  replay and different-body replacement fail, and omission/alteration of the
  signed condition fails authentication. Read back the original bytes.
- Allow the returned `If-None-Match` header in the bucket's approved CORS policy;
  confirm the browser preflight and upload from the exact portal origin.
- Confirm private originals remain private and their authorized downloads work.
- Retire old upload issuers during the approved transition. Existing presigned
  URLs remain usable until expiry or credential revocation, so the code patch
  does not revoke previously issued overwrite-capable URLs. Preserve evidence,
  wait for their documented maximum lifetime or use a separately approved
  revocation, then recheck every published document against its commitment.
  [AWS presigned URL lifetime](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)

Local regression tests and SDK signature comparison are not provider outcome
evidence. Provider behavior, deployed CORS, historical-object integrity and the
approved transition remain release gates.
