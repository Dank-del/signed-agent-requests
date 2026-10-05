# Implemented signed request profile

Profile `signed-agent-requests/0.1`, based on [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html), [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html), and [Web Bot Auth draft 00](https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00). These rules define this application's strict subset; general Web Bot Auth signatures can be valid while failing this profile.

## Requests

Accept only HTTPS GET and HEAD requests without content, user credentials, content encoding, or transfer encoding. A supplied `Content-Length` must be exactly `0`; a supplied Host must match the URL authority. Maximum reconstructed URL length is 8192 characters and combined header-name/value size is 16384 bytes.

The signer permits only configured destination origins. The verifier resolves keys only from configured provider origins. Origins must be canonical HTTPS origins without paths, query strings, fragments, or user information. The provider's directory is always its origin plus `/.well-known/http-message-signatures-directory`.

## Signed components and metadata

Exactly one signature is accepted. `Signature`, `Signature-Input`, and `Signature-Agent` must each contain exactly one dictionary member with the same label. Header values must use canonical structured-field serialization. This intentionally rejects duplicate dictionary members/parameters, extra signatures, and noncanonical encodings. The label is at most 32 characters and matches `[a-z][a-z0-9_-]*`.

The four required covered components are `@method`, `@target-uri`, `content-digest`, and `signature-agent;key="<label>"`. Each appears exactly once; ordering is preserved in the signature base. Other components and component parameters are rejected in v0.1.

`Signature-Agent` uses the dictionary form from the pinned draft, with a string origin and either no item parameter or `type=directory`. The origin used for attribution is the configured provider whose directory supplied the verification key.

The only signature parameters are integer `created`, integer `expires`, string `keyid`, string `alg="ed25519"`, string `nonce`, and string `tag="web-bot-auth"`. The signature is an unparameterized 64-byte Ed25519 byte sequence. The key identifier is the base64url SHA-256 JWK thumbprint; the nonce is canonical base64url containing 16 to 32 bytes. The SDK generates 24 random bytes.

`Content-Digest` contains exactly an unparameterized SHA-256 byte sequence. The verifier compares it to the empty-content hash and the signature covers the transmitted digest header. Content-bearing requests are rejected before verification.

## Time and replay

All clock callbacks return Unix milliseconds. Metadata timestamps use Unix seconds. With `now = floor(clock() / 1000)`, require:

```text
created >= 0
created <= now + 5
expires > created
expires - created <= 60
now < expires
```

Check time before key discovery, after cryptographic verification, and after the replay-store operation. Failed signatures never reserve a nonce.

The replay identity is SHA-256 of the JSON array `[providerOrigin, keyId, nonce]`. Redis reserves that identity using `SET key 1 NX PX ttl`. Only an `OK` response permits progress; a null result means replay, and an error, disconnect, or timeout makes verification unavailable. Keep the reservation until `expires * 1000 + 10000`; the adapter caps retention at 80000 milliseconds. Clocks across replicas must remain within the documented allowance.

The replay store assumes coordinated state across replicas. Redis eviction or loss of state invalidates the replay guarantee; deployment must retain reservations through their full lifetime. Per-request and per-minute operations use bounded Redis deadlines, with offline queuing disabled in the supplied demo configuration.

## Discovery and rotation

Public directory content is limited to 65536 bytes and 16 unique Ed25519 keys. Reject private `d` fields, mismatched JWK thumbprints, incompatible declared algorithms/usage/operations, and malformed key material. Evaluate optional `nbf` and `exp` at lookup time.

Discovery requires status 200 and `application/http-message-signatures-directory+json`. Redirects are forbidden. Default network timeout is 2000 milliseconds. Directory keys are replaced together after a successful refresh; a failure does not extend their previous expiry. Default maximum cache lifetime is 60 seconds, limited further by provider cache directives. Refresh attempts are coalesced and throttled to one per configured provider per 5 seconds.

Publishing a new key allows existing identity continuity through the provider origin. Removal takes effect after cached directories expire. An emergency denied key is checked before lookup and after asynchronous verification work, and overrides cached material locally. Deployment must distribute that denial to all replicas.

## Website results

| Condition | Verification or policy result | Middleware HTTP status |
| --- | --- | --- |
| No signature headers | unsigned | 401 |
| Malformed, unsupported, expired, untrusted, or invalid signature | invalid | 401 |
| Reused nonce | invalid with replay reason | 409 |
| Directory or replay dependency unavailable | unverifiable | 503 |
| Verified identity denied by website | deny | 403 |
| Verified identity exceeds provider limit | rate limit | 429 |
| Policy dependency unavailable | unavailable | 503 |
| Request URL has the wrong configured origin | destination rejection | 400 |
| Verified and allowed | application handler receives identity | application response |

Middleware responses use `Cache-Control: no-store`. A protected endpoint must run verification and policy before a cache can return a privileged response. Shared provider rate limits use an atomic Lua script and Redis's clock. Denied or unconfigured policy providers do not consume a rate-limit slot. Retry-after values are returned on temporary failures and rate limits.

## Compatibility

The [Cloudflare integration documentation](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/) describes a string-form `Signature-Agent` and no nonce reuse database. It does not implement the strict guarantees or dictionary format used here. The implementation does not silently accept that older format or weaker coverage.

The message-signature dependency is pinned to `http-message-signatures@1.0.6`; structured-field parsing is pinned to `structured-headers@2.1.0`. The code uses the dependency for RFC signature-base formatting, while enforcing the application profile, time checks, content digest, provider binding, and replay separately. Tests verify the published RFC Ed25519 vector and independently assembled strict-profile signatures in both directions. Independent external-provider testing remains a separate pilot milestone.
