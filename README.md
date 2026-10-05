# SAR: Signed Agent Requests

SAR helps websites recognise agent providers through cryptographically signed HTTP requests. Providers publish Ed25519 public keys on their domains. Hosted agents sign each request. Websites verify the provider identity, request binding, timestamps, and unique nonce, then apply their own access policy.

The project includes signing SDKs for TypeScript/Bun, Go, and Python, plus a Bun verifier with key discovery, shared Redis replay protection, provider rate limits, and an HTTPS demo. All three clients use the same signature format and are tested against the Bun verifier.

The pilot builds on RFC 9421 and the pinned `draft-ietf-webbotauth-httpsig-protocol-00`, with a stricter application profile. See [the design](design.md) and [the protocol specification](docs/protocol.md).

Status: experimental v0.0.1. The supported flow is provider-signed, public GET/HEAD requests from hosted clients. Independent provider interoperability and deployment-specific validation remain pilot milestones.

## SDKs

| Language | Supported components | Guide |
| --- | --- | --- |
| TypeScript/Bun | Signing, verification, key discovery, replay protection, website policy | [TypeScript SDK](sdks/typescript/README.md) |
| Go 1.23+ | Standard-library signer and HTTP client; isolated `crypto.Signer` support | [Go SDK](sdks/go/README.md) |
| Python 3.11+ | Signer, synchronous and asynchronous HTTPX clients; isolated signer support | [Python SDK](sdks/python/README.md) |

The Go and Python SDKs generate requests for the same Bun verifier. Their guides include installation and usage examples. Package registry publication is separate from publishing this repository; Go and Python currently install directly from GitHub.

## Run the HTTPS demo

Requirements are Bun 1.4+, OpenSSL, and Redis 7.2+ or Valkey. A local Redis/Valkey executable lets the demo start an isolated instance on a private Unix socket. Alternatively, set `REDIS_URL` to your own dedicated Redis database.

```bash
bun install --frozen-lockfile
bun run demo
```

The demo generates dedicated provider keys and a seven-day localhost HTTPS certificate in `.local/`, which is ignored by version control. It starts a provider directory on `https://localhost:9443` and a website on `https://localhost:9444`. It never disables TLS verification. The demo client and resolver explicitly trust only the generated certificate for these local connections.

In a second terminal in this directory:

```bash
bun run demo:request
```

The client demonstrates an accepted provider request, replay rejection, a modified query, the valid original after failed tampering, an expired signature, and an unsigned request. Each scenario prints its HTTP status and PASS or FAIL; the command exits unsuccessfully if a result differs from its expectation. The website root contains a short explanation; a browser may require accepting the generated development certificate to view it.

Use `bun run demo:setup` to generate the keys before starting. `DEMO_DIRECTORY`, `PROVIDER_PORT`, `SITE_PORT`, `PROVIDER_RATE_LIMIT`, and `REDIS_URL` are optional configuration. Use matching directory and port values for the server and client. By default the rate limit is 60 requests per provider per minute. The automatic local Redis instance is ephemeral and is stopped when the demo exits.

## Use the Bun signer

```ts
import { createRequestSigner, signerFromPrivateKey } from './src/index.js';

const { signedFetch } = createRequestSigner({
  providerOrigin: 'https://provider.example',
  signer: signerFromPrivateKey(await Bun.file('/secure/provider-key.pem').text()),
  allowedOrigins: ['https://shop.example'],
});

const response = await signedFetch('https://shop.example/agent/catalog?category=books');
```

The signer accepts a pluggable `ProviderSigner`, so a provider can isolate the signing operation from the caller. Each request gets a cryptographically random nonce and a maximum lifetime of 60 seconds. The client returns redirect responses without automatically forwarding a signature; explicitly sign a new request for an allowed redirected destination.

This profile supports GET and HEAD with no content and no `Cookie` or `Authorization`. It rejects these headers explicitly. Bun 1.4's `Request.credentials` property does not reliably reflect the constructor option; the SDK does not use that metadata as an authorisation boundary. This is a hosted-client pilot rather than a browser cookie or navigation integration.

## Verify and apply website policy

```ts
import { RedisClient } from 'bun';
import {
  createAgentHandler, createProviderPolicy, KeyDirectoryResolver,
  RedisRateLimiter, RedisReplayStore, RequestVerifier,
} from './src/index.js';

const redis = new RedisClient(process.env.REDIS_URL!, {
  enableOfflineQueue: false,
  autoReconnect: true,
  maxRetries: 3,
  connectionTimeout: 1000,
});
await redis.connect();

const resolver = new KeyDirectoryResolver({ providers: ['https://provider.example'] });
await resolver.preload();

const verifier = new RequestVerifier({ resolver, replayStore: new RedisReplayStore(redis) });
const policy = createProviderPolicy({
  rules: [{ origin: 'https://provider.example', action: 'allow', requestsPerMinute: 60 }],
  rateLimiter: new RedisRateLimiter(redis),
});

const agentEndpoint = createAgentHandler({
  externalOrigin: 'https://shop.example',
  verifier,
  policy,
  handle(request, identity) {
    return Response.json({ provider: identity.providerOrigin, products: [] });
  },
});

// Invoke agentEndpoint only for the protected routes in your Bun server.
// TLS termination and routing must preserve the signed external URI.
```

All replicas serving the same endpoint must share the same Redis database and store prefix. Reserve a separate prefix for each website or environment. Set the public `externalOrigin` explicitly; forwarded headers are never used to decide it. The demo uses direct TLS. A proxy deployment must preserve the external scheme, host, path, and query before calling this middleware, and the origin server should accept traffic only from that trusted proxy.

The application receives a typed verified identity. Incoming `x-verified-*` headers are stripped. Telemetry callbacks receive verification status, identity where verified, policy outcome, and elapsed time. The demo logs those fields without request content, cookies, raw signatures, or private material.

The key directory helper `keyDirectory([publicJwk(...)])` produces public-only directory data. Serve it at `/.well-known/http-message-signatures-directory` with `application/http-message-signatures-directory+json`. Providers are explicitly configured; request-supplied keys and arbitrary key discovery URLs are not trusted.

## Check the implementation

```bash
bun run check
bun audit
```

`check` runs strict TypeScript checking, all Bun tests, and the library build. Integration tests launch an isolated Redis/Valkey process and local HTTPS services on temporary ports. If no local Redis executable is available, set `TEST_REDIS_URL` to a dedicated test Redis server. Test key prefixes are random; tests never flush an existing database.

Coverage includes a published RFC 9421 Ed25519 vector, independent signing and verification, modified requests, malformed headers, algorithm downgrade, timestamp constraints, key caching and rotation, revocation, provider isolation, expired cache failure, concurrent replay across two verifier instances, atomic shared rate limits, and real HTTPS directory discovery.

For the Go and Python SDKs, install Go and uv, then run:

```bash
cd sdks/go
go test -race ./...
go vet ./...
cd ../python
uv sync --frozen
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen python -m unittest discover -s tests -v
uv build
cd ../..
bun run check:sdks
```

`check:sdks` installs the built TypeScript package into a separate application and checks its declarations, signing, verification, and replay handling. It also verifies Go and Python requests, including encoded paths, query ordering, empty queries, and root paths, then sends real HTTPS requests through the Bun verifier and shared Redis replay store. Shared conformance fixtures in [`fixtures/`](fixtures/) contain an explicitly public RFC test seed that must never be used for a real provider.

`bun run build` emits JavaScript and declarations under `dist/`. Checks and builds do not publish packages. `@types/node` and `@types/bun` are development dependencies.

## Deployment boundaries

Signature verification establishes provider-endorsed key possession for the covered request. Website permissions remain separate. User consent, delegated user sessions, browser automation, state-changing operations, and independent external-provider interoperability are future integrations.

Redis reservations must survive service restarts for the full acceptance window. Use an appropriately persisted, protected Redis service with a no-eviction policy for replay state. If replay state is lost, suspend signed-agent acceptance until every pre-loss signature has expired; the local ephemeral demo intentionally does not make that restart guarantee. Rate limits use a fixed window based on Redis time and permit bursts at a window boundary.

Use `resolver.denyKey(providerOrigin, keyId)` for immediate local revocation. Distribute emergency denial to every verifier replica. Routine rotation publishes the new key before signing with it and retains the old key through the directory-cache and request-lifetime windows. The resolver caps key-cache lifetime at 60 seconds by default and throttles refreshes. It fails closed when an expired directory cannot be refreshed.

Cloudflare's currently documented integration uses an older `Signature-Agent` form and does not track nonce reuse. This implementation targets the pinned dictionary draft and enforces its own strict replay profile. Cloudflare compatibility mode is not implemented; see [compatibility details](docs/protocol.md#compatibility).

This is a tested implementation of the documented pilot. Deployment-specific proxy behaviour, signing-key custody, Redis persistence, and independent-provider integration still need validation in the environment where it will run.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and [SECURITY.md](SECURITY.md) for vulnerability reporting. This project is available under the [MIT license](LICENSE).
