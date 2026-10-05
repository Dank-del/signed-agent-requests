# SAR TypeScript SDK

The original SAR SDK is written in TypeScript and lives in the repository's root [`src/`](../../src/) directory. Bun is its tested runtime. Version `0.0.1` includes the signing client, verifier, key discovery, replay protection, and website policy interfaces. Go and Python provide additional signing clients for the same protocol.

## Installation

Build from the public repository with Bun:

```bash
git clone https://github.com/Dank-del/signed-agent-requests.git
cd signed-agent-requests
bun install --frozen-lockfile
bun run build
```

From another project, add the built checkout as a local dependency:

```bash
bun add ../signed-agent-requests
```

The package exports JavaScript and TypeScript declarations from `dist/`. A package registry release is separate from this source installation.

## Sign requests

```ts
import { createRequestSigner, signerFromPrivateKey } from 'signed-agent-requests';

const signer = createRequestSigner({
  providerOrigin: 'https://provider.example',
  signer: signerFromPrivateKey(await Bun.file('/secure/provider-key.pem').text()),
  allowedOrigins: ['https://shop.example'],
});

const response = await signer.signedFetch(
  'https://shop.example/agent/catalog?category=books',
);
```

`signRequest(request)` signs a finalised `Request` and returns a clone. `signedFetch(input, init, transport)` builds, signs, and sends a request. The returned request uses manual redirect handling; sign a fresh request for an allowed redirected destination. The clock callback returns Unix milliseconds. An isolated signing service can implement the `ProviderSigner` interface.

## Verify requests

The same package exports `RequestVerifier`, `KeyDirectoryResolver`, `RedisReplayStore`, `RedisRateLimiter`, `createProviderPolicy`, and `createAgentHandler`. See the root [verification example](../../README.md#verify-and-apply-website-policy), [protocol specification](../../docs/protocol.md), and [security policy](../../SECURITY.md).

Run `bun run check` in the repository root for strict type checking, tests, and the library build. MIT licensed.
