# Contributing

Use Bun 1.4+ and the committed `bun.lock`. Install dependencies with `bun install --frozen-lockfile`, then run `bun run check` before opening a pull request. OpenSSL and a Redis 7.2+ or Valkey executable are needed for the local integration tests. Alternatively, point `TEST_REDIS_URL` at a dedicated test database.

The implementation contract is in [docs/protocol.md](docs/protocol.md). Changes to accepted signature formats, request coverage, time constraints, trust, replay handling, or policy outcomes must update that contract and include a test demonstrating the intended behaviour. Keep independently constructed signature tests and the RFC vector independent of the signing SDK.

The current scope is hosted clients making public GET/HEAD requests. Propose browser integration, delegation, or state-changing operations in an issue before implementing them so their authorisation and signature coverage can be designed together.

Go and Python signing SDKs live under `sdks/`. Follow each SDK's README for native tests and builds, and run `bun run check:sdks` from the repository root for interoperability checks. Shared golden fixtures are generated independently of the signing SDKs by `bun fixtures/generate.ts`; the fixture seed is explicitly public test material.

Generate development keys locally with `bun run demo:setup`. Keep real private keys, certificates, environment files, dependency directories, and build output out of commits. The committed public conformance seed must never be used outside testing. Report security findings using [SECURITY.md](SECURITY.md).
