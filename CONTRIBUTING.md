# Contributing

Use Bun 1.4+ and the committed `bun.lock`. Install dependencies with `bun install --frozen-lockfile`, then run `bun run check` before opening a pull request. OpenSSL and a Redis 7.2+ or Valkey executable are needed for the local integration tests. Alternatively, point `TEST_REDIS_URL` at a dedicated test database.

The implementation contract is in [docs/protocol.md](docs/protocol.md). Changes to accepted signature formats, request coverage, time constraints, trust, replay handling, or policy outcomes must update that contract and include a test demonstrating the intended behavior. Keep independently constructed signature tests and the RFC vector independent of the signing SDK.

The current scope is hosted clients making public GET/HEAD requests. Propose browser integration, delegation, or state-changing operations in an issue before implementing them so their authorization and signature coverage can be designed together.

Generate development keys locally with `bun run demo:setup`. Keep private keys, certificates, environment files, dependency directories, and build output out of commits. Report security findings using [SECURITY.md](SECURITY.md).
