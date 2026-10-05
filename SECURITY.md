# Security policy

The current `0.0.x` implementation is an experimental public-read pilot. Security fixes target the latest revision on `main`. Independent provider integration and deployment-specific validation are still required; the project has not received an independent security audit.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository's **Security** tab when available. If private reporting is unavailable, open an issue asking for a private reporting channel without posting exploit details, sensitive request data, or keys.

Include the affected revision, a minimal reproduction using disposable keys, the expected and actual behavior, and the relevant runtime and deployment configuration. Never send production signing keys or credentials.

## Supported boundary

The verifier checks provider key possession and the signed request components. Website access policy is separate. The current profile accepts HTTPS GET/HEAD without request bodies, cookies, or authorization headers.

See [the protocol contract](docs/protocol.md) and [deployment boundaries](README.md#deployment-boundaries) for key trust, revocation, proxy handling, replay-store retention, and failure behavior.
