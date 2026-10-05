# SAR Python SDK

Python 3.11+ signing client for SAR (Signed Agent Requests), version `0.0.1`. It produces the same strict public GET/HEAD profile as the Bun implementation. Verification, key discovery, replay storage, and website policy are implemented by the Bun verifier.

Install directly from the public repository using uv:

```bash
uv add "sar-signed-agent-requests @ git+https://github.com/Dank-del/signed-agent-requests.git@main#subdirectory=sdks/python"
```

This installs from a moving branch. Pin a reviewed commit in applications. The package is not published on PyPI by this repository's checks or builds.

```python
from pathlib import Path
import httpx
from sar import Ed25519Signer, RequestSigner

signer = RequestSigner(
    provider_origin="https://provider.example",
    signer=Ed25519Signer.from_pem(Path("/secure/provider-key.pem").read_bytes()),
    allowed_origins=["https://shop.example"],
)
with httpx.Client(timeout=30) as client:
    response = signer.fetch(client, "GET", "https://shop.example/agent/catalog?category=books")
    response.raise_for_status()
```

For asynchronous clients, call `await signer.afetch(client, "GET", url)` with an `httpx.AsyncClient`. Both helpers sign the final client-built request, disable redirects, and disable authentication applied after signing. Client default cookies or credential headers cause rejection. An isolated signer can implement the `ProviderSigner` protocol instead of loading a local key.

`sign_request(httpx.Request(...))` returns a cloned request for integrations that manage their own transport. Send it with `client.send(request, follow_redirects=False, auth=None)` and do not alter its URL or signed headers. Configure ordinary TLS verification; a custom transport must preserve signed components and must not add user credentials. The clock callback returns Unix seconds.

To develop from this checkout:

```bash
uv sync --frozen
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen python -m unittest discover -s tests -v
uv build
```

See the root [protocol contract](../../docs/protocol.md) and [security policy](../../SECURITY.md). MIT licensed. Shared fixtures contain explicitly public test seeds; never use fixture keys for real providers.
