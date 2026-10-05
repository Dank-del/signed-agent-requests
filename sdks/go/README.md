# SAR Go SDK

Standard-library signing client for SAR (Signed Agent Requests), version `0.0.1`. Requires Go 1.23+. It produces the same strict public GET/HEAD profile as the Bun implementation. Verification, key discovery, replay storage, and website policy are implemented by the Bun verifier.

```bash
go get github.com/Dank-del/signed-agent-requests/sdks/go@main
```

This selects a moving branch. Pin the resolved module version in applications.

```go
package main

import (
    "log"
    "net/http"
    "os"
    "time"
    sar "github.com/Dank-del/signed-agent-requests/sdks/go"
)

func main() {
    pem, err := os.ReadFile("/secure/provider-key.pem")
    if err != nil { log.Fatal(err) }
    key, err := sar.ParsePrivateKey(pem)
    if err != nil { log.Fatal(err) }
    signer, err := sar.NewSigner(key, sar.Options{
        ProviderOrigin: "https://provider.example",
        AllowedOrigins: []string{"https://shop.example"},
    })
    if err != nil { log.Fatal(err) }
    client := signer.Client(&http.Client{Timeout: 30 * time.Second})
    response, err := client.Get("https://shop.example/agent/catalog?category=books")
    if err != nil { log.Fatal(err) }
    defer response.Body.Close()
    log.Printf("HTTP %d", response.StatusCode)
}
```

`Client` copies the base client, disables automatic redirects and cookie storage, and signs every final outgoing request. It preserves the supplied transport and TLS configuration. Credential headers, request bodies, non-HTTPS URLs, and destinations outside the allowlist are rejected. An isolated Ed25519 `crypto.Signer` can replace a local private key.

`Sign(*http.Request)` returns a cloned request for integrations managing their own transport. Disable automatic redirects and do not change the returned URL or signed headers. Supply canonical ASCII/IDNA hostnames and percent-encoded queries; normalise dot segments before signing. A custom transport must preserve signed components and must not add user credentials. `PublicJWK()` returns public-only key directory fields.

Development checks:

```bash
go test -race ./...
go vet ./...
```

See the root [protocol contract](../../docs/protocol.md) and [security policy](../../SECURITY.md). MIT licensed. Shared fixtures contain explicitly public test seeds; never use fixture keys for real providers.
