"""Test-only client used by the repository's cross-language HTTPS checks."""

import json
import ssl
import sys
import time
from pathlib import Path

import httpx

from sar import Ed25519Signer, RequestSigner

config = json.load(sys.stdin)
target = httpx.URL(config["targetUri"])
signer = RequestSigner(
    provider_origin=config["providerOrigin"],
    signer=Ed25519Signer.from_pem(Path(config["keyPath"]).read_bytes()),
    allowed_origins=["https://" + target.netloc.decode("ascii")],
    clock=lambda: config.get("clockSeconds", time.time()),
)
output = {}
if config.get("send"):
    tls = ssl.create_default_context(cafile=config["caPath"])
    with httpx.Client(verify=tls, trust_env=False, timeout=5, follow_redirects=True) as client:
        response = signer.fetch(client, config["method"], target)
        output.update(status=response.status_code, body=response.text)
        signed = response.request
else:
    signed = signer.sign_request(httpx.Request(config["method"], target))
output.update(method=signed.method, url=str(signed.url), headers=dict(signed.headers))
json.dump(output, sys.stdout)
