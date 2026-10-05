import asyncio
import base64
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sar import Ed25519Signer, RequestSigner

FIXTURE = json.loads((Path(__file__).parent / "fixtures/signing-v1.json").read_text())


def signer(origins=("https://shop.example",)):
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(FIXTURE["privateKeySeedHex"]))
    return RequestSigner(
        provider_origin=FIXTURE["providerOrigin"],
        signer=Ed25519Signer(key),
        allowed_origins=origins,
        clock=lambda: FIXTURE["cases"][0]["created"],
    )


class SigningTests(unittest.TestCase):
    def test_shared_vectors_and_independent_crypto(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(FIXTURE["privateKeySeedHex"]))
        self.assertEqual(Ed25519Signer(key).key_id, FIXTURE["keyId"])
        for case in FIXTURE["cases"]:
            with self.subTest(case=case["name"]):
                nonce = base64.urlsafe_b64decode(case["nonce"] + "==")
                request = httpx.Request(case["method"], case["targetUri"])
                request.headers["signature"] = "old signature"
                with patch("sar.signer.secrets.token_bytes", return_value=nonce):
                    signed = signer().sign_request(request)
                self.assertEqual(str(signed.url), case["targetUri"])
                for name, value in case["headers"].items():
                    self.assertEqual(signed.headers[name], value)
                self.assertEqual(request.headers["signature"], "old signature")
                signature = base64.b64decode(signed.headers["signature"][7:-1])
                key.public_key().verify(signature, case["signatureBase"].encode())

    def test_rejects_unsupported_requests(self):
        cases = [
            httpx.Request("GET", "http://shop.example/"),
            httpx.Request("GET", "https://user:secret@shop.example/"),
            httpx.Request("GET", "https://other.example/"),
            httpx.Request("GET", "https://shop.example/#section"),
            httpx.Request("GET", "https://shop.example/a/%2e%2e/b"),
            httpx.Request("POST", "https://shop.example/"),
            httpx.Request("GET", "https://shop.example/", content=b"content"),
        ]
        for name, value in [
            ("cookie", ""),
            ("authorization", "Bearer example"),
            ("content-encoding", "gzip"),
            ("transfer-encoding", "chunked"),
            ("content-length", "1"),
            ("host", "other.example"),
            ("x-padding", "x" * 16000),
        ]:
            cases.append(httpx.Request("GET", "https://shop.example/", headers={name: value}))
        for request in cases:
            with self.subTest(request=request):
                with self.assertRaises(ValueError):
                    signer().sign_request(request)

    def test_rejects_streaming_content(self):
        request = httpx.Request("GET", "https://shop.example/", content=iter([b"content"]))
        with self.assertRaises(ValueError):
            signer().sign_request(request)

    def test_configuration_and_public_only_key(self):
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        provider_key = Ed25519Signer.from_pem(pem)
        self.assertNotIn("d", provider_key.public_jwk())
        self.assertEqual(provider_key.key_id, Ed25519Signer(key).key_id)
        for overrides in [
            {"allowed_origins": []},
            {"provider_origin": "https://provider.example/"},
            {"allowed_origins": ["http://shop.example"]},
            {"lifetime_seconds": 61},
            {"lifetime_seconds": True},
        ]:
            with self.subTest(overrides=overrides):
                options = {
                    "provider_origin": "https://provider.example",
                    "signer": provider_key,
                    "allowed_origins": ["https://shop.example"],
                    **overrides,
                }
                with self.assertRaises(ValueError):
                    RequestSigner(**options)
        with self.assertRaises(ValueError):
            Ed25519Signer.from_pem(b"invalid")

    def test_canonical_root_and_fresh_nonces(self):
        request = httpx.Request("GET", "https://SHOP.EXAMPLE:443")
        first = signer().sign_request(request)
        second = signer().sign_request(request)
        self.assertEqual(str(first.url), "https://shop.example/")
        self.assertNotEqual(first.headers["signature-input"], second.headers["signature-input"])
        self.assertNotIn("signature", request.headers)

    def test_fetch_does_not_follow_redirects_or_apply_auth_after_signing(self):
        calls = []

        def respond(request):
            calls.append(request)
            self.assertIn("signature", request.headers)
            self.assertNotIn("authorization", request.headers)
            return httpx.Response(302, headers={"location": "/next"})

        with httpx.Client(
            transport=httpx.MockTransport(respond),
            follow_redirects=True,
            auth=httpx.BasicAuth("user", "secret"),
        ) as client:
            response = signer().fetch(client, "GET", "https://shop.example/first")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(calls), 1)

    def test_fetch_rejects_client_cookie_defaults(self):
        with httpx.Client(cookies={"session": "example"}) as client:
            with self.assertRaises(ValueError):
                signer().fetch(client, "GET", "https://shop.example/")

    def test_async_fetch(self):
        async def run():
            calls = []

            def respond(request):
                calls.append(request)
                return httpx.Response(302, headers={"location": "/next"})

            async with httpx.AsyncClient(
                transport=httpx.MockTransport(respond),
                follow_redirects=True,
            ) as client:
                response = await signer().afetch(client, "HEAD", "https://shop.example/")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(len(calls), 1)
            self.assertIn("signature", calls[0].headers)

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
