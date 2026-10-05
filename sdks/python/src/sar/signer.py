"""Implementation of the strict signed-agent-requests/0.1 signing profile."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Protocol
from urllib.parse import unquote

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EMPTY_DIGEST = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
PROFILE = "signed-agent-requests/0.1"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class ProviderSigner(Protocol):
    """An Ed25519 signer; callers may implement this using isolated key custody."""

    @property
    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> bytes: ...


class Ed25519Signer:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("an Ed25519 private key is required")
        self._key = key
        self._public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        fields = {"crv": "Ed25519", "kty": "OKP", "x": _base64url(self._public)}
        thumbprint = json.dumps(fields, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self._key_id = _base64url(hashlib.sha256(thumbprint).digest())

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> Ed25519Signer:
        """Load an Ed25519 private key; encrypted PEM keys may supply a password."""
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("an Ed25519 private key is required")
        return cls(key)

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_jwk(self) -> dict[str, object]:
        """Return public-only fields suitable for the provider directory."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _base64url(self._public),
            "kid": self.key_id,
            "alg": "ed25519",
            "use": "sig",
            "key_ops": ["verify"],
        }

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


def _origin(url: httpx.URL) -> str:
    if url.scheme != "https" or not url.is_absolute_url or url.username or url.password:
        raise ValueError("an absolute HTTPS URL without credentials is required")
    host = url.host
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[a-z0-9._-]+", host):
            raise ValueError("use an ASCII/IDNA DNS name or canonical IP address") from None
        if re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]*)", host.rstrip(".").split(".")[-1]):
            raise ValueError("ambiguous numeric host") from None
    else:
        if str(address) != host:
            raise ValueError("use a canonical IP address")
    return "https://" + url.netloc.decode("ascii")


def _require_origin(value: str) -> str:
    origin = _origin(httpx.URL(value))
    if origin != value:
        raise ValueError(
            "origins must be canonical HTTPS origins without paths, queries, or fragments"
        )
    return origin


def _check_size(request: httpx.Request) -> None:
    if len(str(request.url)) > 8192 or sum(len(k) + len(v) for k, v in request.headers.raw) > 16384:
        raise ValueError("request exceeds profile bounds")


class RequestSigner:
    def __init__(
        self,
        *,
        provider_origin: str,
        signer: ProviderSigner,
        allowed_origins: Iterable[str],
        lifetime_seconds: int = 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._provider = _require_origin(provider_origin)
        self._destinations = frozenset(_require_origin(value) for value in allowed_origins)
        if not self._destinations:
            raise ValueError("configure at least one allowed destination")
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 60:
            raise ValueError("signature lifetime must be between 1 and 60 seconds")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", signer.key_id):
            raise ValueError("invalid JWK thumbprint")
        if _base64url(base64.urlsafe_b64decode(signer.key_id + "=")) != signer.key_id:
            raise ValueError("invalid JWK thumbprint")
        self._signer = signer
        self._lifetime = lifetime_seconds
        self._clock = clock

    def sign_request(self, request: httpx.Request) -> httpx.Request:
        """Clone a finalized request. Use send(..., follow_redirects=False, auth=None)."""
        origin = _origin(request.url)
        if origin not in self._destinations:
            raise ValueError("destination is not authorized for this signer")
        if request.method not in ("GET", "HEAD") or "#" in str(request.url):
            raise ValueError("only public HTTPS GET/HEAD requests without content are supported")
        try:
            content = request.content
        except httpx.RequestNotRead as error:
            raise ValueError("streaming request content is not supported") from error
        if content:
            raise ValueError("request content is not supported")
        forbidden = ("authorization", "cookie", "content-encoding", "transfer-encoding")
        if any(name in request.headers for name in forbidden):
            raise ValueError("user credentials and content encodings are not supported")
        if "content-length" in request.headers and request.headers["content-length"] != "0":
            raise ValueError("Content-Length must be exactly 0")
        if "host" in request.headers and request.headers["host"] != request.url.netloc.decode(
            "ascii"
        ):
            raise ValueError("Host must match the URL authority")
        _check_size(request)
        # raw_path includes the exact encoded path/query and always has a root slash.
        target = origin + request.url.raw_path.decode("ascii")
        path = unquote(request.url.raw_path.split(b"?", 1)[0].decode("ascii"))
        if any(part in (".", "..") for part in path.split("/")):
            raise ValueError("normalize dot segments before signing")
        headers = httpx.Headers(request.headers)
        for name in ("signature", "signature-input", "signature-agent"):
            headers.pop(name, None)
        headers["content-digest"] = EMPTY_DIGEST
        headers["signature-agent"] = f'agent="{self._provider}"'
        created = math.floor(self._clock())
        if not 0 <= created <= 999999999999999 - self._lifetime:
            raise ValueError("invalid signing time")
        nonce = _base64url(secrets.token_bytes(24))
        params = (
            '("@method" "@target-uri" "content-digest" "signature-agent";key="agent")'
            f';created={created};expires={created + self._lifetime};keyid="{self._signer.key_id}"'
            f';alg="ed25519";nonce="{nonce}";tag="web-bot-auth"'
        )
        base = (
            f'"@method": {request.method}\n'
            f'"@target-uri": {target}\n'
            f'"content-digest": {EMPTY_DIGEST}\n'
            f'"signature-agent";key="agent": "{self._provider}"\n'
            f'"@signature-params": {params}'
        )
        signature = self._signer.sign(base.encode("ascii"))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("signer returned an invalid Ed25519 signature")
        headers["signature-input"] = "agent=" + params
        headers["signature"] = "agent=:" + base64.b64encode(signature).decode("ascii") + ":"
        result = httpx.Request(
            request.method, target, headers=headers, extensions=dict(request.extensions)
        )
        _check_size(result)
        return result

    def fetch(
        self,
        client: httpx.Client,
        method: str,
        url: str | httpx.URL,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Build, sign, and send with redirects and post-signing auth disabled."""
        request = client.build_request(method, url, headers=headers)
        return client.send(self.sign_request(request), follow_redirects=False, auth=None)

    async def afetch(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str | httpx.URL,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Async equivalent of fetch; both clients use the same signing profile."""
        request = client.build_request(method, url, headers=headers)
        return await client.send(self.sign_request(request), follow_redirects=False, auth=None)
