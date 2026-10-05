import { randomBytes } from 'node:crypto';
import { httpbis } from 'http-message-signatures';
import { serializeDictionary } from 'structured-headers';
import type { ProviderSigner } from './keys.js';
import { checkPublicRequest, EMPTY_DIGEST, MAX_LIFETIME_SECONDS, requireOrigin, requiredFields } from './profile.js';
import type { Clock, Fetcher } from './types.js';

export interface SignerOptions {
  providerOrigin: string;
  signer: ProviderSigner;
  allowedOrigins: readonly string[];
  lifetimeSeconds?: number;
  clock?: Clock;
}

export function createRequestSigner(options: SignerOptions) {
  const provider = requireOrigin(options.providerOrigin);
  const destinations = new Set(options.allowedOrigins.map(requireOrigin));
  if (destinations.size === 0) throw new Error('Configure at least one allowed destination');
  const lifetime = options.lifetimeSeconds ?? MAX_LIFETIME_SECONDS;
  if (!Number.isSafeInteger(lifetime) || lifetime < 1 || lifetime > MAX_LIFETIME_SECONDS) {
    throw new Error('Signature lifetime must be between 1 and 60 seconds');
  }
  const clock = options.clock ?? Date.now;

  async function signRequest(request: Request): Promise<Request> {
    checkPublicRequest(request);
    if (!destinations.has(new URL(request.url).origin)) throw new Error('Destination is not authorized for this signer');
    const headers = new Headers(request.headers);
    headers.delete('signature');
    headers.delete('signature-input');
    headers.delete('signature-agent');
    headers.set('content-digest', EMPTY_DIGEST);
    headers.set('signature-agent', serializeDictionary(new Map([['agent', [provider, new Map()]]])));
    const created = Math.floor(clock() / 1000);
    const signed = await httpbis.signMessage({
      name: 'agent',
      key: { id: options.signer.keyId, alg: 'ed25519', sign: data => options.signer.sign(data) },
      fields: requiredFields('agent'),
      params: ['created', 'expires', 'keyid', 'alg', 'nonce', 'tag'],
      paramValues: {
        created: new Date(created * 1000), expires: new Date((created + lifetime) * 1000),
        nonce: randomBytes(24).toString('base64url'), tag: 'web-bot-auth',
      },
    }, { method: request.method, url: request.url, headers: Object.fromEntries(headers) });
    return new Request(request, { headers: signed.headers, redirect: 'manual' });
  }

  async function signedFetch(input: Request | string | URL, init?: RequestInit, transport: Fetcher = fetch): Promise<Response> {
    const request = new Request(input, init);
    return transport(await signRequest(request));
  }

  return { signRequest, signedFetch };
}
