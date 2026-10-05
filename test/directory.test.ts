import { describe, expect, test } from 'bun:test';
import {
  DIRECTORY_CONTENT_TYPE, DIRECTORY_PATH, generateProviderKey, keyDirectory, KeyDirectoryResolver,
  createRequestSigner, signerFromPrivateKey, type Fetcher,
} from '../src/index.js';
import { harness, NOW, PROVIDER, SHOP, TARGET } from './helpers.js';

describe('trusted key discovery', () => {
  test('deduplicates concurrent discovery and throttles unknown key refresh', async () => {
    const h = harness();
    await Promise.all(Array.from({ length: 30 }, () => h.resolver.resolve(PROVIDER, h.signingKey.keyId)));
    expect(h.calls).toBe(1);
    const unknown = generateProviderKey().publicKey.kid;
    await Promise.all(Array.from({ length: 30 }, () => h.resolver.resolve(PROVIDER, unknown)));
    expect(h.calls).toBe(1);
    h.setNow(NOW + 5_000);
    expect(await h.resolver.resolve(PROVIDER, unknown)).toBeUndefined();
    expect(h.calls).toBe(2);
    expect(await h.resolver.resolve('https://attacker.example', h.signingKey.keyId)).toBeUndefined();
    expect(h.calls).toBe(2);
  });

  test('rotates keys without changing identity and removes old keys after cache refresh', async () => {
    const h = harness();
    const first = await h.request();
    expect((await h.verifier.verify(first)).status).toBe('verified');
    const secondKey = generateProviderKey();
    h.setKeys([h.initialKey, secondKey]);
    h.setNow(NOW + 5_000);
    const secondSigner = createRequestSigner({ providerOrigin: PROVIDER, signer: signerFromPrivateKey(secondKey.privateKeyPem), allowedOrigins: [SHOP], clock: h.clock });
    expect((await h.verifier.verify(await secondSigner.signRequest(new Request(TARGET)))).status).toBe('verified');
    expect((await h.verifier.verify(await h.request())).status).toBe('verified');
    h.setKeys([secondKey]);
    h.setNow(NOW + 16_000);
    expect(await h.verifier.verify(await h.request())).toEqual({ status: 'invalid', reason: 'unknown_key' });
    expect((await h.verifier.verify(await secondSigner.signRequest(new Request(TARGET)))).status).toBe('verified');
  });

  test('emergency denial overrides cached key material immediately', async () => {
    const h = harness();
    expect((await h.verifier.verify(await h.request())).status).toBe('verified');
    h.resolver.denyKey(PROVIDER, h.signingKey.keyId);
    expect(await h.verifier.verify(await h.request())).toEqual({ status: 'invalid', reason: 'key_denied' });
    expect(h.calls).toBe(1);
  });

  test('associates each provider with its own fetched directory', async () => {
    const keyA = generateProviderKey();
    const keyB = generateProviderKey();
    const calls: string[] = [];
    const other = 'https://other-provider.example';
    const resolver = new KeyDirectoryResolver({ providers: [PROVIDER, other], fetch: async input => {
      const url = String(input);
      calls.push(url);
      return Response.json(keyDirectory([url.startsWith(PROVIDER) ? keyA.publicKey : keyB.publicKey]), {
        headers: { 'content-type': DIRECTORY_CONTENT_TYPE },
      });
    } });
    expect(await resolver.resolve(PROVIDER, keyA.publicKey.kid)).toBeDefined();
    expect(await resolver.resolve(other, keyA.publicKey.kid)).toBeUndefined();
    expect(calls).toEqual([PROVIDER + DIRECTORY_PATH, other + DIRECTORY_PATH]);
  });

  test('enforces key validity windows', async () => {
    let now = NOW;
    const key = generateProviderKey().publicKey;
    const resolver = new KeyDirectoryResolver({ providers: [PROVIDER], clock: () => now,
      fetch: async () => Response.json(keyDirectory([{ ...key, nbf: NOW / 1000 + 1, exp: NOW / 1000 + 3 }]), {
        headers: { 'content-type': DIRECTORY_CONTENT_TYPE },
      }),
    });
    expect(await resolver.resolve(PROVIDER, key.kid)).toBeUndefined();
    now += 1000;
    expect(await resolver.resolve(PROVIDER, key.kid)).toBeDefined();
    now += 2000;
    expect(await resolver.resolve(PROVIDER, key.kid)).toBeUndefined();
  });

  test('does not serve stale keys during outages and backs off failing refreshes', async () => {
    let now = NOW;
    let calls = 0;
    let offline = false;
    const key = generateProviderKey().publicKey;
    const resolver = new KeyDirectoryResolver({ providers: [PROVIDER], clock: () => now, fetch: async () => {
      calls++;
      if (offline) throw new Error('offline');
      return Response.json(keyDirectory([key]), { headers: { 'content-type': DIRECTORY_CONTENT_TYPE, 'cache-control': 'max-age=5' } });
    } });
    expect(await resolver.resolve(PROVIDER, key.kid)).toBeDefined();
    offline = true;
    now += 6000;
    await expect(resolver.resolve(PROVIDER, key.kid)).rejects.toThrow('directory unavailable');
    await expect(resolver.resolve(PROVIDER, key.kid)).rejects.toThrow('directory unavailable');
    expect(calls).toBe(2);
  });

  test('rejects malformed, private, mismatched, duplicate, or oversized directory data', async () => {
    const key = generateProviderKey().publicKey;
    for (const payload of [
      {}, { keys: [] }, { keys: [{ ...key, d: 'private' }] },
      { keys: [{ ...key, kid: generateProviderKey().publicKey.kid }] },
      { keys: [{ ...key, crv: 'X25519' }] }, { keys: [key, key] },
      { keys: [{ ...key, key_ops: ['sign'] }] }, { keys: [{ ...key, x: 'bad' }] },
      { keys: [{ ...key, nbf: -1 }] }, { keys: [{ ...key, nbf: 5, exp: 4 }] },
    ]) {
      const resolver = new KeyDirectoryResolver({ providers: [PROVIDER], fetch: async () => Response.json(payload, {
        headers: { 'content-type': DIRECTORY_CONTENT_TYPE },
      }) });
      await expect(resolver.resolve(PROVIDER, key.kid)).rejects.toThrow();
    }
    const oversized = new KeyDirectoryResolver({ providers: [PROVIDER], maxBytes: 32,
      fetch: async () => Response.json(keyDirectory([key]), { headers: { 'content-type': DIRECTORY_CONTENT_TYPE } }),
    });
    await expect(oversized.resolve(PROVIDER, key.kid)).rejects.toThrow();
  });

  test('requests only the configured HTTPS directory and refuses redirect responses', async () => {
    const key = generateProviderKey().publicKey;
    let init: RequestInit | undefined;
    const transport: Fetcher = async (input, options) => {
      expect(String(input)).toBe(PROVIDER + DIRECTORY_PATH);
      init = options;
      return new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/secret' } });
    };
    const resolver = new KeyDirectoryResolver({ providers: [PROVIDER], fetch: transport });
    await expect(resolver.resolve(PROVIDER, key.kid)).rejects.toThrow();
    expect(init?.redirect).toBe('error');
    expect(init?.signal).toBeDefined();
    expect(() => new KeyDirectoryResolver({ providers: ['http://provider.example'] })).toThrow();
    expect(() => new KeyDirectoryResolver({ providers: [PROVIDER + '/keys'] })).toThrow();
  });

  test('bounds discovery even if the custom transport ignores cancellation', async () => {
    const key = generateProviderKey().publicKey;
    const resolver = new KeyDirectoryResolver({ providers: [PROVIDER], timeoutMs: 20,
      fetch: () => new Promise<Response>(() => {}),
    });
    await expect(resolver.resolve(PROVIDER, key.kid)).rejects.toThrow('directory unavailable');
  });

  test('times out a stalled directory stream and does not retain partial keys', async () => {
    const key = generateProviderKey().publicKey;
    let cancelled = false;
    const resolver = new KeyDirectoryResolver({ providers: [PROVIDER], timeoutMs: 20, fetch: async () => {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) { controller.enqueue(new TextEncoder().encode('{"keys":[')); },
        cancel() { cancelled = true; },
      });
      return new Response(stream, { headers: { 'content-type': DIRECTORY_CONTENT_TYPE } });
    } });
    await expect(resolver.resolve(PROVIDER, key.kid)).rejects.toThrow('directory unavailable');
    expect(cancelled).toBe(true);
  });
});
