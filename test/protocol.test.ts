import { describe, expect, test } from 'bun:test';
import { createHash, createPrivateKey, sign, verify } from 'node:crypto';
import { httpbis } from 'http-message-signatures';
import { parseDictionary, serializeDictionary, type InnerList } from 'structured-headers';
import {
  createRequestSigner, EMPTY_DIGEST, generateProviderKey, publicJwk, RequestVerifier,
  signerFromPrivateKey, type ReplayStore,
} from '../src/index.js';
import { harness, NOW, PROVIDER, SHOP, TARGET, withHeaders } from './helpers.js';

describe('strict request signatures', () => {
  test('identifies a provider and rejects a replay', async () => {
    const h = harness();
    const request = await h.request();
    const result = await h.verifier.verify(request);
    expect(result).toEqual({ status: 'verified', identity: {
      providerOrigin: PROVIDER, keyId: h.signingKey.keyId, algorithm: 'ed25519', created: NOW / 1000, expires: NOW / 1000 + 60,
    } });
    expect(await h.verifier.verify(request)).toEqual({ status: 'invalid', reason: 'replay' });
    expect(h.calls).toBe(1);
  });

  test('a fresh request receives a fresh nonce', async () => {
    const h = harness();
    const a = await h.request();
    const b = await h.request();
    expect(a.headers.get('signature-input')).not.toBe(b.headers.get('signature-input'));
    expect((await h.verifier.verify(a)).status).toBe('verified');
    expect((await h.verifier.verify(b)).status).toBe('verified');
  });

  for (const [name, url, method] of [
    ['path', SHOP + '/different?category=books', 'GET'],
    ['query', SHOP + '/agent/catalog?category=stationery', 'GET'],
    ['destination', 'https://other.example/agent/catalog?category=books', 'GET'],
    ['method', TARGET, 'HEAD'],
  ] as const) test(`rejects modified ${name} without reserving the nonce`, async () => {
    const h = harness();
    const original = await h.request();
    const changed = new Request(url!, { method, headers: original.headers });
    expect(await h.verifier.verify(changed)).toEqual({ status: 'invalid', reason: 'bad_signature' });
    expect(h.replay.entries.size).toBe(0);
    expect((await h.verifier.verify(original)).status).toBe('verified');
  });

  test('rejects altered content digest', async () => {
    const h = harness();
    const request = withHeaders(await h.request(), headers => headers.set('content-digest', 'sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:'));
    expect(await h.verifier.verify(request)).toEqual({ status: 'invalid', reason: 'digest_mismatch' });
    expect(h.replay.entries.size).toBe(0);
  });

  test('a signature created independently without the SDK verifies', async () => {
    const h = harness();
    const kid = publicJwk(createPrivateKey(h.initialKey.privateKeyPem)).kid;
    const nonce = Buffer.alloc(24, 17).toString('base64url');
    const input = `("@method" "@target-uri" "content-digest" "signature-agent";key="agent");created=${NOW / 1000};expires=${NOW / 1000 + 60};keyid="${kid}";alg="ed25519";nonce="${nonce}";tag="web-bot-auth"`;
    const base = `"@method": GET\n"@target-uri": ${TARGET}\n"content-digest": ${EMPTY_DIGEST}\n"signature-agent";key="agent": "${PROVIDER}"\n"@signature-params": ${input}`;
    const signature = sign(null, Buffer.from(base), createPrivateKey(h.initialKey.privateKeyPem));
    const request = new Request(TARGET, { headers: {
      'content-digest': EMPTY_DIGEST, 'signature-agent': `agent="${PROVIDER}"`,
      'signature-input': `agent=${input}`, signature: `agent=:${signature.toString('base64')}:`,
    } });
    expect((await h.verifier.verify(request)).status).toBe('verified');
  });

  test('SDK signature verifies against an independently assembled base', async () => {
    const h = harness();
    const request = await h.request();
    const input = request.headers.get('signature-input')!.slice('agent='.length);
    const base = `"@method": GET\n"@target-uri": ${TARGET}\n"content-digest": ${EMPTY_DIGEST}\n"signature-agent";key="agent": "${PROVIDER}"\n"@signature-params": ${input}`;
    const signature = Buffer.from(request.headers.get('signature')!.slice('agent=:'.length, -1), 'base64');
    const publicKey = await h.resolver.resolve(PROVIDER, h.signingKey.keyId);
    expect(verify(null, Buffer.from(base), publicKey!, signature)).toBe(true);
  });

  test('distinguishes unsigned requests from partial headers', async () => {
    const h = harness();
    expect(await h.verifier.verify(new Request(TARGET))).toEqual({ status: 'unsigned' });
    expect(await h.verifier.verify(new Request(TARGET, { headers: { 'signature-agent': `agent="${PROVIDER}"` } })))
      .toEqual({ status: 'invalid', reason: 'malformed_signature' });
  });

  test('unknown providers are rejected without network access', async () => {
    const h = harness();
    const request = withHeaders(await h.request(), headers => headers.set('signature-agent', 'agent="https://attacker.example"'));
    expect(await h.verifier.verify(request)).toEqual({ status: 'invalid', reason: 'untrusted_provider' });
    expect(h.calls).toBe(0);
  });

  test('rejects an unrelated key and algorithm downgrade', async () => {
    const h = harness();
    const wrongSigner = createRequestSigner({ providerOrigin: PROVIDER, signer: signerFromPrivateKey(generateProviderKey().privateKeyPem), allowedOrigins: [SHOP], clock: h.clock });
    expect(await h.verifier.verify(await wrongSigner.signRequest(new Request(TARGET)))).toEqual({ status: 'invalid', reason: 'unknown_key' });
    const modified = withHeaders(await h.request(), headers => headers.set('signature-input', headers.get('signature-input')!.replace('ed25519', 'hmac-sha256')));
    expect(await h.verifier.verify(modified)).toEqual({ status: 'invalid', reason: 'profile_mismatch' });
  });

  test('rejects a valid signature with inadequate request binding', async () => {
    const h = harness();
    const signed = await httpbis.signMessage({ name: 'agent', fields: ['@authority', '"signature-agent";key="agent"'],
      key: { id: h.signingKey.keyId, alg: 'ed25519', sign: data => h.signingKey.sign(data) },
      params: ['created', 'expires', 'keyid', 'alg', 'nonce', 'tag'], paramValues: {
        created: new Date(NOW), expires: new Date(NOW + 60_000), nonce: Buffer.alloc(24, 1).toString('base64url'), tag: 'web-bot-auth',
      },
    }, { method: 'GET', url: TARGET, headers: { 'content-digest': EMPTY_DIGEST, 'signature-agent': `agent="${PROVIDER}"` } });
    expect(await h.verifier.verify(new Request(TARGET, { headers: signed.headers }))).toEqual({ status: 'invalid', reason: 'profile_mismatch' });
  });

  test('rejects duplicate parameters, merged signatures, and mismatched labels', async () => {
    const h = harness();
    const original = await h.request();
    for (const mutate of [
      (headers: Headers) => headers.set('signature-input', headers.get('signature-input')! + ';alg="ed25519"'),
      (headers: Headers) => headers.append('signature', headers.get('signature')!),
      (headers: Headers) => headers.set('signature-agent', `other="${PROVIDER}"`),
    ]) expect((await h.verifier.verify(withHeaders(original, mutate))).status).toBe('invalid');
  });

  test('rejects expiry, future timestamps, excessive lifetimes, and missing nonce', async () => {
    const h = harness();
    const original = await h.request();
    h.setNow(NOW + 60_000);
    expect(await h.verifier.verify(original)).toEqual({ status: 'invalid', reason: 'expired' });
    h.setNow(NOW - 6_000);
    expect(await h.verifier.verify(original)).toEqual({ status: 'invalid', reason: 'invalid_time' });
    h.setNow(NOW);
    for (const mutate of [
      (input: InnerList) => input[1].set('expires', NOW / 1000 + 61),
      (input: InnerList) => input[1].set('created', 1.5),
      (input: InnerList) => input[1].delete('nonce'),
      (input: InnerList) => input[1].set('nonce', 'short'),
    ]) {
      const changed = withHeaders(original, headers => {
        const parsed = parseDictionary(headers.get('signature-input')!);
        mutate(parsed.get('agent') as InnerList);
        headers.set('signature-input', serializeDictionary(parsed));
      });
      expect((await h.verifier.verify(changed)).status).toBe('invalid');
    }
    expect(h.calls).toBe(0);
  });

  test('rejects credentials, bodies, HTTP, and forbidden destinations in the signer', async () => {
    const h = harness();
    for (const request of [new Request(TARGET, { headers: { cookie: 'session=secret' } }),
      new Request(TARGET, { headers: { authorization: 'Bearer secret' } }),
      new Request(TARGET, { method: 'POST', body: 'changed' }), new Request('http://shop.example/agent/catalog')]) {
      expect((await h.verifier.verify(request)).status).toBe('invalid');
      await expect(h.signer.signRequest(request)).rejects.toThrow();
    }
    await expect(h.signer.signRequest(new Request('https://other.example/'))).rejects.toThrow('Destination');
  });

  test('rejects requests whose headers exceed bounds after signing', async () => {
    const h = harness();
    await expect(h.signer.signRequest(new Request(TARGET, { headers: { 'x-padding': 'x'.repeat(16_000) } }))).rejects.toThrow();
  });

  test('dependency outages fail closed and do not reserve invalid signatures', async () => {
    const h = harness();
    const throwingStore: ReplayStore = { async reserve() { throw new Error('offline'); } };
    const verifier = new RequestVerifier({ resolver: h.resolver, replayStore: throwingStore, clock: h.clock });
    expect(await verifier.verify(await h.request())).toEqual({ status: 'unverifiable', reason: 'replay_store_unavailable' });
    const directoryFailure = new RequestVerifier({ resolver: { isTrusted: () => true, isDenied: () => false, async resolve() { throw new Error('offline'); } }, replayStore: h.replay, clock: h.clock });
    expect(await directoryFailure.verify(await h.request())).toEqual({ status: 'unverifiable', reason: 'directory_unavailable' });
    expect(h.replay.entries.size).toBe(0);
  });

  test('rechecks expiry and revocation after asynchronous dependencies', async () => {
    const h = harness();
    const request = await h.request();
    const verifier = new RequestVerifier({ resolver: h.resolver, clock: h.clock, replayStore: {
      async reserve() { h.setNow(NOW + 60_000); return true; },
    } });
    expect(await verifier.verify(request)).toEqual({ status: 'invalid', reason: 'expired' });
    h.setNow(NOW);
    const revoked = new RequestVerifier({ resolver: h.resolver, clock: h.clock, replayStore: {
      async reserve() { h.resolver.denyKey(PROVIDER, h.signingKey.keyId); return true; },
    } });
    expect(await revoked.verify(request)).toEqual({ status: 'invalid', reason: 'key_denied' });
  });

  test('private material is never published in the key directory', () => {
    const h = harness();
    expect(Object.keys(h.initialKey.publicKey)).not.toContain('d');
    expect(h.initialKey.publicKey.kid).toBe(createHash('sha256').update(JSON.stringify({
      crv: 'Ed25519', kty: 'OKP', x: h.initialKey.publicKey.x,
    })).digest('base64url'));
  });
});
