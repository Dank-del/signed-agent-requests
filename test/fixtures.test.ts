import { expect, test } from 'bun:test';
import { createPublicKey, verify } from 'node:crypto';
import fixture from '../fixtures/signing-v1.json' with { type: 'json' };
import { DIRECTORY_CONTENT_TYPE, KeyDirectoryResolver, RequestVerifier, signatureBase, parseSignature } from '../src/index.js';
import { TestReplayStore } from './helpers.js';

for (const vector of fixture.cases) {
  test(`shared language fixture verifies: ${vector.name}`, async () => {
    const clock = () => vector.created * 1000;
    const resolver = new KeyDirectoryResolver({ providers: [fixture.providerOrigin], clock,
      fetch: async () => Response.json({ keys: [fixture.publicKey] }, { headers: { 'content-type': DIRECTORY_CONTENT_TYPE } }),
    });
    const request = new Request(vector.targetUri, { method: vector.method, headers: vector.headers });
    const parsed = parseSignature(request);
    expect(signatureBase(request, parsed.input).toString()).toBe(vector.signatureBase);
    expect(verify(null, Buffer.from(vector.signatureBase), createPublicKey({ key: fixture.publicKey, format: 'jwk' }), parsed.signature)).toBe(true);
    const verifier = new RequestVerifier({ resolver, replayStore: new TestReplayStore(clock), clock });
    expect((await verifier.verify(request)).status).toBe('verified');
    expect(await verifier.verify(request)).toEqual({ status: 'invalid', reason: 'replay' });
  });
}
