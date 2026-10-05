import { describe, expect, test } from 'bun:test';
import { createAgentHandler, createProviderPolicy, type AgentEvent } from '../src/index.js';
import { harness, PROVIDER, SHOP, TARGET, withHeaders } from './helpers.js';

describe('website policy and middleware', () => {
  test('a verified provider can be allowed, denied, or rate limited', async () => {
    const h = harness();
    const verified = await h.verifier.verify(await h.request());
    if (verified.status !== 'verified') throw new Error('Expected verified identity');
    const allow = createProviderPolicy({ rules: [{ origin: PROVIDER, action: 'allow', requestsPerMinute: 1 }], clock: h.clock,
      rateLimiter: { async consume() { return { allowed: true, remaining: 0, resetAt: h.clock() / 1000 + 60 }; } },
    });
    expect(await allow(verified.identity)).toEqual({ action: 'allow', remaining: 0 });
    const deny = createProviderPolicy({ rules: [{ origin: PROVIDER, action: 'deny' }], rateLimiter: { async consume() { throw new Error('must not run'); } } });
    expect(await deny(verified.identity)).toEqual({ action: 'deny' });
    const limited = createProviderPolicy({ rules: [{ origin: PROVIDER, action: 'allow', requestsPerMinute: 1 }], clock: h.clock,
      rateLimiter: { async consume() { return { allowed: false, remaining: 0, resetAt: h.clock() / 1000 + 60 }; } },
    });
    expect(await limited(verified.identity)).toEqual({ action: 'rate_limit', retryAfterSeconds: 60 });
  });

  test('only verified traffic reaches the application and injected identity headers are stripped', async () => {
    const h = harness();
    const events: AgentEvent[] = [];
    let called = 0;
    const handler = createAgentHandler({ externalOrigin: SHOP, verifier: h.verifier, policy: async () => ({ action: 'allow' }),
      onEvent: event => events.push(event), handle(request, identity) {
        called++;
        expect(request.headers.has('x-verified-provider')).toBe(false);
        return Response.json({ provider: identity.providerOrigin }, { headers: { 'cache-control': 'public, max-age=60' } });
      },
    });
    expect((await handler(new Request(TARGET))).status).toBe(401);
    const request = withHeaders(await h.request(), headers => headers.set('x-verified-provider', 'attacker'));
    const response = await handler(request);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toEqual({ provider: PROVIDER });
    expect(called).toBe(1);
    expect(events.map(event => event.verification.status)).toEqual(['unsigned', 'verified']);
    expect((await handler(request)).status).toBe(409);
    expect(called).toBe(1);
  });

  test('policy failures and explicit policy decisions map to clear HTTP responses', async () => {
    const h = harness();
    for (const [action, expected] of [['deny', 403], ['unavailable', 503], ['rate_limit', 429]] as const) {
      const handler = createAgentHandler({ externalOrigin: SHOP, verifier: h.verifier,
        policy: async () => action === 'rate_limit' ? { action, retryAfterSeconds: 12 } : { action },
        handle: () => { throw new Error('must not run'); },
      });
      const response = await handler(await h.request());
      expect(response.status).toBe(expected);
      if (action === 'rate_limit') expect(response.headers.get('retry-after')).toBe('12');
    }
    const failing = createAgentHandler({ externalOrigin: SHOP, verifier: h.verifier,
      policy: async () => { throw new Error('offline'); }, handle: () => { throw new Error('must not run'); },
    });
    expect((await failing(await h.request())).status).toBe(503);
  });

  test('telemetry errors cannot change the access decision and forwarded origins are ignored', async () => {
    const h = harness();
    const handler = createAgentHandler({ externalOrigin: SHOP, verifier: h.verifier,
      policy: async () => ({ action: 'allow' }), handle: () => new Response('ok'),
      onEvent: () => { throw new Error('telemetry offline'); },
    });
    const request = withHeaders(await h.request(), headers => headers.set('x-forwarded-host', 'attacker.example'));
    expect((await handler(request)).status).toBe(200);
    const wrong = new Request('https://attacker.example/agent/catalog', { headers: request.headers });
    expect((await handler(wrong)).status).toBe(400);
  });
});
