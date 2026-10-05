import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { RedisClient } from 'bun';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  createRequestSigner, KeyDirectoryResolver, RedisRateLimiter, RedisReplayStore, RequestVerifier, signerFromPrivateKey,
} from '../src/index.js';
import { startLocalRedis } from '../demo/redis-process.js';
import { startDemo } from '../demo/runtime.js';
import { harness, PROVIDER, SHOP } from './helpers.js';

let localRedis: Awaited<ReturnType<typeof startLocalRedis>> | undefined;
let clientA: RedisClient;
let clientB: RedisClient;
let demo: Awaited<ReturnType<typeof startDemo>>;
let directory: string;
let redisUrl: string;

beforeAll(async () => {
  localRedis = process.env.TEST_REDIS_URL ? undefined : await startLocalRedis();
  redisUrl = process.env.TEST_REDIS_URL ?? localRedis!.url;
  clientA = new RedisClient(redisUrl, { enableOfflineQueue: false, autoReconnect: false });
  clientB = new RedisClient(redisUrl, { enableOfflineQueue: false, autoReconnect: false });
  await Promise.all([clientA.connect(), clientB.connect()]);
  directory = await mkdtemp(join(tmpdir(), 'signed-agent-demo-'));
  demo = await startDemo({ directory, redisUrl, providerPort: 0, sitePort: 0, prefix: `integration:${randomUUID()}`, requestsPerMinute: 1000 });
}, 15_000);

afterAll(async () => {
  await demo?.stop();
  clientA?.close();
  clientB?.close();
  await localRedis?.stop();
  if (directory) await rm(directory, { recursive: true, force: true });
});

describe('real Redis and HTTPS', () => {
  test('failed startup releases an already opened provider listener', async () => {
    const probe = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: () => new Response('probe') });
    const providerPort = probe.port!;
    await probe.stop(true);
    await expect(startDemo({
      directory, redisUrl, providerPort, sitePort: Number(new URL(demo.siteOrigin).port),
      prefix: `startup:${randomUUID()}`,
    })).rejects.toThrow();
    const replacement = Bun.serve({ hostname: '127.0.0.1', port: providerPort, fetch: () => new Response('released') });
    try { expect(replacement.port).toBe(providerPort); } finally { await replacement.stop(true); }
  });

  test('only one of two independent verifiers can accept the same request concurrently', async () => {
    const h = harness();
    const now = Date.now();
    h.setNow(now);
    const prefix = `race:${randomUUID()}`;
    const verifierA = new RequestVerifier({ resolver: h.resolver, replayStore: new RedisReplayStore(clientA, { prefix }) });
    const resolverB = new KeyDirectoryResolver({ providers: [PROVIDER], fetch: h.transport });
    const verifierB = new RequestVerifier({ resolver: resolverB, replayStore: new RedisReplayStore(clientB, { prefix }) });
    const request = await h.request();
    const results = await Promise.all([verifierA.verify(request), verifierB.verify(request)]);
    expect(results.filter(result => result.status === 'verified').length).toBe(1);
    expect(results.filter(result => result.status === 'invalid' && result.reason === 'replay').length).toBe(1);
  });

  test('rate limits are shared and atomic across two clients', async () => {
    const prefix = `rate:${randomUUID()}`;
    const limitA = new RedisRateLimiter(clientA, { prefix });
    const limitB = new RedisRateLimiter(clientB, { prefix });
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? limitA : limitB).consume(PROVIDER, 5, 60)));
    expect(results.filter(result => result.allowed).length).toBe(5);
    expect(results.every(result => result.remaining >= 0)).toBe(true);
    expect(new Set(results.map(result => result.resetAt)).size).toBe(1);
  });

  test('replay reservations have a bounded TTL and disconnected stores fail closed', async () => {
    const prefix = `ttl:${randomUUID()}`;
    const store = new RedisReplayStore(clientA, { prefix });
    const key = 'a'.repeat(64);
    expect(await store.reserve(key, Date.now() + 2000)).toBe(true);
    const ttl = await clientB.send('PTTL', [`${prefix}:nonce:${key}`]);
    expect(typeof ttl).toBe('number');
    expect(ttl as number).toBeGreaterThan(0);
    expect(ttl as number).toBeLessThanOrEqual(2000);
    const disconnected = new RedisClient('redis://127.0.0.1:1', { enableOfflineQueue: false, autoReconnect: false });
    await expect(new RedisReplayStore(disconnected).reserve(key, Date.now() + 2000)).rejects.toThrow();
    disconnected.close();
  });

  test('a real HTTPS request verifies against the real provider directory and replay is rejected', async () => {
    const pem = await Bun.file(join(directory, 'provider-key.pem')).text();
    const signer = createRequestSigner({ providerOrigin: demo.providerOrigin, signer: signerFromPrivateKey(pem), allowedOrigins: [demo.siteOrigin] });
    const request = await signer.signRequest(new Request(demo.siteOrigin + '/agent/catalog?category=books'));
    const response = await demo.transport(request.clone());
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json() as { provider: string; products: { category: string }[] };
    expect(body.provider).toBe(demo.providerOrigin);
    expect(body.products.length).toBe(2);
    expect(body.products.every(product => product.category === 'books')).toBe(true);
    expect((await demo.transport(request.clone())).status).toBe(409);
    expect((await demo.transport(new Request(demo.siteOrigin + '/agent/catalog'))).status).toBe(401);
  });

  test('signed fetch does not follow redirects with a reusable signature', async () => {
    const h = harness();
    let request: Request | undefined;
    const response = await h.signer.signedFetch(SHOP + '/redirect', {}, async input => {
      request = input as Request;
      return new Response(null, { status: 302, headers: { location: 'https://other.example' } });
    });
    expect(response.status).toBe(302);
    expect(request?.redirect).toBe('manual');
    expect(request?.headers.has('cookie')).toBe(false);
    expect(request?.headers.has('authorization')).toBe(false);
  });
});
