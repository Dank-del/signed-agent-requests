import { join } from 'node:path';
import { RedisClient } from 'bun';
import {
  createAgentHandler, createProviderPolicy, DIRECTORY_CONTENT_TYPE, DIRECTORY_PATH,
  KeyDirectoryResolver, RedisRateLimiter, RedisReplayStore, RequestVerifier,
  type AgentEvent, type Fetcher,
} from '../src/index.js';
import { setupDemo } from './setup.js';

const catalog = [
  { id: 'book-001', name: 'Practical cryptography', category: 'books', price: 24, currency: 'USD' },
  { id: 'book-002', name: 'Building reliable systems', category: 'books', price: 32, currency: 'USD' },
  { id: 'desk-001', name: 'Notebook', category: 'stationery', price: 6, currency: 'USD' },
];

export interface DemoOptions {
  directory?: string;
  redisUrl: string;
  providerPort?: number;
  sitePort?: number;
  requestsPerMinute?: number;
  prefix?: string;
  onEvent?: (event: AgentEvent) => void;
}

export async function startDemo(options: DemoOptions) {
  const directory = options.directory ?? '.local';
  await setupDemo(directory);
  const cert = await Bun.file(join(directory, 'tls-cert.pem')).text();
  const key = await Bun.file(join(directory, 'tls-key.pem')).text();
  const directoryText = await Bun.file(join(directory, 'directory.json')).text();
  const transport: Fetcher = (input, init) => fetch(input, { ...init, tls: { ca: cert } });
  const redis = new RedisClient(options.redisUrl, {
    enableOfflineQueue: false, autoReconnect: true, maxRetries: 3, connectionTimeout: 1000,
  });
  let provider: ReturnType<typeof Bun.serve> | undefined;
  let site: ReturnType<typeof Bun.serve> | undefined;
  try {
    await redis.connect();
    provider = Bun.serve({
      hostname: '127.0.0.1', port: options.providerPort ?? 9443, tls: { cert, key }, maxRequestBodySize: 1024,
      fetch(request) {
        const path = new URL(request.url).pathname;
        if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method not allowed', { status: 405 });
        if (path !== DIRECTORY_PATH) return new Response('Not found', { status: 404 });
        return new Response(request.method === 'HEAD' ? null : directoryText, {
          headers: { 'content-type': DIRECTORY_CONTENT_TYPE, 'cache-control': 'public, max-age=60' },
        });
      },
    });
    const providerOrigin = `https://localhost:${provider.port}`;
    const resolver = new KeyDirectoryResolver({ providers: [providerOrigin], fetch: transport });
    const storeOptions = { prefix: options.prefix ?? 'signed-agent:demo' };
    const verifier = new RequestVerifier({ resolver, replayStore: new RedisReplayStore(redis, storeOptions) });
    const policy = createProviderPolicy({ rules: [{ origin: providerOrigin, action: 'allow', requestsPerMinute: options.requestsPerMinute ?? 60 }],
      rateLimiter: new RedisRateLimiter(redis, storeOptions) });
    let agentHandler: (request: Request) => Promise<Response> = async () => new Response('Starting', { status: 503 });
    site = Bun.serve({
      hostname: '127.0.0.1', port: options.sitePort ?? 9444, tls: { cert, key }, maxRequestBodySize: 1024,
      fetch(request) {
        const path = new URL(request.url).pathname;
        if (path === '/agent/catalog') return agentHandler(request);
        if (path === '/health') return Response.json({ ready: redis.connected }, { status: redis.connected ? 200 : 503 });
        if (path === '/' && request.method === 'GET') return new Response(homepage, {
          headers: { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'", 'cache-control': 'no-store' },
        });
        return new Response('Not found', { status: 404 });
      },
    });
    const siteOrigin = `https://localhost:${site.port}`;
    agentHandler = createAgentHandler({ externalOrigin: siteOrigin, verifier, policy,
      ...(options.onEvent ? { onEvent: options.onEvent } : {}),
      handle(request, identity) {
        const category = new URL(request.url).searchParams.get('category');
        const data = { provider: identity.providerOrigin, products: catalog.filter(item => !category || item.category === category) };
        return new Response(request.method === 'HEAD' ? null : JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
      },
    });
    await resolver.preload();
    const refresh = setInterval(() => { void resolver.refreshAll().catch(() => {}); }, 30_000);
    return { providerOrigin, siteOrigin, resolver, verifier, transport,
      async stop() { clearInterval(refresh); await Promise.all([provider!.stop(true), site!.stop(true)]); redis.close(); },
    };
  } catch (error) { await Promise.all([provider?.stop(true), site?.stop(true)]); redis.close(); throw error; }
}

const homepage = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SAR — Signed Agent Requests</title><style>body{font:17px/1.6 system-ui;max-width:780px;margin:72px auto;padding:0 24px;color:#14212b;background:#fafbfc}h1{font-size:38px;line-height:1.15}code,pre{font-family:ui-monospace,monospace;background:#edf1f4;border-radius:5px}code{padding:2px 5px}pre{padding:20px;overflow:auto}small{color:#64717d}</style>
<small>SAR · Local HTTPS pilot</small><h1>Requests with a verifiable provider identity</h1>
<p>The provider signs each request. This website verifies its public key, signature, timestamps, and unique nonce before applying an access policy.</p>
<h2>Try the flow</h2><pre>bun run demo:request</pre><p>The client demonstrates accepted requests, tampering, expiry, replay, and unsigned traffic.</p>
<p><code>GET /agent/catalog?category=books</code> returns structured catalog data to the approved provider. Unsigned requests receive <code>401</code>. A repeated signed request receives <code>409</code>.</p>
<p>Provider signatures identify an endorsed signing key. Website permissions and user authorization remain separate decisions.</p></html>`;
