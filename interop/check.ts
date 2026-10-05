import assert from 'node:assert/strict';
import { createPrivateKey } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import fixture from '../fixtures/signing-v1.json' with { type: 'json' };
import { DIRECTORY_CONTENT_TYPE, KeyDirectoryResolver, RequestVerifier } from '../src/index.js';
import { TestReplayStore } from '../test/helpers.js';
import { startLocalRedis } from '../demo/redis-process.js';
import { startDemo } from '../demo/runtime.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const temporary = await mkdtemp(join(tmpdir(), 'sar-interop-'));
let redis: Awaited<ReturnType<typeof startLocalRedis>> | undefined;
let demo: Awaited<ReturnType<typeof startDemo>> | undefined;
let assertions = 0;

async function run(command: string[], cwd: string, input?: object): Promise<string> {
  const process = Bun.spawn(command, { cwd, stdout: 'pipe', stderr: 'pipe',
    stdin: input ? new Blob([JSON.stringify(input)]) : 'ignore',
  });
  const timeout = setTimeout(() => { process.kill(); }, 60_000);
  try {
    const [code, stdout, stderr] = await Promise.all([
      process.exited, new Response(process.stdout).text(), new Response(process.stderr).text(),
    ]);
    if (code !== 0) throw new Error(`${command[0]} failed (${code}): ${stderr}`);
    return stdout;
  } finally { clearTimeout(timeout); }
}

interface SignedOutput { method: string; url: string; headers: Record<string, string>; status?: number; body?: string }
function request(output: SignedOutput) { return new Request(output.url, { method: output.method, headers: output.headers }); }
function equal(actual: unknown, expected: unknown, message: string) { assert.deepEqual(actual, expected, message); assertions++; }

try {
  // Exercise the built TypeScript SDK as a separate application's dependency.
  await run(['bun', 'run', 'build'], root);
  const archive = join(temporary, 'sar-typescript.tgz');
  await run(['bun', 'pm', 'pack', '--filename', archive, '--ignore-scripts', '--quiet'], root);
  const consumer = join(temporary, 'typescript-consumer');
  await Bun.write(join(consumer, 'package.json'), JSON.stringify({
    name: 'sar-consumer-check', private: true, type: 'module',
    dependencies: { 'signed-agent-requests': `file:${archive}` },
    devDependencies: { '@types/bun': '1.4.0', '@types/node': '22.20.5', typescript: '5.9.3' },
    scripts: { typecheck: 'tsc --noEmit -p tsconfig.json' },
  }));
  await Bun.write(join(consumer, 'tsconfig.json'), JSON.stringify({
    compilerOptions: { target: 'ES2023', module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, skipLibCheck: true },
    include: ['consumer.ts'],
  }));
  await Bun.write(join(consumer, 'consumer.ts'), `
import assert from 'node:assert/strict';
import { createRequestSigner, generateProviderKey, signerFromPrivateKey, keyDirectory,
  KeyDirectoryResolver, RequestVerifier, DIRECTORY_CONTENT_TYPE } from 'signed-agent-requests';
const key = generateProviderKey();
const provider = 'https://provider.example';
const signer = createRequestSigner({ providerOrigin: provider, signer: signerFromPrivateKey(key.privateKeyPem), allowedOrigins: ['https://shop.example'] });
const signed = await signer.signRequest(new Request('https://shop.example/agent/catalog'));
assert.equal(signed.redirect, 'manual');
const resolver = new KeyDirectoryResolver({ providers: [provider], fetch: async () => Response.json(keyDirectory([key.publicKey]), { headers: { 'content-type': DIRECTORY_CONTENT_TYPE } }) });
const entries = new Set<string>();
const verifier = new RequestVerifier({ resolver, replayStore: { async reserve(key) { if (entries.has(key)) return false; entries.add(key); return true; } } });
assert.equal((await verifier.verify(signed)).status, 'verified');
assert.deepEqual(await verifier.verify(signed), { status: 'invalid', reason: 'replay' });
const response = await signer.signedFetch('https://shop.example/agent/catalog', {}, async request => {
  assert.equal((await verifier.verify(request as Request)).status, 'verified');
  return new Response(null, { status: 204 });
});
assert.equal(response.status, 204);
console.log(JSON.stringify({ verified: true }));
`);
  await run(['bun', 'install', '--ignore-scripts'], consumer);
  await run(['bun', 'run', 'typecheck'], consumer);
  equal(JSON.parse(await run(['bun', 'consumer.ts'], consumer)), { verified: true }, 'TypeScript: installed SDK signing and verification');
  equal((await Bun.file(join(consumer, 'node_modules/signed-agent-requests/package.json')).json()).version, '0.0.1', 'TypeScript: package version');
  equal(await Bun.file(join(consumer, 'node_modules/signed-agent-requests/.local/provider-key.pem')).exists(), false, 'TypeScript: exclude local private keys from package');
  console.log('PASS TypeScript: installed package, declarations, signing, verification, replay');
  for (const copy of ['sdks/go/testdata/signing-v1.json', 'sdks/python/tests/fixtures/signing-v1.json']) {
    equal(await Bun.file(join(root, copy)).json(), fixture, `${copy}: shared fixture consistency`);
  }
  const binary = join(temporary, 'sar-go-client');
  await run(['go', 'build', '-o', binary, './internal/interop'], join(root, 'sdks/go'));
  const clients = [
    { name: 'Go', command: [binary], cwd: root },
    { name: 'Python', command: ['uv', 'run', '--frozen', 'python', 'tests/interop_client.py'], cwd: join(root, 'sdks/python') },
  ];
  const testKey = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(fixture.privateKeySeedHex, 'hex'),
  ]) });
  const keyPath = join(temporary, 'public-test-key.pem');
  await writeFile(keyPath, testKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  const clock = () => fixture.cases[0]!.created * 1000;
  const resolver = new KeyDirectoryResolver({ providers: [fixture.providerOrigin], clock,
    fetch: async () => Response.json({ keys: [fixture.publicKey] }, { headers: { 'content-type': DIRECTORY_CONTENT_TYPE } }),
  });
  const verifier = new RequestVerifier({ resolver, replayStore: new TestReplayStore(clock), clock });
  for (const client of clients) {
    for (const vector of [...fixture.cases, { name: 'root-path', method: 'GET', targetUri: 'https://shop.example' }]) {
      const output = JSON.parse(await run(client.command, client.cwd, {
        keyPath, providerOrigin: fixture.providerOrigin, targetUri: vector.targetUri,
        method: vector.method, clockSeconds: fixture.cases[0]!.created,
      })) as SignedOutput;
      const signed = request(output);
      const changed = new URL(signed.url);
      changed.searchParams.set('tampered', 'true');
      equal(await verifier.verify(new Request(changed, { method: signed.method, headers: signed.headers })),
        { status: 'invalid', reason: 'bad_signature' }, `${client.name}: reject modified URI`);
      equal((await verifier.verify(signed)).status, 'verified', `${client.name}: verify ${vector.name}`);
      equal(await verifier.verify(signed), { status: 'invalid', reason: 'replay' }, `${client.name}: reject replay`);
      console.log(`PASS ${client.name}: ${vector.name}, tampering, replay`);
    }
  }
  redis = process.env.TEST_REDIS_URL ? undefined : await startLocalRedis();
  demo = await startDemo({ directory: join(temporary, 'https'), redisUrl: process.env.TEST_REDIS_URL ?? redis!.url,
    providerPort: 0, sitePort: 0, prefix: `interop:${crypto.randomUUID()}`, requestsPerMinute: 1000 });
  for (const client of clients) {
    const input = { keyPath: join(temporary, 'https/provider-key.pem'), caPath: join(temporary, 'https/tls-cert.pem'),
      providerOrigin: demo.providerOrigin, targetUri: demo.siteOrigin + '/agent/catalog?category=books', send: true };
    const get = JSON.parse(await run(client.command, client.cwd, { ...input, method: 'GET' })) as SignedOutput;
    equal(get.status, 200, `${client.name}: HTTPS GET`);
    equal(JSON.parse(get.body!).provider, demo.providerOrigin, `${client.name}: correct provider`);
    equal(JSON.parse(get.body!).products.length, 2, `${client.name}: correct query`);
    equal((await demo.transport(request(get))).status, 409, `${client.name}: HTTPS replay`);
    const changed = new URL(get.url);
    changed.searchParams.set('tampered', 'true');
    equal((await demo.transport(new Request(changed, { headers: get.headers }))).status, 401, `${client.name}: HTTPS tamper`);
    const head = JSON.parse(await run(client.command, client.cwd, { ...input, method: 'HEAD' })) as SignedOutput;
    equal(head.status, 200, `${client.name}: HTTPS HEAD`);
    equal(head.body, '', `${client.name}: empty HEAD response`);
    const expired = JSON.parse(await run(client.command, client.cwd, {
      ...input, method: 'GET', clockSeconds: Math.floor(Date.now() / 1000) - 61,
    })) as SignedOutput;
    equal(expired.status, 401, `${client.name}: expired signature`);
    console.log(`PASS ${client.name}: real HTTPS GET/HEAD, replay, tampering, expiry`);
  }
  console.log(`${assertions} cross-language assertions passed.`);
} finally {
  await demo?.stop();
  await redis?.stop();
  await rm(temporary, { recursive: true, force: true });
}
