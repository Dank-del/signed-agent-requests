import { join } from 'node:path';
import { createRequestSigner, signerFromPrivateKey, type Fetcher } from '../src/index.js';

const directory = process.env.DEMO_DIRECTORY ?? '.local';
const cert = await Bun.file(join(directory, 'tls-cert.pem')).text();
const pem = await Bun.file(join(directory, 'provider-key.pem')).text();
const providerOrigin = `https://localhost:${process.env.PROVIDER_PORT ?? 9443}`;
const siteOrigin = `https://localhost:${process.env.SITE_PORT ?? 9444}`;
const transport: Fetcher = (request, init) => fetch(request, { ...init, tls: { ca: cert } });
const options = { providerOrigin, signer: signerFromPrivateKey(pem), allowedOrigins: [siteOrigin] };
const signer = createRequestSigner(options);
const target = siteOrigin + '/agent/catalog?category=books';

async function scenario(label: string, request: Request, expected: number) {
  const response = await transport(request);
  const body = await response.json();
  console.log(`${label}: ${response.status} ${response.status === expected ? 'PASS' : 'FAIL'}`);
  console.log(JSON.stringify(body, null, 2));
  if (response.status !== expected) process.exitCode = 1;
}

const signed = await signer.signRequest(new Request(target));
await scenario('Accepted provider', signed.clone(), 200);
await scenario('Replay of the same request', signed.clone(), 409);
const tampered = await signer.signRequest(new Request(target));
await scenario('Changed query', new Request(siteOrigin + '/agent/catalog?category=stationery', { headers: tampered.headers }), 401);
await scenario('Original after failed tampering', tampered, 200);
const expiredSigner = createRequestSigner({ ...options, clock: () => Date.now() - 61_000 });
await scenario('Expired signature', await expiredSigner.signRequest(new Request(target)), 401);
await scenario('Unsigned request', new Request(target), 401);
