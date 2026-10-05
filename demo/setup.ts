import { chmod, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { generateProviderKey, keyDirectory } from '../src/index.js';

export async function setupDemo(directory = '.local'): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const names = ['provider-key.pem', 'directory.json', 'tls-key.pem', 'tls-cert.pem'];
  const present = await Promise.all(names.map(name => Bun.file(join(directory, name)).exists()));
  if (present.every(Boolean)) return;
  if (present.some(Boolean)) throw new Error('Incomplete demo keys. Use a new demo directory to avoid replacing existing keys.');
  const openssl = Bun.which('openssl');
  if (!openssl) throw new Error('Install openssl to generate the local HTTPS certificate');
  const result = Bun.spawnSync([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '7',
    '-keyout', join(directory, 'tls-key.pem'), '-out', join(directory, 'tls-cert.pem'),
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1']);
  if (result.exitCode !== 0) throw new Error('Failed to generate local HTTPS certificate');
  const key = generateProviderKey();
  await Bun.write(join(directory, 'provider-key.pem'), key.privateKeyPem);
  await Bun.write(join(directory, 'directory.json'), JSON.stringify(keyDirectory([key.publicKey]), null, 2) + '\n');
  await Promise.all(['provider-key.pem', 'tls-key.pem'].map(name => chmod(join(directory, name), 0o600)));
}

if (import.meta.main) {
  await setupDemo(process.env.DEMO_DIRECTORY ?? '.local');
  console.log('Local provider keys and HTTPS certificate are ready. Private keys stay in .local.');
}
