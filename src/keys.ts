import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

export interface PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid: string;
  alg: 'ed25519';
  use: 'sig';
  key_ops: ['verify'];
  nbf?: number;
  exp?: number;
}

export interface ProviderSigner {
  readonly keyId: string;
  sign(data: Buffer): Promise<Buffer>;
}

export function jwkThumbprint(jwk: { crv: string; kty: string; x: string }): string {
  return createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest('base64url');
}

export function publicJwk(key: KeyObject): PublicJwk {
  const publicKey = key.type === 'private' ? createPublicKey(key) : key;
  if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('An Ed25519 public or private key is required');
  }
  const jwk = publicKey.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') throw new Error('Missing Ed25519 key material');
  const fields = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: jwk.x };
  return { ...fields, kid: jwkThumbprint(fields), alg: 'ed25519', use: 'sig', key_ops: ['verify'] };
}

export function signerFromPrivateKey(pem: string | Buffer | KeyObject): ProviderSigner {
  const key = typeof pem === 'string' || Buffer.isBuffer(pem) ? createPrivateKey(pem) : pem;
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') throw new Error('An Ed25519 private key is required');
  return { keyId: publicJwk(key).kid, async sign(data) { return sign(null, data, key); } };
}

export function generateProviderKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicKey: publicJwk(publicKey),
  };
}

export function keyDirectory(keys: readonly PublicJwk[]) {
  if (keys.length < 1 || keys.length > 16 || new Set(keys.map(key => key.kid)).size !== keys.length) {
    throw new Error('A directory requires 1 to 16 unique keys');
  }
  // Construct public-only fields even if a caller supplies an object with extra properties.
  return { keys: keys.map(({ kty, crv, x, kid, alg, use, key_ops, nbf, exp }) => ({
    kty, crv, x, kid, alg, use, key_ops,
    ...(nbf === undefined ? {} : { nbf }), ...(exp === undefined ? {} : { exp }),
  })) };
}
