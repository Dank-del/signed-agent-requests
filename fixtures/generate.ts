// Creates deterministic public conformance data using Node crypto, independently
// of SAR's signing SDK. The RFC 8032 test seed is public and unsafe for real use.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';

const seedHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const key = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex'),
]) });
const publicKey = createPublicKey(key).export({ format: 'jwk' });
const keyId = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: publicKey.x })).digest('base64url');
const providerOrigin = 'https://provider.example';
const digest = 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:';
const targets = [
  { name: 'catalog-get', method: 'GET', targetUri: 'https://shop.example/agent/catalog?category=books' },
  { name: 'encoded-head', method: 'HEAD', targetUri: 'https://shop.example/catalog%2Fbooks?z=%2F&a=two+words&a=%E2%9C%93' },
  { name: 'empty-query', method: 'GET', targetUri: 'https://shop.example/?' },
];
const cases = targets.map((target, index) => {
  const created = 1_791_244_800;
  const expires = created + 60;
  const nonce = Buffer.alloc(24, index + 1).toString('base64url');
  const params = `("@method" "@target-uri" "content-digest" "signature-agent";key="agent");created=${created};expires=${expires};keyid="${keyId}";alg="ed25519";nonce="${nonce}";tag="web-bot-auth"`;
  const signatureBase = `"@method": ${target.method}\n"@target-uri": ${target.targetUri}\n"content-digest": ${digest}\n"signature-agent";key="agent": "${providerOrigin}"\n"@signature-params": ${params}`;
  return { ...target, created, expires, nonce, signatureBase, headers: {
    'content-digest': digest, 'signature-agent': `agent="${providerOrigin}"`, 'signature-input': `agent=${params}`,
    signature: `agent=:${sign(null, Buffer.from(signatureBase), key).toString('base64')}:`,
  } };
});
const data = JSON.stringify({
  purpose: 'Public conformance fixture only. Never use this signing seed for a real provider.',
  seedSource: 'RFC 8032 section 7.1, TEST 1',
  profile: 'signed-agent-requests/0.1', providerOrigin, privateKeySeedHex: seedHex, keyId,
  publicKey: { ...publicKey, kid: keyId, alg: 'ed25519', use: 'sig', key_ops: ['verify'] }, cases,
}, null, 2) + '\n';
// Copies make native module tests usable outside the monorepo checkout.
for (const destination of ['./signing-v1.json', '../sdks/go/testdata/signing-v1.json', '../sdks/python/tests/fixtures/signing-v1.json']) {
  await Bun.write(new URL(destination, import.meta.url), data);
}
