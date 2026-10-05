import { expect, test } from 'bun:test';
import { createPublicKey, verify } from 'node:crypto';
import { httpbis } from 'http-message-signatures';

// Published RFC 9421 Appendix B.1.4 and B.2.6. Public test key only.
// https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.2.6
test('matches the independently published RFC 9421 Ed25519 vector', () => {
  const base = httpbis.createSignatureBase({ fields: ['date', '@method', '@path', '@authority', 'content-type', 'content-length'] }, {
    method: 'POST', url: 'https://example.com/foo?param=Value&Pet=dog',
    headers: { date: 'Tue, 20 Apr 2021 02:07:55 GMT', 'content-type': 'application/json', 'content-length': '18' },
  });
  base.push(['"@signature-params"', ['("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"']]);
  const expected = '"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@method": POST\n"@path": /foo\n"@authority": example.com\n"content-type": application/json\n"content-length": 18\n"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"';
  expect(httpbis.formatSignatureBase(base)).toBe(expected);
  const publicKey = createPublicKey('-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=\n-----END PUBLIC KEY-----');
  const signature = Buffer.from('wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==', 'base64');
  expect(verify(null, Buffer.from(expected), publicKey, signature)).toBe(true);
});
