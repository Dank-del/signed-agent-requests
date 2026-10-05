import { createHash, timingSafeEqual } from 'node:crypto';
import { httpbis } from 'http-message-signatures';
import {
  isInnerList, parseDictionary, serializeDictionary, serializeInnerList, serializeItem, Token,
  type InnerList,
} from 'structured-headers';
import { ProfileError } from './types.js';

export const PROFILE = 'signed-agent-requests/0.1';
export const PROTOCOL_DRAFT = 'draft-ietf-webbotauth-httpsig-protocol-00';
export const DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
export const DIRECTORY_CONTENT_TYPE = 'application/http-message-signatures-directory+json';
export const MAX_LIFETIME_SECONDS = 60;
export const CLOCK_SKEW_SECONDS = 5;
export const REPLAY_RETENTION_MARGIN_MS = 10_000;
export const EMPTY_DIGEST = `sha-256=:${createHash('sha256').update('').digest('base64')}:`;

export function requireOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value || url.username || url.password) {
    throw new Error('Provider and destination origins must be canonical HTTPS origins');
  }
  return url.origin;
}

export function checkPublicRequest(request: Request): void {
  const url = new URL(request.url);
  if (url.protocol !== 'https:' || url.hash || url.username || url.password
    || !['GET', 'HEAD'].includes(request.method) || request.body !== null
    || request.headers.has('authorization') || request.headers.has('cookie')
    || request.headers.has('content-encoding') || request.headers.has('transfer-encoding')
    || (request.headers.has('content-length') && request.headers.get('content-length') !== '0')
    || (request.headers.has('host') && request.headers.get('host') !== url.host)) {
    throw new ProfileError('unsupported_request');
  }
  let size = 0;
  request.headers.forEach((value, name) => { size += Buffer.byteLength(name + value); });
  if (size > 16_384 || request.url.length > 8_192) throw new ProfileError('unsupported_request');
}

export function requiredFields(label: string): string[] {
  return ['"@method"', '"@target-uri"', '"content-digest"', `"signature-agent";key="${label}"`];
}

function dictionary(request: Request, name: string) {
  const value = request.headers.get(name);
  if (!value || value.length > 4_096) throw new ProfileError('malformed_signature');
  const parsed = parseDictionary(value);
  // This pilot deliberately requires canonical single-signature serialization.
  // It rejects duplicate dictionary members/parameters and merged header ambiguity.
  if (parsed.size !== 1 || serializeDictionary(parsed) !== value) {
    throw new ProfileError('malformed_signature');
  }
  return parsed;
}

export interface ParsedSignature {
  label: string;
  input: InnerList;
  providerOrigin: string;
  keyId: string;
  nonce: string;
  created: number;
  expires: number;
  signature: Buffer;
}

export function parseSignature(request: Request): ParsedSignature {
  try {
    const inputs = dictionary(request, 'signature-input');
    const signatures = dictionary(request, 'signature');
    const agents = dictionary(request, 'signature-agent');
    const [label, input] = [...inputs][0]!;
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(label) || !isInnerList(input)) {
      throw new ProfileError('malformed_signature');
    }
    const signature = signatures.get(label);
    const agent = agents.get(label);
    if (!signature || isInnerList(signature) || !(signature[0] instanceof ArrayBuffer)
      || signature[0].byteLength !== 64 || signature[1].size !== 0
      || !agent || isInnerList(agent) || typeof agent[0] !== 'string') {
      throw new ProfileError('malformed_signature');
    }
    if (agent[1].size > 1 || (agent[1].size === 1
      && (!(agent[1].get('type') instanceof Token) || String(agent[1].get('type')) !== 'directory'))) {
      throw new ProfileError('profile_mismatch');
    }
    const fields = input[0].map(field => serializeItem(field));
    const required = requiredFields(label);
    if (fields.length !== required.length || new Set(fields).size !== required.length
      || !required.every(field => fields.includes(field))) throw new ProfileError('profile_mismatch');

    const params = input[1];
    const names = ['created', 'expires', 'keyid', 'alg', 'nonce', 'tag'];
    if (params.size !== names.length || !names.every(name => params.has(name))
      || params.get('alg') !== 'ed25519' || params.get('tag') !== 'web-bot-auth') {
      throw new ProfileError('profile_mismatch');
    }
    const created = params.get('created');
    const expires = params.get('expires');
    const keyId = params.get('keyid');
    const nonce = params.get('nonce');
    if (typeof created !== 'number' || !Number.isSafeInteger(created)
      || typeof expires !== 'number' || !Number.isSafeInteger(expires)) {
      throw new ProfileError('invalid_time');
    }
    if (typeof keyId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(keyId)
      || Buffer.from(keyId, 'base64url').toString('base64url') !== keyId
      || typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{22,43}$/.test(nonce)
      || Buffer.from(nonce, 'base64url').toString('base64url') !== nonce) {
      throw new ProfileError('profile_mismatch');
    }
    let providerOrigin: string;
    try { providerOrigin = requireOrigin(agent[0]); }
    catch { throw new ProfileError('profile_mismatch'); }
    return { label, input, providerOrigin, keyId, nonce, created, expires, signature: Buffer.from(signature[0]) };
  } catch (error) {
    if (error instanceof ProfileError) throw error;
    throw new ProfileError('malformed_signature');
  }
}

export function checkTime(parsed: Pick<ParsedSignature, 'created' | 'expires'>, nowMs: number): void {
  const now = Math.floor(nowMs / 1000);
  if (parsed.created < 0 || parsed.created > now + CLOCK_SKEW_SECONDS
    || parsed.expires <= parsed.created || parsed.expires - parsed.created > MAX_LIFETIME_SECONDS) {
    throw new ProfileError('invalid_time');
  }
  if (now >= parsed.expires) throw new ProfileError('expired');
}

export function checkDigest(request: Request): void {
  try {
    const digest = parseDictionary(request.headers.get('content-digest') ?? '');
    const item = digest.get('sha-256');
    if (digest.size !== 1 || !item || isInnerList(item) || !(item[0] instanceof ArrayBuffer)
      || item[0].byteLength !== 32 || item[1].size !== 0
      || !timingSafeEqual(Buffer.from(item[0]), createHash('sha256').update('').digest())) {
      throw new ProfileError('digest_mismatch');
    }
  } catch { throw new ProfileError('digest_mismatch'); }
}

export function signatureBase(request: Request, input: InnerList): Buffer {
  const base = httpbis.createSignatureBase({ fields: input[0].map(field => serializeItem(field)) }, {
    method: request.method,
    url: request.url,
    headers: Object.fromEntries(request.headers),
  });
  base.push(['"@signature-params"', [serializeInnerList(input)]]);
  return Buffer.from(httpbis.formatSignatureBase(base));
}
