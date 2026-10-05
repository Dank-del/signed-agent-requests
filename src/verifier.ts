import { createHash, verify } from 'node:crypto';
import { checkDigest, checkPublicRequest, checkTime, parseSignature, REPLAY_RETENTION_MARGIN_MS, signatureBase } from './profile.js';
import { ProfileError, type Clock, type KeyResolver, type ReplayStore, type VerificationResult } from './types.js';

export interface VerifierOptions { resolver: KeyResolver; replayStore: ReplayStore; clock?: Clock }

export class RequestVerifier {
  private readonly clock: Clock;
  constructor(private readonly options: VerifierOptions) { this.clock = options.clock ?? Date.now; }

  async verify(request: Request): Promise<VerificationResult> {
    try {
      checkPublicRequest(request);
      if (!['signature', 'signature-input', 'signature-agent'].some(name => request.headers.has(name))) {
        return { status: 'unsigned' };
      }
      const parsed = parseSignature(request);
      checkTime(parsed, this.clock());
      checkDigest(request);
      const { resolver } = this.options;
      if (!resolver.isTrusted(parsed.providerOrigin)) throw new ProfileError('untrusted_provider');
      if (resolver.isDenied(parsed.providerOrigin, parsed.keyId)) throw new ProfileError('key_denied');
      let key;
      try { key = await resolver.resolve(parsed.providerOrigin, parsed.keyId); }
      catch { return { status: 'unverifiable', reason: 'directory_unavailable' }; }
      if (resolver.isDenied(parsed.providerOrigin, parsed.keyId)) throw new ProfileError('key_denied');
      if (!key) throw new ProfileError('unknown_key');
      if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519'
        || !verify(null, signatureBase(request, parsed.input), key, parsed.signature)) {
        throw new ProfileError('bad_signature');
      }
      // Directory lookup and cryptography may have crossed the expiry boundary.
      checkTime(parsed, this.clock());
      const replayKey = createHash('sha256').update(JSON.stringify([
        parsed.providerOrigin, parsed.keyId, parsed.nonce,
      ])).digest('hex');
      let reserved: boolean;
      try {
        reserved = await this.options.replayStore.reserve(replayKey,
          parsed.expires * 1000 + REPLAY_RETENTION_MARGIN_MS);
      } catch { return { status: 'unverifiable', reason: 'replay_store_unavailable' }; }
      if (!reserved) throw new ProfileError('replay');
      checkTime(parsed, this.clock());
      if (resolver.isDenied(parsed.providerOrigin, parsed.keyId)) throw new ProfileError('key_denied');
      return { status: 'verified', identity: {
        providerOrigin: parsed.providerOrigin, keyId: parsed.keyId, algorithm: 'ed25519',
        created: parsed.created, expires: parsed.expires,
      } };
    } catch (error) {
      return { status: 'invalid', reason: error instanceof ProfileError ? error.reason : 'malformed_signature' };
    }
  }
}
