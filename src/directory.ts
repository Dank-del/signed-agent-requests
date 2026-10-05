import { createPublicKey, type KeyObject } from 'node:crypto';
import { DIRECTORY_CONTENT_TYPE, DIRECTORY_PATH, requireOrigin } from './profile.js';
import { jwkThumbprint } from './keys.js';
import { withDeadline } from './deadline.js';
import { DependencyError, type Clock, type Fetcher, type KeyResolver } from './types.js';

interface CachedKey { key: KeyObject; nbf?: number; exp?: number }
interface ProviderState {
  origin: string;
  keys: Map<string, CachedKey>;
  expiresAt: number;
  nextRefreshAt: number;
  denied: Set<string>;
  pending?: Promise<void>;
}

export interface DirectoryOptions {
  providers: readonly string[];
  fetch?: Fetcher;
  clock?: Clock;
  maxAgeSeconds?: number;
  refreshCooldownSeconds?: number;
  timeoutMs?: number;
  maxBytes?: number;
}

async function readBounded(response: Response, maxBytes: number, signal: AbortSignal): Promise<string> {
  if (!response.body) throw new Error('Missing directory body');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error('Directory exceeds size limit');
      chunks.push(value);
    }
    signal.throwIfAborted();
    return Buffer.concat(chunks).toString('utf8');
  } finally { signal.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}); }
}

function parseKeys(value: unknown): Map<string, CachedKey> {
  if (!value || typeof value !== 'object' || !('keys' in value)
    || !Array.isArray(value.keys) || value.keys.length < 1 || value.keys.length > 16) throw new Error('Invalid key directory');
  const keys = new Map<string, CachedKey>();
  for (const item of value.keys as unknown[]) {
    if (!item || typeof item !== 'object') throw new Error('Invalid JWK');
    const jwk = item as Record<string, unknown>;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string'
      || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x) || Buffer.from(jwk.x, 'base64url').toString('base64url') !== jwk.x
      || 'd' in jwk || (jwk.alg !== undefined && jwk.alg !== 'ed25519')
      || (jwk.use !== undefined && jwk.use !== 'sig')
      || (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 || jwk.key_ops[0] !== 'verify'))
      || (jwk.nbf !== undefined && (!Number.isSafeInteger(jwk.nbf) || (jwk.nbf as number) < 0))
      || (jwk.exp !== undefined && (!Number.isSafeInteger(jwk.exp) || (jwk.exp as number) <= 0))
      || (jwk.nbf !== undefined && jwk.exp !== undefined && (jwk.exp as number) <= (jwk.nbf as number))) {
      throw new Error('Invalid Ed25519 public JWK');
    }
    const publicFields = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
    const id = jwkThumbprint(publicFields);
    if ((jwk.kid !== undefined && jwk.kid !== id) || keys.has(id)) throw new Error('Invalid key identifier');
    keys.set(id, {
      key: createPublicKey({ key: publicFields, format: 'jwk' }),
      ...(jwk.nbf === undefined ? {} : { nbf: jwk.nbf as number }),
      ...(jwk.exp === undefined ? {} : { exp: jwk.exp as number }),
    });
  }
  return keys;
}

export class KeyDirectoryResolver implements KeyResolver {
  private readonly states: Map<string, ProviderState>;
  private readonly transport: Fetcher;
  private readonly clock: Clock;
  private readonly maxAgeMs: number;
  private readonly cooldownMs: number;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;

  constructor(options: DirectoryOptions) {
    this.states = new Map(options.providers.map(origin => [requireOrigin(origin), {
      origin, keys: new Map(), expiresAt: 0, nextRefreshAt: 0, denied: new Set<string>(),
    }]));
    if (this.states.size === 0) throw new Error('Configure at least one trusted provider');
    this.transport = options.fetch ?? fetch;
    this.clock = options.clock ?? Date.now;
    this.maxAgeMs = (options.maxAgeSeconds ?? 60) * 1000;
    this.cooldownMs = (options.refreshCooldownSeconds ?? 5) * 1000;
    this.timeoutMs = options.timeoutMs ?? 2000;
    this.maxBytes = options.maxBytes ?? 65_536;
    for (const value of [this.maxAgeMs, this.cooldownMs, this.timeoutMs, this.maxBytes]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error('Directory bounds must be positive integers');
    }
  }

  isTrusted(origin: string): boolean { return this.states.has(origin); }
  isDenied(origin: string, keyId: string): boolean { return this.states.get(origin)?.denied.has(keyId) ?? false; }
  denyKey(origin: string, keyId: string): void {
    const state = this.states.get(origin);
    if (!state) throw new Error('Unknown provider');
    state.denied.add(keyId);
  }

  private async refresh(state: ProviderState): Promise<void> {
    if (state.pending) return state.pending;
    if (this.clock() < state.nextRefreshAt) {
      if (this.clock() >= state.expiresAt) throw new DependencyError('directory');
      return;
    }
    state.nextRefreshAt = this.clock() + this.cooldownMs;
    const operation = (async () => {
      try {
        const { keys, lifetime } = await withDeadline(async signal => {
          const response = await this.transport(state.origin + DIRECTORY_PATH, {
            redirect: 'error', signal, headers: { accept: DIRECTORY_CONTENT_TYPE },
          });
          signal.throwIfAborted();
          if (response.status !== 200 || response.redirected
            || (response.url !== '' && response.url !== state.origin + DIRECTORY_PATH)
            || response.headers.get('content-type')?.split(';')[0]?.trim() !== DIRECTORY_CONTENT_TYPE) {
            await response.body?.cancel();
            throw new Error('Unexpected directory response');
          }
          const keys = parseKeys(JSON.parse(await readBounded(response, this.maxBytes, signal)));
          const directive = response.headers.get('cache-control') ?? '';
          const match = /(?:^|,)\s*max-age=(\d+)(?:\s*(?:,|$))/i.exec(directive);
          const advertisedMs = match ? Number(match[1]) * 1000 : this.maxAgeMs;
          const lifetime = /(?:^|,)\s*(?:no-store|no-cache)(?:\s*(?:,|$))/i.test(directive) ? 0
            : Math.min(this.maxAgeMs, advertisedMs);
          return { keys, lifetime };
        }, this.timeoutMs);
        // A late response from a timed-out transport cannot overwrite the cache.
        state.keys = keys;
        state.expiresAt = this.clock() + lifetime;
      } catch (cause) { throw new DependencyError('directory', { cause }); }
    })();
    state.pending = operation;
    try { await operation; } finally { delete state.pending; }
  }

  async resolve(origin: string, keyId: string): Promise<KeyObject | undefined> {
    const state = this.states.get(origin);
    if (!state || state.denied.has(keyId)) return undefined;
    if (this.clock() >= state.expiresAt || !state.keys.has(keyId)) await this.refresh(state);
    const key = state.keys.get(keyId);
    const now = Math.floor(this.clock() / 1000);
    if (!key || state.denied.has(keyId) || (key.nbf !== undefined && now < key.nbf)
      || (key.exp !== undefined && now >= key.exp)) return undefined;
    return key.key;
  }

  async preload(): Promise<void> { await Promise.all([...this.states.values()].map(state => this.refresh(state))); }

  /** Call from a controlled background task; the same refresh cooldown still applies. */
  async refreshAll(): Promise<void> { await this.preload(); }
}
