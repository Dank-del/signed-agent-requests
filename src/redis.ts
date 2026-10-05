import { createHash } from 'node:crypto';
import { DependencyError, type Clock, type RateLimiter, type RateLimitResult, type ReplayStore } from './types.js';

export interface RedisConnection {
  readonly connected: boolean;
  send(command: string, args: string[]): Promise<unknown>;
}

async function command(client: RedisConnection, name: string, args: string[], timeoutMs: number): Promise<unknown> {
  if (!client.connected) throw new DependencyError('redis');
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      client.send(name, args),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new DependencyError('redis')), timeoutMs); }),
    ]);
  } catch (cause) { throw new DependencyError('redis', { cause }); }
  finally { if (timer) clearTimeout(timer); }
}

export interface RedisStoreOptions { prefix?: string; timeoutMs?: number; clock?: Clock }

function bounds(options: RedisStoreOptions) {
  const prefix = options.prefix ?? 'signed-agent:v1';
  const timeoutMs = options.timeoutMs ?? 1000;
  if (!/^[A-Za-z0-9:_-]{1,80}$/.test(prefix) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('Invalid Redis store options');
  }
  return { prefix, timeoutMs };
}

export class RedisReplayStore implements ReplayStore {
  private readonly prefix: string;
  private readonly timeoutMs: number;
  private readonly clock: Clock;
  constructor(private readonly client: RedisConnection, options: RedisStoreOptions = {}) {
    ({ prefix: this.prefix, timeoutMs: this.timeoutMs } = bounds(options));
    this.clock = options.clock ?? Date.now;
  }

  async reserve(key: string, retainUntilMs: number): Promise<boolean> {
    const ttl = Math.ceil(retainUntilMs - this.clock());
    if (!/^[a-f0-9]{64}$/.test(key) || !Number.isSafeInteger(ttl) || ttl <= 0 || ttl > 80_000) {
      throw new Error('Invalid replay reservation');
    }
    const result = await command(this.client, 'SET', [`${this.prefix}:nonce:${key}`, '1', 'NX', 'PX', String(ttl)], this.timeoutMs);
    if (result !== null && result !== 'OK') throw new DependencyError('redis');
    return result === 'OK';
  }
}

// Redis time is authoritative for rate-limit windows across replicas.
const RATE_LIMIT_SCRIPT = `
local epoch = tonumber(redis.call('TIME')[1])
local seconds = tonumber(ARGV[1])
local window = math.floor(epoch / seconds)
local previous = tonumber(redis.call('HGET', KEYS[1], 'window'))
local count
if previous == window then
  count = redis.call('HINCRBY', KEYS[1], 'count', 1)
else
  redis.call('HSET', KEYS[1], 'window', window, 'count', 1)
  count = 1
end
redis.call('EXPIRE', KEYS[1], seconds + 5)
return { count, (window + 1) * seconds }
`;

export class RedisRateLimiter implements RateLimiter {
  private readonly prefix: string;
  private readonly timeoutMs: number;
  constructor(private readonly client: RedisConnection, options: RedisStoreOptions = {}) {
    ({ prefix: this.prefix, timeoutMs: this.timeoutMs } = bounds(options));
  }

  async consume(origin: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(windowSeconds)
      || windowSeconds < 1 || windowSeconds > 3600) throw new Error('Invalid rate limit');
    const key = createHash('sha256').update(origin).digest('hex');
    const result = await command(this.client, 'EVAL', [RATE_LIMIT_SCRIPT, '1', `${this.prefix}:rate:${key}`, String(windowSeconds)], this.timeoutMs);
    if (!Array.isArray(result) || result.length !== 2 || !Number.isSafeInteger(result[0])
      || !Number.isSafeInteger(result[1])) throw new DependencyError('redis');
    const count = result[0] as number;
    return { allowed: count <= limit, remaining: Math.max(0, limit - count), resetAt: result[1] as number };
  }
}
