import { requireOrigin } from './profile.js';
import type { AgentPolicy, Clock, RateLimiter } from './types.js';

export interface ProviderRule { origin: string; action: 'allow' | 'deny'; requestsPerMinute?: number }

export function createProviderPolicy(options: { rules: readonly ProviderRule[]; rateLimiter: RateLimiter; clock?: Clock }): AgentPolicy {
  const rules = new Map(options.rules.map(rule => {
    requireOrigin(rule.origin);
    if (rule.requestsPerMinute !== undefined && (!Number.isSafeInteger(rule.requestsPerMinute) || rule.requestsPerMinute < 1)) {
      throw new Error('Rate limits must be positive integers');
    }
    return [rule.origin, rule];
  }));
  const clock = options.clock ?? Date.now;
  return async identity => {
    const rule = rules.get(identity.providerOrigin);
    if (!rule || rule.action === 'deny') return { action: 'deny' };
    try {
      const result = await options.rateLimiter.consume(identity.providerOrigin, rule.requestsPerMinute ?? 60, 60);
      if (!result.allowed) return { action: 'rate_limit', retryAfterSeconds: Math.max(1, result.resetAt - Math.floor(clock() / 1000)) };
      return { action: 'allow', remaining: result.remaining };
    } catch { return { action: 'unavailable' }; }
  };
}
