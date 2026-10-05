import type { KeyObject } from 'node:crypto';

export type Clock = () => number;
export type Fetcher = (input: Request | string | URL, init?: RequestInit) => Promise<Response>;

export interface VerifiedIdentity {
  readonly providerOrigin: string;
  readonly keyId: string;
  readonly algorithm: 'ed25519';
  readonly created: number;
  readonly expires: number;
}

export type InvalidReason =
  | 'malformed_signature' | 'profile_mismatch' | 'unsupported_request'
  | 'invalid_time' | 'expired' | 'digest_mismatch' | 'untrusted_provider'
  | 'unknown_key' | 'key_denied' | 'bad_signature' | 'replay';

export type VerificationResult =
  | { status: 'verified'; identity: VerifiedIdentity }
  | { status: 'unsigned' }
  | { status: 'invalid'; reason: InvalidReason }
  | { status: 'unverifiable'; reason: 'directory_unavailable' | 'replay_store_unavailable' };

export interface KeyResolver {
  isTrusted(providerOrigin: string): boolean;
  isDenied(providerOrigin: string, keyId: string): boolean;
  resolve(providerOrigin: string, keyId: string): Promise<KeyObject | undefined>;
}

/** Must coordinate all verifier replicas that can accept the same request. */
export interface ReplayStore {
  reserve(key: string, retainUntilMs: number): Promise<boolean>;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export interface RateLimiter {
  consume(providerOrigin: string, limit: number, windowSeconds: number): Promise<RateLimitResult>;
}

export type PolicyDecision =
  | { action: 'allow'; remaining?: number }
  | { action: 'deny' }
  | { action: 'rate_limit'; retryAfterSeconds: number }
  | { action: 'unavailable' };

export type AgentPolicy = (identity: VerifiedIdentity) => Promise<PolicyDecision>;

export class ProfileError extends Error {
  constructor(public readonly reason: InvalidReason) {
    super(reason);
    this.name = 'ProfileError';
  }
}

export class DependencyError extends Error {
  constructor(public readonly dependency: 'directory' | 'redis', options?: ErrorOptions) {
    super(`${dependency} unavailable`, options);
    this.name = 'DependencyError';
  }
}
