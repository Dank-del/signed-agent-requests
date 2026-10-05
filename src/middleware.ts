import { requireOrigin } from './profile.js';
import { RequestVerifier } from './verifier.js';
import type { AgentPolicy, VerifiedIdentity, VerificationResult, PolicyDecision } from './types.js';

export interface AgentEvent { verification: VerificationResult; policy?: PolicyDecision; durationMs: number }
export interface AgentHandlerOptions {
  externalOrigin: string;
  verifier: RequestVerifier;
  policy: AgentPolicy;
  handle: (request: Request, identity: VerifiedIdentity) => Response | Promise<Response>;
  onEvent?: (event: AgentEvent) => void;
}

function failure(status: number, code: string, retryAfter?: number): Response {
  return Response.json({ error: code }, { status, headers: {
    'cache-control': 'no-store', ...(retryAfter === undefined ? {} : { 'retry-after': String(retryAfter) }),
  } });
}

export function createAgentHandler(options: AgentHandlerOptions): (request: Request) => Promise<Response> {
  const origin = requireOrigin(options.externalOrigin);
  return async request => {
    const started = performance.now();
    const emit = (verification: VerificationResult, policy?: PolicyDecision) => {
      try { options.onEvent?.({ verification, ...(policy === undefined ? {} : { policy }), durationMs: performance.now() - started }); }
      catch { /* Observability must not alter the authorization decision. */ }
    };
    if (new URL(request.url).origin !== origin) return failure(400, 'wrong_destination');
    const verification = await options.verifier.verify(request);
    if (verification.status !== 'verified') {
      emit(verification);
      if (verification.status === 'unverifiable') return failure(503, verification.reason, 1);
      if (verification.status === 'unsigned') return failure(401, 'signature_required');
      return failure(verification.reason === 'replay' ? 409 : 401, verification.reason);
    }
    let policy: PolicyDecision;
    try { policy = await options.policy(verification.identity); } catch { policy = { action: 'unavailable' }; }
    emit(verification, policy);
    if (policy.action === 'deny') return failure(403, 'provider_denied');
    if (policy.action === 'unavailable') return failure(503, 'policy_unavailable', 1);
    if (policy.action === 'rate_limit') return failure(429, 'rate_limit', policy.retryAfterSeconds);
    // Do not forward attacker-supplied identity headers into application code.
    const headers = new Headers(request.headers);
    for (const name of [...headers.keys()]) if (name.startsWith('x-verified-')) headers.delete(name);
    const response = await options.handle(new Request(request, { headers }), verification.identity);
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('cache-control', 'no-store');
    if (policy.remaining !== undefined) responseHeaders.set('x-ratelimit-remaining', String(policy.remaining));
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
  };
}
