import {
  createRequestSigner, DIRECTORY_CONTENT_TYPE, generateProviderKey, keyDirectory, KeyDirectoryResolver,
  RequestVerifier, signerFromPrivateKey, type Clock, type Fetcher, type ReplayStore,
} from '../src/index.js';

export const PROVIDER = 'https://provider.example';
export const SHOP = 'https://shop.example';
export const TARGET = SHOP + '/agent/catalog?category=books';
export const NOW = 1_791_244_800_000;

export class TestReplayStore implements ReplayStore {
  readonly entries = new Map<string, number>();
  constructor(private readonly clock: Clock) {}
  async reserve(key: string, expires: number) {
    if ((this.entries.get(key) ?? 0) > this.clock()) return false;
    this.entries.set(key, expires);
    return true;
  }
}

export function harness() {
  let now = NOW;
  let calls = 0;
  let responseKeys = [generateProviderKey()];
  const initialKey = responseKeys[0]!;
  const clock = () => now;
  const transport: Fetcher = async () => {
    calls++;
    return Response.json(keyDirectory(responseKeys.map(key => key.publicKey)), {
      headers: { 'content-type': DIRECTORY_CONTENT_TYPE, 'cache-control': 'max-age=10' },
    });
  };
  const resolver = new KeyDirectoryResolver({ providers: [PROVIDER], fetch: transport, clock });
  const replay = new TestReplayStore(clock);
  const verifier = new RequestVerifier({ resolver, replayStore: replay, clock });
  const signingKey = signerFromPrivateKey(initialKey.privateKeyPem);
  const signer = createRequestSigner({ providerOrigin: PROVIDER, signer: signingKey, allowedOrigins: [SHOP], clock });
  return { clock, resolver, replay, verifier, signer, signingKey, initialKey, transport,
    setNow(value: number) { now = value; }, setKeys(keys: typeof responseKeys) { responseKeys = keys; },
    get calls() { return calls; }, async request() { return signer.signRequest(new Request(TARGET)); },
  };
}

export function withHeaders(request: Request, mutate: (headers: Headers) => void): Request {
  const headers = new Headers(request.headers);
  mutate(headers);
  return new Request(request.url, { method: request.method, headers });
}
