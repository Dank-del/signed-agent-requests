import { startLocalRedis } from './redis-process.js';
import { startDemo } from './runtime.js';

const localRedis = process.env.REDIS_URL ? undefined : await startLocalRedis();
try {
  const runtime = await startDemo({
    redisUrl: process.env.REDIS_URL ?? localRedis!.url,
    directory: process.env.DEMO_DIRECTORY ?? '.local',
    providerPort: Number(process.env.PROVIDER_PORT ?? 9443), sitePort: Number(process.env.SITE_PORT ?? 9444),
    requestsPerMinute: Number(process.env.PROVIDER_RATE_LIMIT ?? 60),
    onEvent(event) {
      console.log(JSON.stringify({ status: event.verification.status,
        ...(event.verification.status === 'verified' ? { provider: event.verification.identity.providerOrigin, keyId: event.verification.identity.keyId } : {}),
        ...('reason' in event.verification ? { reason: event.verification.reason } : {}),
        policy: event.policy?.action, durationMs: Math.round(event.durationMs * 100) / 100,
      }));
    },
  });
  console.log(`Provider directory: ${runtime.providerOrigin}/.well-known/http-message-signatures-directory`);
  console.log(`Website: ${runtime.siteOrigin}`);
  console.log('Run bun run demo:request in another terminal. Ctrl+C stops the local services.');
  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    await runtime.stop();
    await localRedis?.stop();
    process.exit(0);
  };
  process.on('SIGINT', () => { void close(); });
  process.on('SIGTERM', () => { void close(); });
} catch (error) { await localRedis?.stop(); throw error; }
