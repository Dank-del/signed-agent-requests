import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RedisClient } from 'bun';

/** Starts an isolated local Redis/Valkey instance; never touches an existing database. */
export async function startLocalRedis() {
  const executable = Bun.which('redis-server') ?? Bun.which('valkey-server');
  if (!executable) throw new Error('Install Redis 7.2+ or Valkey, or provide REDIS_URL');
  const directory = await mkdtemp(join(tmpdir(), 'signed-agent-redis-'));
  const socket = join(directory, 'redis.sock');
  const process = Bun.spawn([executable, '--port', '0', '--unixsocket', socket, '--unixsocketperm', '700',
    '--save', '', '--appendonly', 'no', '--daemonize', 'no'], { stdout: 'ignore', stderr: 'pipe' });
  try {
    for (let attempt = 0; attempt < 100; attempt++) {
      if (process.exitCode !== null) throw new Error(`Redis failed to start: ${await new Response(process.stderr).text()}`);
      try { await stat(socket); break; } catch { await Bun.sleep(20); }
    }
    const url = `redis+unix://${socket}`;
    const client = new RedisClient(url, { autoReconnect: false, enableOfflineQueue: false, connectionTimeout: 1000 });
    try { await client.connect(); await client.send('PING', []); } finally { client.close(); }
    return { url, async stop() { process.kill(); await process.exited; await rm(directory, { recursive: true, force: true }); } };
  } catch (error) {
    process.kill();
    await process.exited;
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
