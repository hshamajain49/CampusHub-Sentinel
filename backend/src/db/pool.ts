// pg pool. Production connects to Neon's DIRECT endpoint as the least-privilege role sentinel_app.
import pg from 'pg';
import { config } from '../config/env.js';
import { logger } from '../lib/logger.js';

pg.types.setTypeParser(20, (v) => Number(v)); // int8 (counts, identity ids) → number

const dbUrl = new URL(config.DATABASE_URL);
if (dbUrl.hostname.includes('-pooler.')) {
  throw new Error('DATABASE_URL points at a Neon -pooler endpoint; use the direct (unpooled) connection string');
}
const sslRequested = config.DATABASE_SSL || ['require', 'verify-ca', 'verify-full'].includes(dbUrl.searchParams.get('sslmode') ?? '');
dbUrl.searchParams.delete('sslmode');
dbUrl.searchParams.delete('channel_binding');

export const databaseHost = dbUrl.hostname;

export const pool = new pg.Pool({
  connectionString: dbUrl.toString(),
  max: config.DATABASE_POOL_MAX,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  ssl: sslRequested ? { rejectUnauthorized: true } : false,
  application_name: 'sentinel-api',
  options: '-c statement_timeout=10s -c lock_timeout=5s -c idle_in_transaction_session_timeout=15s -c TimeZone=UTC',
});
pool.on('error', (err) => logger.warn({ err: err.message }, 'idle database client error'));

export type DbClient = pg.Pool | pg.PoolClient;

/** BEGIN … COMMIT with one retry on serialization/deadlock errors. */
export async function withTransaction<T>(fn: (tx: pg.PoolClient) => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    const client = await pool.connect();
    try {
      await client.query('begin');
      const out = await fn(client);
      await client.query('commit');
      return out;
    } catch (err: any) {
      await client.query('rollback').catch(() => undefined);
      if (attempt === 0 && (err?.code === '40001' || err?.code === '40P01')) continue;
      throw err;
    } finally {
      client.release();
    }
  }
}
