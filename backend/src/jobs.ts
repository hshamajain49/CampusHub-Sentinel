// In-process scheduled work (one Render instance). Retention: sentinel_purge() removes rows past each app's retention
// settings, five minutes after start and then every six hours. A failure is logged and retried next time.
import { pool } from './db/pool.js';
import { logger } from './lib/logger.js';

export async function runRetention(): Promise<Record<string, number> | null> {
  try {
    const { rows } = await pool.query<{ out: Record<string, number> }>('select public.sentinel_purge() as out');
    const out = rows[0]!.out;
    if (Object.values(out).some((n) => n > 0)) logger.info({ purged: out }, 'retention purge');
    return out;
  } catch (err) {
    logger.error({ err }, 'retention purge failed');
    return null;
  }
}

export function startJobs(): () => void {
  const first = setTimeout(() => void runRetention(), 5 * 60_000);
  const every = setInterval(() => void runRetention(), 6 * 3_600_000);
  first.unref();
  every.unref();
  return () => {
    clearTimeout(first);
    clearInterval(every);
  };
}
