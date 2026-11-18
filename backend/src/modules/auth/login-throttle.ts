// Failed sign-ins, in Postgres (survives restarts). Keys are HMACs, so unknown emails are throttled exactly like real
// ones and no address is stored.
//   account  5 failures within 15 min → locked 1 min, doubling with each further failure, at most 60 min
//   IP       20 failures within 15 min → locked 30 min
import type { DbClient } from '../../db/pool.js';
import { pool } from '../../db/pool.js';
import { keyedHash } from '../../lib/crypto.js';

export const THROTTLE = {
  account: { threshold: 5, windowMinutes: 15, baseLockSeconds: 60, maxLockSeconds: 3600 },
  ip: { threshold: 20, windowMinutes: 15, baseLockSeconds: 1800, maxLockSeconds: 1800 },
} as const;

const accountKey = (email: string) => `acct:${keyedHash(`acct\n${email.trim().toLowerCase()}`)}`;
const ipKey = (ip: string) => `ip:${keyedHash(`ip\n${ip}`)}`;

export async function checkThrottle(email: string, ip: string | null, db: DbClient = pool): Promise<number> {
  const keys = [accountKey(email), ...(ip ? [ipKey(ip)] : [])];
  const { rows } = await db.query<{ wait: number | null }>(
    `select ceil(extract(epoch from max(locked_until) - now()))::int as wait
       from public.login_throttle where key = any($1::text[]) and locked_until > now()`,
    [keys],
  );
  return Math.max(0, rows[0]?.wait ?? 0);
}

async function bump(db: DbClient, key: string, t: (typeof THROTTLE)[keyof typeof THROTTLE]) {
  await db.query(
    `insert into public.login_throttle as l (key, failures, window_started_at, locked_until)
     values ($1, 1, now(), null)
     on conflict (key) do update set
       failures = case when l.window_started_at < now() - make_interval(mins => $2) then 1 else l.failures + 1 end,
       window_started_at = case when l.window_started_at < now() - make_interval(mins => $2) then now() else l.window_started_at end,
       locked_until = case
         when (case when l.window_started_at < now() - make_interval(mins => $2) then 1 else l.failures + 1 end) >= $3
         then now() + make_interval(secs => least($5::float8, $4::float8 * power(2, (case when l.window_started_at < now() - make_interval(mins => $2) then 1 else l.failures + 1 end) - $3)))
         else l.locked_until end,
       updated_at = now()`,
    [key, t.windowMinutes, t.threshold, t.baseLockSeconds, t.maxLockSeconds],
  );
}

export async function recordFailure(email: string, ip: string | null, db: DbClient = pool): Promise<void> {
  await bump(db, accountKey(email), THROTTLE.account);
  if (ip) await bump(db, ipKey(ip), THROTTLE.ip);
}

export async function clearAccount(email: string, db: DbClient = pool): Promise<void> {
  await db.query('delete from public.login_throttle where key = $1', [accountKey(email)]);
}
