// Integration helpers: the real Express app against the local test database (:5434/sentinel_test).
import request from 'supertest';
import { createApp } from '../src/app.js';
import { config } from '../src/config/env.js';
import { pool } from '../src/db/pool.js';
import { encrypt } from '../src/lib/crypto.js';
import { hashPassword } from '../src/lib/passwords.js';
import { base32Encode, generateTotpSecret, totp } from '../src/lib/totp.js';

export const app = createApp();
export const ORIGIN = config.APP_ORIGIN;
export const PASSWORD = 'Correct-horse-battery-42';

/** Wipes test data. Append-only tables can only be emptied with the purge flag, which only the owner role can use. */
export async function resetDb() {
  const c = await pool.connect();
  try {
    await c.query('begin');
    await c.query("set local sentinel.purge = 'on'");
    await c.query(
      `truncate audit_logs, security_events, incident_notes, alert_events, security_alerts, security_incidents, notification_log,
                notification_preferences, ip_blocks, ip_allowlist, suspicious_ips, analytics_events, analytics_sessions,
                analytics_visitors, traffic_minutes, administrator_sessions, login_throttle`,
    );
    await c.query('update detection_rules set updated_by = null');
    await c.query('delete from administrator_accounts');
    await c.query('commit');
  } catch (e) {
    await c.query('rollback');
    throw e;
  } finally {
    c.release();
  }
}

export interface TestAdmin {
  id: string;
  email: string;
  password: string;
  /** The raw TOTP secret when the account has an authenticator. */
  secret: Buffer | null;
}

/** An account inserted directly: by default with an authenticator and no pending password change. */
export async function createAdmin(
  email: string,
  opts: { role?: 'owner' | 'analyst'; mustChangePassword?: boolean; totp?: boolean; password?: string } = {},
): Promise<TestAdmin> {
  const password = opts.password ?? PASSWORD;
  const secret = opts.totp === false ? null : generateTotpSecret();
  const { rows } = await pool.query(
    `insert into administrator_accounts (email, display_name, role, password_hash, must_change_password, totp_secret, totp_enabled_at)
     values ($1, $2, $3, $4, $5, $6, case when $6::text is null then null else now() end) returning id`,
    [email, email.split('@')[0], opts.role ?? 'owner', await hashPassword(password), opts.mustChangePassword ?? false, secret ? encrypt(base32Encode(secret), 'totp-secret') : null],
  );
  return { id: rows[0].id, email, password, secret };
}

/** Requests with the dashboard's Origin and CSRF header, keeping cookies like a browser. */
export function browser() {
  const agent = request.agent(app);
  const csrf = (r: request.Test) => r.set('origin', ORIGIN).set('x-requested-with', 'sentinel');
  return {
    agent,
    get: (p: string) => agent.get(p),
    post: (p: string, body?: object) => csrf(agent.post(p)).send(body ?? {}),
  };
}

/** A code for the NEXT time step: always newer than any code already used in the current one. */
export const nextCode = (secret: Buffer) => totp(secret, Date.now() + 30_000);

/** Signs in through every step and returns a browser with an active session. */
export async function signedIn(a: TestAdmin) {
  const b = browser();
  const login = await b.post('/api/auth/login', { email: a.email, password: a.password });
  if (login.body.data?.state !== 'mfa_verify') throw new Error(`unexpected state ${JSON.stringify(login.body)}`);
  // A code is accepted once per time step; tests sign the same account in repeatedly, so start from a clean slate.
  await pool.query('update administrator_accounts set totp_last_step = 0 where id = $1', [a.id]);
  const verify = await b.post('/api/auth/mfa/verify', { code: nextCode(a.secret!) });
  if (verify.body.data?.state !== 'active') throw new Error(`verify failed ${JSON.stringify(verify.body)}`);
  return b;
}

export function cookieOf(res: request.Response): string | undefined {
  const raw = res.headers['set-cookie'] as unknown as string[] | undefined;
  return raw?.find((c) => c.startsWith(`${config.SESSION_COOKIE}=`));
}

export async function closePool() {
  await pool.end();
}
