// Server-side sessions. The browser holds an opaque random token in an HttpOnly, Secure, SameSite=Strict cookie;
// the database holds only its SHA-256. A session ends on sign-out, after SESSION_IDLE_MINUTES without activity, or
// SESSION_ABSOLUTE_HOURS after sign-in, whichever comes first. Until every sign-in step is done (new password,
// authenticator) it lives at most 15 minutes and can only reach the step endpoints.
import type { Response } from 'express';
import { config } from '../../config/env.js';
import type { DbClient } from '../../db/pool.js';
import { pool } from '../../db/pool.js';
import { randomToken, sha256 } from '../../lib/crypto.js';
import type { AdminInfo, SessionInfo } from '../../types/express.js';

export type SessionState = SessionInfo['state'];
const PENDING_MINUTES = 15;

export async function createSession(db: DbClient, adminId: string, state: SessionState, ip: string | null, userAgent: string | null): Promise<string> {
  const token = randomToken(32);
  await db.query(
    `insert into public.administrator_sessions (admin_id, token_hash, state, expires_at, ip, user_agent)
     values ($1, $2, $3, now() + make_interval(mins => $4), $5::inet, $6)`,
    [adminId, sha256(token), state, state === 'active' ? config.SESSION_ABSOLUTE_HOURS * 60 : PENDING_MINUTES, ip, userAgent],
  );
  return token;
}

/** The session behind a cookie token, or null (unknown, revoked, expired, idle too long, account deactivated). */
export async function findSession(token: string): Promise<{ session: SessionInfo; admin: AdminInfo } | null> {
  const { rows } = await pool.query(
    `select s.id, s.state, s.created_at, s.expires_at, s.mfa_verified_at, s.reauth_at,
            (s.last_seen_at < now() - interval '60 seconds') as stale,
            a.id as admin_id, a.email, a.display_name, a.role, a.must_change_password, (a.totp_enabled_at is not null) as totp_enabled
       from public.administrator_sessions s
       join public.administrator_accounts a on a.id = s.admin_id
      where s.token_hash = $1 and s.revoked_at is null and s.expires_at > now()
        and s.last_seen_at > now() - make_interval(mins => $2) and a.is_active`,
    [sha256(token), config.SESSION_IDLE_MINUTES],
  );
  const r = rows[0];
  if (!r) return null;
  // Sliding idle timeout, written at most once a minute.
  if (r.stale) await pool.query('update public.administrator_sessions set last_seen_at = now() where id = $1', [r.id]);
  return {
    session: { id: r.id, state: r.state, createdAt: r.created_at, expiresAt: r.expires_at, mfaVerifiedAt: r.mfa_verified_at, reauthAt: r.reauth_at },
    admin: {
      id: r.admin_id,
      email: r.email,
      displayName: r.display_name,
      role: r.role,
      mustChangePassword: r.must_change_password,
      totpEnabled: r.totp_enabled,
    },
  };
}

/**
 * Moves a session to its next state. Reaching 'active' issues a NEW token (the pre-authentication one can't be
 * reused: no session fixation) and sets the absolute lifetime from the original sign-in.
 */
export async function advanceSession(db: DbClient, sessionId: string, state: SessionState, opts: { mfaVerified?: boolean } = {}): Promise<string | null> {
  const token = state === 'active' ? randomToken(32) : null;
  await db.query(
    `update public.administrator_sessions
        set state = $2,
            mfa_verified_at = case when $3::boolean then now() else mfa_verified_at end,
            token_hash = coalesce($4, token_hash),
            expires_at = case when $2 = 'active' then created_at + make_interval(hours => $5) else expires_at end,
            last_seen_at = now()
      where id = $1`,
    [sessionId, state, !!opts.mfaVerified, token ? sha256(token) : null, config.SESSION_ABSOLUTE_HOURS],
  );
  return token;
}

export async function revokeSession(db: DbClient, sessionId: string): Promise<void> {
  await db.query('update public.administrator_sessions set revoked_at = now() where id = $1 and revoked_at is null', [sessionId]);
}

export async function revokeAdminSessions(db: DbClient, adminId: string, exceptSessionId: string | null = null): Promise<void> {
  await db.query(
    'update public.administrator_sessions set revoked_at = now() where admin_id = $1 and revoked_at is null and ($2::uuid is null or id <> $2::uuid)',
    [adminId, exceptSessionId],
  );
}

export function setSessionCookie(res: Response, token: string): void {
  // No Max-Age: a browser session cookie. The server-side expiry is what counts.
  res.cookie(config.SESSION_COOKIE, token, { httpOnly: true, secure: config.production, sameSite: 'strict', path: '/' });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(config.SESSION_COOKIE, { httpOnly: true, secure: config.production, sameSite: 'strict', path: '/' });
}
