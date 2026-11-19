// Developer sign-in. Steps, in order:
//   1. email + password                                    → a pending session (15 min) in the first open step
//   2. authenticator code, if one is set up                 ('mfa_verify')        ┐ only with MFA_MODE=required
//   3. new password, if the current one is temporary        ('password_change')   │
//   4. set up an authenticator, if there is none yet        ('mfa_enroll')        ┘ (mandatory when required)
//   → 'active': the token is replaced and the session lasts until idle/absolute expiry.
// With MFA_MODE=off (the current default) only steps 1 and 3 exist, and sensitive actions re-confirm the password only.
// Every outcome is written to the audit log. Wrong password and unknown email look identical (message and timing).
import { createHash, randomBytes } from 'node:crypto';
import QRCode from 'qrcode';
import { config } from '../../config/env.js';
import { pool, withTransaction } from '../../db/pool.js';
import { appError } from '../../errors/app-error.js';
import { decrypt, encrypt, keyedHash } from '../../lib/crypto.js';
import { hashPassword, passwordProblem, verifyPassword } from '../../lib/passwords.js';
import { base32Decode, base32Encode, generateTotpSecret, otpauthUrl, verifyTotp } from '../../lib/totp.js';
import type { AdminInfo, SessionInfo } from '../../types/express.js';
import { type AuditActor, writeAudit } from '../audit/audit.service.js';
import { checkThrottle, clearAccount, recordFailure } from './login-throttle.js';
import { advanceSession, createSession, revokeAdminSessions, revokeSession, type SessionState } from './sessions.js';

const TOTP_ISSUER = 'CampusHub Sentinel';
const PENDING_SETUP_MINUTES = 15;
const RECOVERY_CODE_COUNT = 10;
const MFA_LOCK = { threshold: 5, baseSeconds: 300, maxSeconds: 3600 } as const;

/** Whether authenticator codes are asked for (MFA_MODE). Read at call time, so tests can switch it. */
export const mfaRequired = () => config.MFA_MODE === 'required';

export function nextState(admin: { mustChangePassword: boolean; totpEnabled: boolean }, mfaVerified: boolean, required = mfaRequired()): SessionState {
  if (!required) return admin.mustChangePassword ? 'password_change' : 'active';
  if (admin.totpEnabled && !mfaVerified) return 'mfa_verify';
  if (admin.mustChangePassword) return 'password_change';
  if (!admin.totpEnabled) return 'mfa_enroll';
  return 'active';
}

const minutes = (s: number) => Math.max(1, Math.ceil(s / 60));

// ─────────────────────────── 1. sign in ───────────────────────────
export async function login(input: { email: string; password: string }, actor: AuditActor): Promise<{ token: string; state: SessionState }> {
  const email = input.email.trim().toLowerCase();
  const wait = await checkThrottle(email, actor.ip);
  if (wait > 0) {
    await writeAudit(pool, { ...actor, adminEmail: null }, { action: 'auth.login', outcome: 'failure', details: { reason: 'locked', emailHash: keyedHash(email) } });
    throw appError('SIGN_IN_LOCKED', `Too many failed attempts. Try again in ${minutes(wait)} minute${minutes(wait) === 1 ? '' : 's'}.`, { retryAfterSeconds: wait });
  }
  const { rows } = await pool.query(
    `select id, email, password_hash, is_active, must_change_password, (totp_enabled_at is not null) as totp_enabled
       from public.administrator_accounts where email = $1`,
    [email],
  );
  const a = rows[0];
  const ok = await verifyPassword(a?.password_hash, input.password); // runs a dummy hash when the account doesn't exist
  if (!a || !ok || !a.is_active) {
    await recordFailure(email, actor.ip);
    // The attempted email is stored only if it is a real account; anything else (a typo, a pasted password) as a hash.
    await writeAudit(pool, { ...actor, adminId: a?.id ?? null, adminEmail: a?.email ?? null }, {
      action: 'auth.login',
      outcome: 'failure',
      details: { reason: !a ? 'unknown_account' : !ok ? 'wrong_password' : 'deactivated', ...(a ? {} : { emailHash: keyedHash(email) }) },
    });
    throw appError('INVALID_CREDENTIALS');
  }
  await clearAccount(email);
  const state = nextState({ mustChangePassword: a.must_change_password, totpEnabled: a.totp_enabled }, false);
  const token = await withTransaction(async (tx) => {
    const t = await createSession(tx, a.id, state, actor.ip, actor.userAgent);
    await tx.query('update public.administrator_accounts set last_login_at = now(), last_login_ip = $2::inet where id = $1', [a.id, actor.ip]);
    await writeAudit(tx, { ...actor, adminId: a.id, adminEmail: a.email }, { action: 'auth.login', details: { next: state } });
    return t;
  });
  return { token, state };
}

/** Loads the account's current flags (they may have changed since the session was loaded). */
async function flags(adminId: string) {
  const { rows } = await pool.query<{ must_change_password: boolean; totp_enabled: boolean }>(
    'select must_change_password, (totp_enabled_at is not null) as totp_enabled from public.administrator_accounts where id = $1',
    [adminId],
  );
  return { mustChangePassword: rows[0]!.must_change_password, totpEnabled: rows[0]!.totp_enabled };
}

/** After a step: the next state; reaching 'active' returns a new token for the cookie. */
async function advance(session: SessionInfo, adminId: string, opts: { mfaVerified?: boolean } = {}) {
  const verified = opts.mfaVerified || !!session.mfaVerifiedAt;
  const state = nextState(await flags(adminId), verified);
  const token = await advanceSession(pool, session.id, state, { mfaVerified: opts.mfaVerified });
  return { state, token };
}

// ─────────────────────────── password ───────────────────────────
export async function changePassword(
  session: SessionInfo,
  admin: AdminInfo,
  body: { currentPassword: string; newPassword: string },
  actor: AuditActor,
): Promise<{ state: SessionState; token: string | null }> {
  const { rows } = await pool.query<{ password_hash: string }>('select password_hash from public.administrator_accounts where id = $1', [admin.id]);
  if (!(await verifyPassword(rows[0]?.password_hash, body.currentPassword))) {
    await writeAudit(pool, actor, { action: 'auth.password_change', outcome: 'failure', details: { reason: 'wrong_current_password' } });
    throw appError('INVALID_CURRENT_PASSWORD', undefined, { fieldErrors: { currentPassword: ['Your current password is incorrect.'] } });
  }
  if (body.newPassword === body.currentPassword) {
    throw appError('WEAK_PASSWORD', 'Choose a password you have not used here.', { fieldErrors: { newPassword: ['Choose a different password.'] } });
  }
  const problem = passwordProblem(body.newPassword, admin.email);
  if (problem) throw appError('WEAK_PASSWORD', problem, { fieldErrors: { newPassword: [problem] } });
  const hash = await hashPassword(body.newPassword);
  await withTransaction(async (tx) => {
    await tx.query('update public.administrator_accounts set password_hash = $2, must_change_password = false where id = $1', [admin.id, hash]);
    await revokeAdminSessions(tx, admin.id, session.id); // every other device signs in again
    await writeAudit(tx, actor, { action: 'auth.password_change' });
  });
  return advance(session, admin.id);
}

// ─────────────────────────── authenticator ───────────────────────────
const hashRecovery = (code: string) => createHash('sha256').update(code.replace(/[\s-]/g, '').toLowerCase()).digest('hex');

function newRecoveryCodes() {
  const plain = Array.from({ length: RECOVERY_CODE_COUNT }, () => {
    const s = base32Encode(randomBytes(7)).slice(0, 10).toLowerCase();
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
  return { plain, hashes: plain.map(hashRecovery) };
}

export async function mfaSetup(admin: AdminInfo, actor: AuditActor) {
  const secret = generateTotpSecret();
  const b32 = base32Encode(secret);
  await pool.query(
    'update public.administrator_accounts set totp_pending_secret = $2, totp_pending_at = now() where id = $1 and totp_enabled_at is null',
    [admin.id, encrypt(b32, 'totp-secret')],
  );
  await writeAudit(pool, actor, { action: 'auth.mfa_setup_started' });
  const url = otpauthUrl(secret, TOTP_ISSUER, admin.email);
  return { secret: b32.replace(/(.{4})/g, '$1 ').trim(), otpauthUrl: url, qrSvg: await QRCode.toString(url, { type: 'svg', errorCorrectionLevel: 'M', margin: 2 }) };
}

async function recordMfaFailure(adminId: string) {
  await pool.query(
    `update public.administrator_accounts
        set mfa_failures = mfa_failures + 1,
            mfa_locked_until = case when mfa_failures + 1 >= $2
                                    then now() + make_interval(secs => least($4::float8, $3::float8 * power(2, mfa_failures + 1 - $2)))
                                    else mfa_locked_until end
      where id = $1`,
    [adminId, MFA_LOCK.threshold, MFA_LOCK.baseSeconds, MFA_LOCK.maxSeconds],
  );
}

async function mfaRow(adminId: string) {
  const { rows } = await pool.query(
    `select totp_secret, totp_pending_secret, totp_enabled_at, totp_last_step, recovery_codes,
            (totp_pending_at > now() - make_interval(mins => $2)) as pending_fresh,
            case when mfa_locked_until > now() then ceil(extract(epoch from mfa_locked_until - now()))::int end as lock_seconds
       from public.administrator_accounts where id = $1`,
    [adminId, PENDING_SETUP_MINUTES],
  );
  return rows[0]!;
}

function lockedError(seconds: number) {
  return appError('SIGN_IN_LOCKED', `Too many wrong codes. Try again in ${minutes(seconds)} minute${minutes(seconds) === 1 ? '' : 's'}.`, { retryAfterSeconds: seconds });
}

export async function mfaEnable(session: SessionInfo, admin: AdminInfo, code: string, actor: AuditActor) {
  const row = await mfaRow(admin.id);
  if (row.totp_enabled_at) throw appError('CONFLICT', 'An authenticator is already set up.');
  if (!row.totp_pending_secret || !row.pending_fresh) throw appError('SETUP_EXPIRED');
  if (row.lock_seconds) throw lockedError(row.lock_seconds);
  const step = verifyTotp(base32Decode(decrypt(row.totp_pending_secret, 'totp-secret')), code);
  if (step === null) {
    await recordMfaFailure(admin.id);
    await writeAudit(pool, actor, { action: 'auth.mfa_enable', outcome: 'failure', details: { reason: 'invalid_code' } });
    throw appError('INVALID_CODE');
  }
  const codes = newRecoveryCodes();
  await withTransaction(async (tx) => {
    const res = await tx.query(
      `update public.administrator_accounts
          set totp_secret = totp_pending_secret, totp_pending_secret = null, totp_pending_at = null, totp_enabled_at = now(),
              totp_last_step = $2, recovery_codes = $3, mfa_failures = 0, mfa_locked_until = null
        where id = $1 and totp_enabled_at is null and totp_pending_secret is not null`,
      [admin.id, step, codes.hashes],
    );
    if (!res.rowCount) throw appError('CONFLICT', 'An authenticator is already set up.');
    await writeAudit(tx, actor, { action: 'auth.mfa_enable' });
  });
  return { recoveryCodes: codes.plain, ...(await advance(session, admin.id, { mfaVerified: true })) };
}

/** A 6-digit code (each time step usable once) or a single-use recovery code. */
async function checkCode(adminId: string, code: string, opts: { allowRecovery: boolean }): Promise<{ ok: boolean; usedRecovery: boolean; recoveryLeft: number }> {
  const row = await mfaRow(adminId);
  if (!row.totp_enabled_at || !row.totp_secret) throw appError('STEP_REQUIRED', 'Set up an authenticator first.', { next: 'mfa_enroll' });
  if (row.lock_seconds) throw lockedError(row.lock_seconds);
  if (/^\d{6}$/.test(code)) {
    const step = verifyTotp(base32Decode(decrypt(row.totp_secret, 'totp-secret')), code);
    const ok =
      step !== null &&
      (await pool.query(
        'update public.administrator_accounts set totp_last_step = $2, mfa_failures = 0, mfa_locked_until = null where id = $1 and totp_last_step < $2',
        [adminId, step],
      )).rowCount === 1;
    return { ok, usedRecovery: false, recoveryLeft: row.recovery_codes.length };
  }
  if (!opts.allowRecovery) return { ok: false, usedRecovery: false, recoveryLeft: row.recovery_codes.length };
  const res = await pool.query<{ left: number }>(
    `update public.administrator_accounts set recovery_codes = array_remove(recovery_codes, $2), mfa_failures = 0, mfa_locked_until = null
      where id = $1 and $2 = any(recovery_codes) returning cardinality(recovery_codes) as left`,
    [adminId, hashRecovery(code)],
  );
  return { ok: !!res.rows[0], usedRecovery: !!res.rows[0], recoveryLeft: res.rows[0]?.left ?? row.recovery_codes.length };
}

export async function mfaVerify(session: SessionInfo, admin: AdminInfo, code: string, actor: AuditActor) {
  const r = await checkCode(admin.id, code, { allowRecovery: true });
  if (!r.ok) {
    await recordMfaFailure(admin.id);
    await writeAudit(pool, actor, { action: 'auth.mfa_verify', outcome: 'failure', details: { reason: 'invalid_code' } });
    throw appError('INVALID_CODE');
  }
  await writeAudit(pool, actor, { action: 'auth.mfa_verify', details: r.usedRecovery ? { recoveryCode: true, recoveryCodesLeft: r.recoveryLeft } : {} });
  return { usedRecoveryCode: r.usedRecovery, recoveryCodesLeft: r.recoveryLeft, ...(await advance(session, admin.id, { mfaVerified: true })) };
}

// ─────────────────────────── step-up, sign-out, view ───────────────────────────
/** Confirms the password (+ an authenticator code, not a recovery code, when MFA is required) before a sensitive action. */
export async function reauth(session: SessionInfo, admin: AdminInfo, body: { password: string; code?: string }, actor: AuditActor) {
  const { rows } = await pool.query<{ password_hash: string }>('select password_hash from public.administrator_accounts where id = $1', [admin.id]);
  const passwordOk = await verifyPassword(rows[0]?.password_hash, body.password);
  const codeOk = passwordOk && (!mfaRequired() || (!!body.code && (await checkCode(admin.id, body.code, { allowRecovery: false })).ok));
  if (!passwordOk || !codeOk) {
    await recordMfaFailure(admin.id);
    await writeAudit(pool, actor, { action: 'auth.reauth', outcome: 'failure', details: { reason: passwordOk ? 'invalid_code' : 'wrong_password' } });
    throw passwordOk ? appError('INVALID_CODE') : appError('INVALID_CURRENT_PASSWORD');
  }
  await pool.query('update public.administrator_sessions set reauth_at = now() where id = $1', [session.id]);
  await writeAudit(pool, actor, { action: 'auth.reauth' });
}

export async function logout(session: SessionInfo, actor: AuditActor) {
  await withTransaction(async (tx) => {
    await revokeSession(tx, session.id);
    await writeAudit(tx, actor, { action: 'auth.logout' });
  });
}

export function sessionView(session: SessionInfo, admin: AdminInfo, reauthMinutes: number) {
  const reauthUntil = session.reauthAt ? new Date(new Date(session.reauthAt).getTime() + reauthMinutes * 60_000) : null;
  return {
    state: session.state,
    admin: { id: admin.id, email: admin.email, displayName: admin.displayName, role: admin.role },
    expiresAt: new Date(session.expiresAt).toISOString(),
    reauthUntil: reauthUntil && reauthUntil.getTime() > Date.now() ? reauthUntil.toISOString() : null,
    mfaRequired: mfaRequired(),
  };
}
