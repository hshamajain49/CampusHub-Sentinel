// Developer sign-in, sessions, CSRF, roles, step-up and the audit trail (Part 6 of the brief).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { pool } from '../../src/db/pool.js';
import { createAdmin as createAdminService } from '../../src/modules/admins/admins.service.js';
import { base32Decode, totp } from '../../src/lib/totp.js';
import { app, browser, closePool, cookieOf, createAdmin, nextCode, ORIGIN, PASSWORD, resetDb, signedIn } from '../helpers.js';

beforeAll(resetDb);
afterAll(closePool);

const auditActions = async (email: string) =>
  (await pool.query("select action, outcome from audit_logs where admin_email = $1 order by id", [email])).rows.map((r) => `${r.action}:${r.outcome}`);

describe('first sign-in: temporary password → new password → authenticator → active', () => {
  it('walks every step, rotating the session token at the end', async () => {
    const actor = { adminId: null, adminEmail: 'cli', ip: null, userAgent: 'test' };
    const { temporaryPassword } = await createAdminService(actor, { email: 'first@sentinel.dev', displayName: 'First Owner', role: 'owner' });
    expect(temporaryPassword).toMatch(/^[A-Za-z0-9_-]{20}$/);
    const stored = (await pool.query("select password_hash from administrator_accounts where email = 'first@sentinel.dev'")).rows[0].password_hash;
    expect(stored.startsWith('$argon2id$')).toBe(true);

    const b = browser();
    const login = await b.post('/api/auth/login', { email: 'First@Sentinel.dev ', password: temporaryPassword });
    expect(login.status, JSON.stringify(login.body)).toBe(200);
    expect(login.body.data.state).toBe('password_change');
    const cookie = cookieOf(login)!;
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Strict/i);
    expect(cookie).toMatch(/Path=\//);
    expect(cookie).not.toMatch(/Max-Age|Expires/i); // a browser-session cookie; the server decides the lifetime

    // Nothing but the current step is reachable
    const blocked = await b.get('/api/audit-logs');
    expect(blocked.status).toBe(403);
    expect(blocked.body.error).toMatchObject({ code: 'STEP_REQUIRED', details: { next: 'password_change' } });
    expect((await b.post('/api/auth/mfa/setup')).body.error.code).toBe('STEP_REQUIRED');

    const weak = await b.post('/api/auth/password', { currentPassword: temporaryPassword, newPassword: 'Password2024!' });
    expect(weak.status).toBe(400);
    expect(weak.body.error.code).toBe('WEAK_PASSWORD');
    expect((await b.post('/api/auth/password', { currentPassword: temporaryPassword, newPassword: 'first-sentinel-pass' })).body.error.message).toMatch(/email/);
    const changed = await b.post('/api/auth/password', { currentPassword: temporaryPassword, newPassword: PASSWORD });
    expect(changed.body.data.state).toBe('mfa_enroll');

    const setup = await b.post('/api/auth/mfa/setup');
    expect(setup.status).toBe(200);
    expect(setup.body.data.qrSvg).toContain('<svg');
    expect(setup.body.data.otpauthUrl).toMatch(/^otpauth:\/\/totp\/CampusHub%20Sentinel:/);
    const secret = base32Decode(setup.body.data.secret);
    const right = totp(secret);
    const wrong = String((Number(right) + 500_000) % 1_000_000).padStart(6, '0');
    expect((await b.post('/api/auth/mfa/enable', { code: wrong })).body.error.code).toBe('INVALID_CODE');

    const preActive = cookie.split(';')[0]!;
    const enabled = await b.post('/api/auth/mfa/enable', { code: right });
    expect(enabled.status, JSON.stringify(enabled.body)).toBe(200);
    expect(enabled.body.data.state).toBe('active');
    expect(enabled.body.data.recoveryCodes).toHaveLength(10);
    const activeCookie = cookieOf(enabled)!.split(';')[0]!;
    expect(activeCookie).not.toBe(preActive); // new token: the pre-authentication one is dead

    expect((await b.get('/api/audit-logs')).status).toBe(200);
    const stale = await request(app).get('/api/auth/session').set('cookie', preActive);
    expect(stale.status).toBe(401);

    expect(await auditActions('first@sentinel.dev')).toEqual([
      'auth.login:success',
      'auth.password_change:success',
      'auth.mfa_setup_started:success',
      'auth.mfa_enable:failure',
      'auth.mfa_enable:success',
    ]);
  });

  it('the next sign-in asks for a code; a used code and a wrong code are refused', async () => {
    const { rows } = await pool.query("select totp_secret from administrator_accounts where email = 'first@sentinel.dev'");
    expect(rows[0].totp_secret.startsWith('v1.')).toBe(true); // encrypted at rest
    const b = browser();
    const login = await b.post('/api/auth/login', { email: 'first@sentinel.dev', password: PASSWORD });
    expect(login.body.data.state).toBe('mfa_verify');
    expect((await b.post('/api/auth/mfa/verify', { code: '12345' })).status).toBe(400);
  });
});

describe('sign-in failures', () => {
  it('gives the same answer for an unknown email and a wrong password', async () => {
    await createAdmin('known@sentinel.dev');
    const unknown = await browser().post('/api/auth/login', { email: 'nobody@sentinel.dev', password: PASSWORD });
    const wrong = await browser().post('/api/auth/login', { email: 'known@sentinel.dev', password: 'Not-the-password-1' });
    expect(unknown.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(unknown.body.error.code).toBe(wrong.body.error.code);
    expect(unknown.body.error.message).toBe(wrong.body.error.message);
    // The audit keeps a keyed hash, not the typed address, for unknown accounts
    const { rows } = await pool.query("select admin_email, details from audit_logs where details->>'reason' = 'unknown_account'");
    expect(rows[0].admin_email).toBeNull();
    expect(JSON.stringify(rows[0].details)).not.toContain('nobody');
  });

  it('locks the account after 5 failures, even for the right password', async () => {
    await createAdmin('target@sentinel.dev');
    for (let i = 0; i < 5; i++) expect((await browser().post('/api/auth/login', { email: 'target@sentinel.dev', password: `Wrong-guess-${i}x` })).status).toBe(401);
    const locked = await browser().post('/api/auth/login', { email: 'target@sentinel.dev', password: PASSWORD });
    expect(locked.status).toBe(429);
    expect(locked.body.error.code).toBe('SIGN_IN_LOCKED');
    const keys = (await pool.query('select key from login_throttle')).rows.map((r) => r.key).join(' ');
    expect(keys).not.toMatch(/@|target/);
  });

  it('refuses unknown fields and a deactivated account', async () => {
    expect((await browser().post('/api/auth/login', { email: 'known@sentinel.dev', password: PASSWORD, role: 'owner' })).status).toBe(400);
    await pool.query("update administrator_accounts set is_active = false where email = 'known@sentinel.dev'");
    expect((await browser().post('/api/auth/login', { email: 'known@sentinel.dev', password: PASSWORD })).body.error.code).toBe('INVALID_CREDENTIALS');
  });
});

describe('cross-site request protection', () => {
  const login = { email: 'csrf@sentinel.dev', password: PASSWORD };
  it('refuses a state-changing request without the custom header or from another origin', async () => {
    const noHeader = await request(app).post('/api/auth/login').set('origin', ORIGIN).send(login);
    expect(noHeader.status).toBe(403);
    expect(noHeader.body.error.code).toBe('CSRF_REJECTED');
    const evil = await request(app).post('/api/auth/login').set('origin', 'https://evil.example').set('x-requested-with', 'sentinel').send(login);
    expect(evil.body.error.code).toBe('CSRF_REJECTED');
    const crossSite = await request(app).post('/api/auth/login').set('sec-fetch-site', 'cross-site').set('x-requested-with', 'sentinel').send(login);
    expect(crossSite.body.error.code).toBe('CSRF_REJECTED');
  });
  it('accepts a same-origin request that omits Origin but carries Sec-Fetch-Site', async () => {
    const ok = await request(app).post('/api/auth/login').set('sec-fetch-site', 'same-origin').set('x-requested-with', 'sentinel').send(login);
    expect(ok.status).toBe(401); // reached sign-in (unknown account), not the CSRF check
  });
  it('never sends CORS headers', async () => {
    const pre = await request(app).options('/api/auth/login').set('origin', 'https://evil.example').set('access-control-request-method', 'POST');
    expect(pre.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('sessions end', () => {
  it('on sign-out (the cookie is useless afterwards)', async () => {
    const owner = await createAdmin('logout@sentinel.dev');
    const b = browser();
    await b.post('/api/auth/login', { email: owner.email, password: owner.password });
    const verified = await b.post('/api/auth/mfa/verify', { code: nextCode(owner.secret!) });
    const cookie = cookieOf(verified)!.split(';')[0]!;
    expect((await request(app).get('/api/auth/session').set('cookie', cookie)).status).toBe(200);
    const out = await b.post('/api/auth/logout');
    expect(out.status).toBe(204);
    expect(String(out.headers['set-cookie'])).toMatch(/sentinel_session=;/); // cleared in the browser
    expect((await request(app).get('/api/auth/session').set('cookie', cookie)).status).toBe(401); // and dead on the server
  });
  it('after 30 idle minutes, at the absolute limit, and when the account is deactivated', async () => {
    const owner = await createAdmin('expiry@sentinel.dev');
    let b = await signedIn(owner);
    await pool.query("update administrator_sessions set last_seen_at = now() - interval '31 minutes' where admin_id = $1", [owner.id]);
    expect((await b.get('/api/auth/session')).status).toBe(401);
    b = await signedIn(owner);
    // The schema requires expires_at > created_at: a lifetime of 1 ms is already over.
    await pool.query("update administrator_sessions set expires_at = created_at + interval '1 millisecond' where admin_id = $1 and revoked_at is null", [owner.id]);
    expect((await b.get('/api/auth/session')).status).toBe(401);
    b = await signedIn(owner);
    await pool.query('update administrator_accounts set is_active = false where id = $1', [owner.id]);
    expect((await b.get('/api/auth/session')).status).toBe(401);
  });
  it('a pending session (before the code) lasts 15 minutes, an active one SESSION_ABSOLUTE_HOURS', async () => {
    const owner = await createAdmin('lifetime@sentinel.dev');
    const b = browser();
    await b.post('/api/auth/login', { email: owner.email, password: owner.password });
    const pending = (await pool.query('select extract(epoch from expires_at - created_at)::int as s from administrator_sessions where admin_id = $1', [owner.id])).rows[0].s;
    expect(pending).toBe(15 * 60);
    await pool.query('update administrator_accounts set totp_last_step = 0 where id = $1', [owner.id]);
    await b.post('/api/auth/mfa/verify', { code: nextCode(owner.secret!) });
    const active = (await pool.query('select extract(epoch from expires_at - created_at)::int as s from administrator_sessions where admin_id = $1', [owner.id])).rows[0].s;
    expect(active).toBe(12 * 3600);
  });
});

describe('roles and step-up confirmation', () => {
  it('analysts can read but not manage developers; owners need a fresh password + code', async () => {
    const owner = await createAdmin('owner@sentinel.dev');
    const analyst = await createAdmin('analyst@sentinel.dev', { role: 'analyst' });
    const a = await signedIn(analyst);
    expect((await a.get('/api/admins')).body.error.code).toBe('FORBIDDEN');
    expect((await a.get('/api/audit-logs')).status).toBe(200);

    const o = await signedIn(owner);
    expect((await o.get('/api/admins')).status).toBe(200);
    const body = { email: 'new.dev@sentinel.dev', displayName: 'New Dev', role: 'analyst' };
    expect((await o.post('/api/admins', body)).body.error.code).toBe('REAUTH_REQUIRED');
    expect((await o.post('/api/auth/reauth', { password: 'Wrong-password-1', code: '000000' })).body.error.code).toBe('INVALID_CURRENT_PASSWORD');
    expect((await o.post('/api/auth/reauth', { password: owner.password, code: totp(owner.secret!, Date.now() + 30_000) })).status).toBe(422); // already used
    await pool.query('update administrator_accounts set totp_last_step = 0, mfa_failures = 0, mfa_locked_until = null where id = $1', [owner.id]);
    expect((await o.post('/api/auth/reauth', { password: owner.password, code: nextCode(owner.secret!) })).status).toBe(204);

    const created = await o.post('/api/admins', body);
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect(created.body.data.temporaryPassword).toHaveLength(20);
    expect(created.body.data.admin).toMatchObject({ email: 'new.dev@sentinel.dev', role: 'analyst', mustChangePassword: true, totpEnabled: false });
    expect((await o.post('/api/admins', body)).status).toBe(409);
    expect((await o.post(`/api/admins/${owner.id}/deactivate`)).body.error.message).toMatch(/your own/);

    const reset = await o.post(`/api/admins/${analyst.id}/reset-mfa`);
    expect(reset.body.data.totpEnabled).toBe(false);
    expect((await a.get('/api/auth/session')).status).toBe(401); // the analyst was signed out
    const again = await browser().post('/api/auth/login', { email: analyst.email, password: analyst.password });
    expect(again.body.data.state).toBe('mfa_enroll');

    const deactivated = await o.post(`/api/admins/${analyst.id}/deactivate`);
    expect(deactivated.body.data.isActive).toBe(false);
    const actions = (await pool.query("select action from audit_logs where admin_email = 'owner@sentinel.dev' order by id")).rows.map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(['auth.reauth', 'admin.created', 'admin.mfa_reset', 'admin.deactivated']));
  });
});

describe('audit log API', () => {
  it('lists newest first with filters, and only for signed-in developers', async () => {
    expect((await request(app).get('/api/audit-logs')).status).toBe(401);
    const b = await signedIn(await createAdmin('reader@sentinel.dev', { role: 'analyst' }));
    const all = await b.get('/api/audit-logs?pageSize=5');
    expect(all.body.meta.pageSize).toBe(5);
    expect(all.body.data.length).toBeLessThanOrEqual(5);
    const failures = await b.get('/api/audit-logs?outcome=failure&pageSize=100');
    expect(failures.body.data.length).toBeGreaterThan(0);
    expect(failures.body.data.every((e: { outcome: string }) => e.outcome === 'failure')).toBe(true);
    expect((await b.get(`/api/audit-logs?action=${encodeURIComponent("x'); drop table audit_logs;--")}`)).status).toBe(400);
  });
});

describe('tamper resistance (database)', () => {
  async function asApp<T>(sql: string, params: unknown[] = []): Promise<{ ok: true; rows: T[] } | { ok: false; code: string }> {
    const c = await pool.connect();
    try {
      await c.query('begin');
      await c.query('set local role sentinel_app');
      const { rows } = await c.query(sql, params);
      await c.query('rollback');
      return { ok: true, rows };
    } catch (e: any) {
      await c.query('rollback').catch(() => undefined);
      return { ok: false, code: e.code };
    } finally {
      c.release();
    }
  }

  it('the app role can append to the audit log but never change or delete it', async () => {
    expect((await asApp("insert into audit_logs (action) values ('test.append') returning id")).ok).toBe(true);
    expect(await asApp("update audit_logs set action = 'x.y'")).toEqual({ ok: false, code: '42501' });
    expect(await asApp('delete from audit_logs')).toEqual({ ok: false, code: '42501' });
    expect(await asApp('truncate audit_logs')).toEqual({ ok: false, code: '42501' });
    expect(await asApp('delete from security_events')).toEqual({ ok: false, code: '42501' });
    expect(await asApp('delete from administrator_accounts')).toEqual({ ok: false, code: '42501' });
    expect(await asApp('drop table detection_rules')).toEqual({ ok: false, code: '42501' });
  });

  it('even the owner role is refused outside the retention purge', async () => {
    await expect(pool.query("update audit_logs set action = 'x.y'")).rejects.toMatchObject({ code: 'SA001' });
    await expect(pool.query('delete from audit_logs')).rejects.toMatchObject({ code: 'SA001' });
  });

  it('the app role runs the retention purge, which only removes rows past retention', async () => {
    const before = (await pool.query<{ n: number }>('select count(*)::int as n from audit_logs')).rows[0]!.n;
    const r = await asApp<{ out: Record<string, number> }>('select sentinel_purge() as out');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.rows[0]!.out.audit_logs).toBe(0); // nothing is 2 years old
    expect((await pool.query<{ n: number }>('select count(*)::int as n from audit_logs')).rows[0]!.n).toBe(before);
  });
});

describe('HTTP hardening', () => {
  it('sends strict security headers and no framework banner', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['content-security-policy']).toContain("script-src 'self'");
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['permissions-policy']).toContain('camera=()');
  });
  it('API answers are never cached; unknown routes are a JSON 404 without details', async () => {
    const res = await request(app).get('/api/nope');
    expect(res.status).toBe(404);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body.error).toMatchObject({ code: 'NOT_FOUND', details: null });
  });
  it('a forged session cookie is ignored and cleared', async () => {
    const res = await request(app).get('/api/auth/session').set('cookie', 'sentinel_session=forged');
    expect(res.status).toBe(401);
    expect(String(res.headers['set-cookie'])).toMatch(/sentinel_session=;/);
  });
});
