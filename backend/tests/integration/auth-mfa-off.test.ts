// MFA_MODE=off (the default since 2026-11-19): sign-in is password only, and sensitive actions re-confirm the
// password only. The other suites run with MFA_MODE=required (.env.test); this file switches it off at run time.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { config } from '../../src/config/env.js';
import { browser, closePool, createAdmin, PASSWORD, resetDb } from '../helpers.js';

const setMode = (m: 'required' | 'off') => ((config as { MFA_MODE: string }).MFA_MODE = m);

beforeAll(async () => {
  await resetDb();
  setMode('off');
});
afterAll(async () => {
  setMode('required');
  await closePool();
});

describe('password-only sign-in (MFA_MODE=off)', () => {
  it('a developer with an authenticator signs straight in, without a code', async () => {
    const a = await createAdmin('enrolled@mfa-off.dev');
    const b = browser();
    const login = await b.post('/api/auth/login', { email: a.email, password: a.password });
    expect(login.status).toBe(200);
    expect(login.body.data.state).toBe('active');
    const s = await b.get('/api/auth/session');
    expect(s.body.data).toMatchObject({ state: 'active', mfaRequired: false });
    expect((await b.get('/api/security/rules')).status).not.toBe(401);
  });

  it('a new developer changes the temporary password and is in: no authenticator setup', async () => {
    const a = await createAdmin('new@mfa-off.dev', { totp: false, mustChangePassword: true });
    const b = browser();
    const login = await b.post('/api/auth/login', { email: a.email, password: a.password });
    expect(login.body.data.state).toBe('password_change');
    const changed = await b.post('/api/auth/password', { currentPassword: a.password, newPassword: 'A-brand-new-passphrase-2026' });
    expect(changed.status, JSON.stringify(changed.body)).toBe(200);
    expect(changed.body.data.state).toBe('active');
  });

  it('a wrong password is still refused', async () => {
    await createAdmin('wrong@mfa-off.dev');
    const res = await browser().post('/api/auth/login', { email: 'wrong@mfa-off.dev', password: 'not-the-password-1' });
    expect(res.status).toBe(401);
  });

  it('sensitive actions re-confirm with the password only', async () => {
    const a = await createAdmin('reauth@mfa-off.dev');
    const b = browser();
    await b.post('/api/auth/login', { email: a.email, password: a.password });
    const bad = await b.post('/api/auth/reauth', { password: 'not-the-password-1' });
    expect(bad.body.error.code).toBe('INVALID_CURRENT_PASSWORD');
    const ok = await b.post('/api/auth/reauth', { password: PASSWORD });
    expect(ok.status).toBe(204);
    expect((await b.get('/api/auth/session')).body.data.reauthUntil).not.toBeNull();
  });

  it('turning MFA back on asks enrolled developers for their code again', async () => {
    setMode('required');
    try {
      const a = await createAdmin('back-on@mfa-off.dev');
      const login = await browser().post('/api/auth/login', { email: a.email, password: a.password });
      expect(login.body.data.state).toBe('mfa_verify');
    } finally {
      setMode('off');
    }
  });
});
