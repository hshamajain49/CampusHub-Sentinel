import { describe, expect, it } from 'vitest';
import { decrypt, encrypt, keyedHash, randomToken, safeEqual } from '../../src/lib/crypto.js';
import { generatePassword, hashPassword, passwordProblem, verifyPassword } from '../../src/lib/passwords.js';
import { hotp, totp } from '../../src/lib/totp.js';
import { parseCookies } from '../../src/middleware/basics.js';
import { nextState } from '../../src/modules/auth/auth.service.js';

describe('crypto', () => {
  it('round-trips, uses a fresh IV, and binds ciphertext to its purpose', () => {
    const a = encrypt('JBSWY3DPEHPK3PXP', 'totp-secret');
    expect(a).not.toBe(encrypt('JBSWY3DPEHPK3PXP', 'totp-secret'));
    expect(decrypt(a, 'totp-secret')).toBe('JBSWY3DPEHPK3PXP');
    expect(() => decrypt(a, 'ingest-secret')).toThrow(); // another purpose's key can't read it
  });
  it('detects tampering', () => {
    const [v, iv, ct, tag] = encrypt('secret', 'totp-secret').split('.');
    const bad = Buffer.from(ct!, 'base64url');
    bad[0]! ^= 1;
    expect(() => decrypt([v, iv, bad.toString('base64url'), tag].join('.'), 'totp-secret')).toThrow();
  });
  it('keyed hashes are stable per purpose and differ across purposes', () => {
    expect(keyedHash('203.0.113.9', 'ip-hash')).toBe(keyedHash('203.0.113.9', 'ip-hash'));
    expect(keyedHash('203.0.113.9', 'ip-hash')).not.toBe(keyedHash('203.0.113.9'));
  });
  it('tokens are 256-bit base64url; comparison is length-safe', () => {
    expect(randomToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('passwords', () => {
  it.each([
    ['short', /12 characters/],
    ['Password2024!', /too common/],
    ['sentinel-admin1', null],
    ['aaaaaaaaaaaaaa', /too common/],
    ['priya.sharma-2026x', /email/],
  ])('%s', (pw, problem) => {
    const msg = passwordProblem(pw, 'priya.sharma@college.edu');
    if (problem) expect(msg).toMatch(problem);
    else expect(msg).toBeNull();
  });
  it('hashes with argon2id and verifies; an unknown account still takes a hash', async () => {
    const h = await hashPassword('Correct-horse-battery-42');
    expect(h.startsWith('$argon2id$v=19$m=19456,t=2,p=1$')).toBe(true);
    expect(await verifyPassword(h, 'Correct-horse-battery-42')).toBe(true);
    expect(await verifyPassword(h, 'wrong')).toBe(false);
    expect(await verifyPassword(null, 'anything')).toBe(false);
  });
  it('generates passwords from the full alphabet', () => {
    const many = Array.from({ length: 200 }, () => generatePassword()).join('');
    expect(new Set(many).size).toBeGreaterThan(55);
    expect(generatePassword(32)).toHaveLength(32);
  });
});

describe('TOTP (RFC 6238 Appendix B, RFC 4226 Appendix D)', () => {
  const s = Buffer.from('12345678901234567890', 'ascii');
  it('matches the published vectors', () => {
    expect(totp(s, 59_000, 8)).toBe('94287082');
    expect(totp(s, 1_111_111_109_000, 8)).toBe('07081804');
    expect(totp(s, 20_000_000_000_000, 8)).toBe('65353130');
    expect([0, 1, 2].map((c) => hotp(s, c))).toEqual(['755224', '287082', '359152']);
  });
});

describe('sign-in steps', () => {
  it.each([
    [{ mustChangePassword: true, totpEnabled: false }, false, 'password_change'],
    [{ mustChangePassword: false, totpEnabled: false }, false, 'mfa_enroll'],
    [{ mustChangePassword: false, totpEnabled: true }, false, 'mfa_verify'],
    [{ mustChangePassword: true, totpEnabled: true }, false, 'mfa_verify'], // the code before anything else
    [{ mustChangePassword: true, totpEnabled: true }, true, 'password_change'],
    [{ mustChangePassword: false, totpEnabled: true }, true, 'active'],
  ])('%j, code passed: %s → %s', (admin, verified, expected) => {
    expect(nextState(admin, verified)).toBe(expected);
  });
});

describe('parseCookies', () => {
  it('parses, keeps the first duplicate, and ignores malformed parts', () => {
    expect(parseCookies('a=1; b=two%20words; a=3; =x; bad; c=%E0%A4%A')).toEqual({ a: '1', b: 'two words' });
    expect(parseCookies(undefined)).toEqual({});
  });
});
