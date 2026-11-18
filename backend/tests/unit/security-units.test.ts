import { describe, expect, it } from 'vitest';
import { redactDetails } from '../../src/modules/ingest/ingest.service.js';
import { signRequest, verifySignature } from '../../src/modules/ingest/signature.js';
import { inQuietHours, renderAlertEmail } from '../../src/modules/notify/notifier.js';
import { riskLevel } from '../../src/modules/security/ips.service.js';

const SECRET = 'test-secret-for-signatures-only';

describe('ingestion signatures', () => {
  const body = Buffer.from('{"events":[]}');
  const now = 1_800_000_000;
  const sig = signRequest(SECRET, 'POST', '/ingest/v1/events', body, now);

  it('accepts the exact request it signs', () => {
    expect(sig).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(verifySignature(SECRET, sig, 'POST', '/ingest/v1/events', body, now)).toBe('ok');
    expect(verifySignature(SECRET, sig, 'post', '/ingest/v1/events', body, now + 299)).toBe('ok');
  });
  it.each([
    ['another secret', () => verifySignature('other-secret', sig, 'POST', '/ingest/v1/events', body, now), 'mismatch'],
    ['a changed body', () => verifySignature(SECRET, sig, 'POST', '/ingest/v1/events', Buffer.from('{"events":[1]}'), now), 'mismatch'],
    ['another endpoint', () => verifySignature(SECRET, sig, 'GET', '/ingest/v1/blocklist', body, now), 'mismatch'],
    ['older than 5 minutes', () => verifySignature(SECRET, sig, 'POST', '/ingest/v1/events', body, now + 301), 'stale'],
    ['from the future', () => verifySignature(SECRET, sig, 'POST', '/ingest/v1/events', body, now - 301), 'stale'],
    ['a malformed header', () => verifySignature(SECRET, 'v1=abc', 'POST', '/ingest/v1/events', body, now), 'malformed'],
    ['no header', () => verifySignature(SECRET, undefined, 'POST', '/ingest/v1/events', body, now), 'malformed'],
  ])('rejects %s', (_name, check, expected) => expect(check()).toBe(expected));
});

describe('redactDetails', () => {
  it('removes credential-looking fields at any depth, keeps the rest', () => {
    const out = redactDetails({
      password: 'hunter2',
      newPassword: 'x',
      token: 't',
      Authorization: 'Bearer abc',
      nested: { apiKey: 'k', cookie: 'c', ok: 'fine', deeper: { sessionToken: 's' } },
      accountKey: 'acct:hash',
      reason: 'wrong_password',
      list: [{ secret: 1 }, 'plain'],
    });
    expect(out).toEqual({
      password: '[redacted]',
      newPassword: '[redacted]',
      token: '[redacted]',
      Authorization: '[redacted]',
      nested: { apiKey: '[redacted]', cookie: '[redacted]', ok: 'fine', deeper: { sessionToken: '[redacted]' } },
      accountKey: 'acct:hash',
      reason: 'wrong_password',
      list: [{ secret: '[redacted]' }, 'plain'],
    });
  });
  it('caps depth, list length and string length', () => {
    const deep = { a: { b: { c: { d: { e: { f: 1 } } } } } };
    expect(JSON.stringify(redactDetails(deep))).toContain('[truncated]');
    expect((redactDetails({ l: Array.from({ length: 50 }, (_, i) => i) }) as { l: number[] }).l).toHaveLength(20);
    expect((redactDetails({ s: 'x'.repeat(2000) }) as { s: string }).s).toHaveLength(500);
  });
});

describe('notifications', () => {
  it('quiet hours, including ranges across midnight (REPORT_TIMEZONE is UTC in tests)', () => {
    const at = (h: number, m = 0) => new Date(Date.UTC(2026, 10, 17, h, m));
    expect(inQuietHours('22:00', '07:00', at(23))).toBe(true);
    expect(inQuietHours('22:00', '07:00', at(6, 59))).toBe(true);
    expect(inQuietHours('22:00', '07:00', at(7))).toBe(false);
    expect(inQuietHours('09:00', '17:00', at(12))).toBe(true);
    expect(inQuietHours('09:00', '17:00', at(18))).toBe(false);
    expect(inQuietHours(null, null, at(3))).toBe(false);
  });
  it('escapes everything in the HTML email and never claims a compromise', () => {
    const mail = renderAlertEmail({
      id: 'a1',
      severity: 'high',
      title: '<script>alert(1)</script>',
      reason: '11 events from "203.0.113.9" & more',
      app: 'CampusHub',
      firstSeen: new Date(0),
      lastSeen: new Date(0),
      occurrences: 11,
    });
    expect(mail.html).not.toContain('<script>');
    expect(mail.html).toContain('&lt;script&gt;');
    expect(mail.html).toContain('&quot;203.0.113.9&quot; &amp; more');
    expect(mail.subject).toMatch(/^\[Sentinel\] HIGH: /);
    expect(mail.text).toMatch(/not proof of a compromise/);
  });
  it('risk levels', () => {
    expect([0, 9.9, 10, 29, 30, 59, 60, 500].map(riskLevel)).toEqual(['low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical']);
  });
});
