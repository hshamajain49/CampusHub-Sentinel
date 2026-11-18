// Security monitoring end to end: signed ingestion, detection rules, alerts (dedupe, escalation, cooldown), email,
// suspicious IPs, blocks + allowlist, incidents, dashboard reads, simulated traffic, live push, secret rotation.
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { pool } from '../../src/db/pool.js';
import { registerApp, rotateIngestSecret } from '../../src/modules/apps/apps.service.js';
import { signRequest } from '../../src/modules/ingest/signature.js';
import { setEmailTransport, type EmailMessage } from '../../src/modules/notify/notifier.js';
import { invalidateRules } from '../../src/modules/security/rules.js';
import { app, browser, closePool, cookieOf, createAdmin, nextCode, resetDb, signedIn, type TestAdmin } from '../helpers.js';

const APP = 'sec-test';
let keyId: string;
let secret: string;
const mails: EmailMessage[] = [];
let owner: TestAdmin;
let ownerB: Awaited<ReturnType<typeof signedIn>>;
let analystB: Awaited<ReturnType<typeof signedIn>>;

function ingest(body: object | string, opts: { t?: number; path?: string; secret?: string; key?: string } = {}) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const sig = signRequest(opts.secret ?? secret, 'POST', opts.path ?? '/ingest/v1/events', raw, opts.t);
  return request(app)
    .post('/ingest/v1/events')
    .set('x-sentinel-key', opts.key ?? keyId)
    .set('x-sentinel-signature', sig)
    .set('content-type', 'application/json')
    .send(raw);
}
function blocklist() {
  return request(app).get('/ingest/v1/blocklist').set('x-sentinel-key', keyId).set('x-sentinel-signature', signRequest(secret, 'GET', '/ingest/v1/blocklist', ''));
}
const ev = (category: string, extra: Record<string, unknown> = {}) => ({
  id: randomUUID().replace(/-/g, ''),
  occurredAt: new Date().toISOString(),
  category,
  severity: 'low',
  description: `${category} (test)`,
  ...extra,
});
const failedLogin = (ip: string, account = 'acct-default', extra: Record<string, unknown> = {}) =>
  ev('auth.login_failed', { sourceIp: ip, route: '/api/auth/sign-in/email', method: 'POST', statusCode: 401, details: { accountKey: account }, ...extra });
const send = async (events: object[]) => {
  const res = await ingest({ events });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return res.body.data as { accepted: number; duplicates: number; dropped: number; alerts: number };
};
const alertsFor = async (ruleKey: string, group?: string) =>
  (
    await pool.query(
      `select * from security_alerts where rule_key = $1 and ($2::text is null or group_key = $2) order by first_seen_at`,
      [ruleKey, group ?? null],
    )
  ).rows;
async function eventually<T>(fn: () => Promise<T>, ok: (v: T) => boolean, ms = 3000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (ok(v) || Date.now() > end) return v;
    await new Promise((r) => setTimeout(r, 50));
  }
}
async function reauth(b: Awaited<ReturnType<typeof signedIn>>, a: TestAdmin) {
  await pool.query('update administrator_accounts set totp_last_step = 0, mfa_failures = 0, mfa_locked_until = null where id = $1', [a.id]);
  const r = await b.post('/api/auth/reauth', { password: a.password, code: nextCode(a.secret!) });
  expect(r.status).toBe(204);
}

beforeAll(async () => {
  await resetDb();
  await registerApp({ slug: APP, name: 'Security Test App', origins: ['http://localhost:5173'] });
  const creds = (await rotateIngestSecret(APP))!;
  keyId = creds.ingestKeyId;
  secret = creds.ingestSecret;
  await pool.query("update detection_rules set auto_block = false, enabled = true");
  invalidateRules();
  setEmailTransport({ send: async (m) => void mails.push(m) });
  owner = await createAdmin('owner@sec.dev');
  ownerB = await signedIn(owner);
  analystB = await signedIn(await createAdmin('analyst@sec.dev', { role: 'analyst' }));
});
afterAll(async () => {
  await pool.query('update detection_rules set auto_block = false');
  await closePool();
});

describe('ingestion is signed server-to-server', () => {
  it.each([
    ['no key', () => request(app).post('/ingest/v1/events').set('content-type', 'application/json').send('{}')],
    ['a wrong secret', () => ingest({ events: [] }, { secret: 'not-the-secret' })],
    ['an unknown key id', () => ingest({ events: [] }, { key: 'ik_unknownunknown' })],
    ['a stale timestamp (replay after 5 minutes)', () => ingest({ events: [] }, { t: Math.floor(Date.now() / 1000) - 600 })],
    ['a signature for another endpoint', () => ingest({ events: [] }, { path: '/ingest/v1/blocklist' })],
  ])('refuses %s', async (_n, call) => {
    const res = await call();
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHENTICATED');
  });

  it('refuses a tampered body (signed one thing, sent another)', async () => {
    const sig = signRequest(secret, 'POST', '/ingest/v1/events', '{"events":[]}');
    const res = await request(app).post('/ingest/v1/events').set('x-sentinel-key', keyId).set('x-sentinel-signature', sig).send('{"events":[],"traffic":[]}');
    expect(res.status).toBe(401);
  });

  it('validates the batch strictly; an empty batch is a heartbeat', async () => {
    expect((await ingest({ events: [{ ...ev('auth.login_failed'), admin: true }] })).status).toBe(400);
    expect((await ingest({ events: [ev('Not A Category')] })).status).toBe(400);
    expect((await ingest('{"events": [')).status).toBe(400);
    const hb = await ingest({ events: [] });
    expect(hb.body.data).toEqual({ accepted: 0, duplicates: 0, dropped: 0, alerts: 0 });
    const { rows } = await pool.query('select last_ingest_at from monitored_applications where slug = $1', [APP]);
    expect(rows[0].last_ingest_at).not.toBeNull();
  });

  it('dedupes by event id, redacts credentials, clamps future times, drops week-old events', async () => {
    const e1 = ev('auth.login_succeeded', { severity: 'info', userRef: 'u-1', details: { password: 'hunter2', nested: { token: 't' }, accountKey: 'k1', ok: 1 } });
    const future = ev('auth.login_succeeded', { severity: 'info', occurredAt: new Date(Date.now() + 3_600_000).toISOString() });
    const old = ev('auth.login_succeeded', { severity: 'info', occurredAt: new Date(Date.now() - 8 * 86_400_000).toISOString() });
    expect(await send([e1, future, old])).toMatchObject({ accepted: 2, duplicates: 0, dropped: 1 });
    expect(await send([e1])).toMatchObject({ accepted: 0, duplicates: 1 });
    const stored = (await pool.query('select details, occurred_at from security_events where event_id = $1', [e1.id])).rows[0];
    expect(stored.details).toEqual({ password: '[redacted]', nested: { token: '[redacted]' }, accountKey: 'k1', ok: 1 });
    const f = (await pool.query('select occurred_at, received_at from security_events where event_id = $1', [future.id])).rows[0];
    expect(new Date(f.occurred_at).getTime()).toBeLessThanOrEqual(new Date(f.received_at).getTime() + 1000);
  });
});

describe('detection: brute force, spraying, account under attack', () => {
  it('more than 10 failed sign-ins from one IP in 5 minutes → one high alert, repeats add to it, one email', async () => {
    const ip = '203.0.113.10';
    await send(Array.from({ length: 10 }, (_, i) => failedLogin(ip, `acct-${i % 2}`)));
    expect(await alertsFor('brute_force_ip', ip)).toHaveLength(0); // 10 is not "more than 10"
    const out = await send([failedLogin(ip, 'acct-0')]);
    expect(out.alerts).toBe(1);
    await send([failedLogin(ip), failedLogin(ip), failedLogin(ip)]);
    const [a, ...rest] = await alertsFor('brute_force_ip', ip);
    expect(rest).toHaveLength(0);
    expect(a).toMatchObject({ severity: 'high', status: 'open', occurrences: 14, classification: 'suspicious' });
    // The reason is refreshed with each repeat: it states the current evidence.
    expect(a.detection_reason).toMatch(/14 auth\.login_failed events for 203\.0\.113\.10 within 5 min \(threshold 11\)/);
    expect((await pool.query('select count(*)::int as n from alert_events where alert_id = $1', [a.id])).rows[0].n).toBe(4);
    // Both developers get high alerts by default: one email each, not one per repeat.
    const mailed = await eventually(
      async () => (await pool.query("select admin_id from notification_log where alert_id = $1 and status = 'sent'", [a.id])).rows,
      (rows) => rows.length >= 2,
    );
    expect(mailed).toHaveLength(2);
    await new Promise((r) => setTimeout(r, 200));
    const bf = mails.filter((m) => m.subject.includes('203.0.113.10'));
    expect(bf.map((m) => m.to.email).sort()).toEqual(['analyst@sec.dev', 'owner@sec.dev']);
    expect(bf[0]!.subject).toMatch(/^\[Sentinel\] HIGH: /);
    const ipRow = (await pool.query("select risk_score::float8 as r, event_count from suspicious_ips where ip = $1", [ip])).rows[0];
    expect(ipRow.event_count).toBe(14);
    expect(ipRow.r).toBeGreaterThanOrEqual(24); // 14 × 1 (low) + 10 for the alert
  });

  it('password spraying: one IP failing against 5 different accounts', async () => {
    await send(['a', 'b', 'c', 'd'].map((acct) => failedLogin('198.51.100.7', `spray-${acct}`)));
    expect(await alertsFor('password_spraying', '198.51.100.7')).toHaveLength(0);
    await send([failedLogin('198.51.100.7', 'spray-e')]);
    expect(await alertsFor('password_spraying', '198.51.100.7')).toMatchObject([{ severity: 'high' }]);
  });

  it('account under attack: 10 failures for one account from at least 3 IPs', async () => {
    const two = Array.from({ length: 10 }, (_, i) => failedLogin(`192.0.2.${(i % 2) + 1}`, 'acct-two-ips'));
    await send(two);
    expect(await alertsFor('account_under_attack', 'acct-two-ips')).toHaveLength(0);
    const three = Array.from({ length: 10 }, (_, i) => failedLogin(`192.0.2.${(i % 3) + 11}`, 'acct-three-ips'));
    await send(three);
    const [a] = await alertsFor('account_under_attack', 'acct-three-ips');
    expect(a.detection_reason).toMatch(/from 3 IP addresses/);
  });
});

describe('detection: authorisation, escalation, new IPs, traffic', () => {
  it('a member refused on an admin API → medium; 3 within 10 minutes → escalates to high (and is emailed then)', async () => {
    const denied = (path: string) =>
      ev('authz.denied', { severity: 'medium', sourceIp: '203.0.113.20', userRef: 'student-42', actorRole: 'student', route: path, method: 'GET', statusCode: 403 });
    await send([denied('/api/v1/bookings/:bookingId')]); // not an admin route: this rule ignores it
    expect(await alertsFor('member_admin_api', 'student-42')).toHaveLength(0);
    await send([denied('/api/v1/admin/users')]);
    const [first] = await alertsFor('member_admin_api', 'student-42');
    expect(first.severity).toBe('medium');
    expect(mails.filter((m) => m.subject.includes('student-42'))).toHaveLength(0); // medium: below the default email level
    await send([denied('/api/v1/admin/settings'), denied('/api/v1/admin/audit-logs')]);
    const [escalated] = await alertsFor('member_admin_api', 'student-42');
    expect(escalated).toMatchObject({ id: first.id, severity: 'high' });
    // Emailed once on escalation, to each developer whose preference covers high.
    await eventually(async () => mails.filter((m) => m.subject.includes('student-42')).length, (n) => n >= 2);
    await new Promise((r) => setTimeout(r, 200));
    expect(mails.filter((m) => m.subject.includes('student-42')).map((m) => m.to.email).sort()).toEqual(['analyst@sec.dev', 'owner@sec.dev']);
  });

  it('a Super Admin signing in from a never-seen IP (the very first sign-in is not "new")', async () => {
    const login = (ip: string) => ev('auth.login_succeeded', { severity: 'info', sourceIp: ip, userRef: 'admin-1', actorRole: 'super_admin' });
    await send([login('192.0.2.100')]);
    await send([login('192.0.2.100')]);
    expect(await alertsFor('admin_new_ip')).toHaveLength(0);
    await send([login('192.0.2.200')]);
    const [a] = await alertsFor('admin_new_ip');
    expect(a).toMatchObject({ severity: 'medium', group_key: 'admin-1' });
    expect(a.detection_reason).toMatch(/192\.0\.2\.200, an address not seen for this account/);
  });

  it('a traffic spike against the previous hour (baseline counts are overwritten on replay, not added)', async () => {
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    const baseline = Array.from({ length: 30 }, (_, i) => ({ minute: new Date(now - (31 - i) * 60_000).toISOString(), requests: 20 }));
    expect((await ingest({ traffic: baseline })).status).toBe(200);
    expect((await ingest({ traffic: baseline })).status).toBe(200); // replay
    const sum = (await pool.query('select sum(requests)::int as n from traffic_minutes')).rows[0].n;
    expect(sum).toBe(600);
    await ingest({ traffic: [{ minute: new Date(now - 60_000).toISOString(), requests: 250 }] }); // below min_rpm 300
    expect(await alertsFor('traffic_spike')).toHaveLength(0);
    await ingest({ traffic: [{ minute: new Date(now).toISOString(), requests: 900, status4xx: 600 }] });
    const [a] = await alertsFor('traffic_spike');
    expect(a.detection_reason).toMatch(/900 requests .* median of the previous hour \(20\)/);
  });
});

describe('triage: false positives quieten, resolved alerts reopen on new activity', () => {
  it('false positive → quiet for the rule cooldown; afterwards a new alert', async () => {
    const ip = '203.0.113.30';
    await send(Array.from({ length: 11 }, () => failedLogin(ip)));
    const [a] = await alertsFor('brute_force_ip', ip);
    const fp = await analystB.post(`/api/security/alerts/${a.id}`, {}); // wrong method
    expect(fp.status).toBe(404);
    const patched = await analystB.agent
      .patch(`/api/security/alerts/${a.id}?app=${APP}`)
      .set('origin', 'http://localhost:5180')
      .set('x-requested-with', 'sentinel')
      .send({ status: 'false_positive', note: 'load test from the lab' });
    expect(patched.status, JSON.stringify(patched.body)).toBe(200);
    expect(patched.body.data).toMatchObject({ status: 'false_positive', resolvedBy: 'analyst@sec.dev' });
    await send(Array.from({ length: 11 }, () => failedLogin(ip)));
    expect(await alertsFor('brute_force_ip', ip)).toHaveLength(1);
    await pool.query("update security_alerts set resolved_at = now() - interval '2 hours' where id = $1", [a.id]);
    await send([failedLogin(ip)]);
    expect(await alertsFor('brute_force_ip', ip)).toHaveLength(2);
    const audit = await pool.query("select details from audit_logs where action = 'alert.status_changed' and target_id = $1", [a.id]);
    expect(audit.rows[0].details).toMatchObject({ from: 'open', to: 'false_positive', note: 'load test from the lab' });
  });

  it('resolved → the next match opens a new alert straight away', async () => {
    const ip = '203.0.113.31';
    await send(Array.from({ length: 11 }, () => failedLogin(ip)));
    const [a] = await alertsFor('brute_force_ip', ip);
    await pool.query("update security_alerts set status = 'resolved', resolved_at = now() where id = $1", [a.id]);
    await send([failedLogin(ip)]);
    expect(await alertsFor('brute_force_ip', ip)).toHaveLength(2);
  });
});

describe('blocks and the allowlist', () => {
  it('rules are tuned by owners only, after a fresh confirmation', async () => {
    const patch = (b: typeof ownerB, body: object) =>
      b.agent.patch('/api/security/rules/brute_force_ip').set('origin', 'http://localhost:5180').set('x-requested-with', 'sentinel').send(body);
    expect((await patch(analystB, { autoBlock: true })).body.error.code).toBe('FORBIDDEN');
    expect((await patch(ownerB, { autoBlock: true })).body.error.code).toBe('REAUTH_REQUIRED');
    await reauth(ownerB, owner);
    expect((await patch(ownerB, { threshold: 0 })).status).toBe(400);
    const ok = await patch(ownerB, { autoBlock: true, blockSeconds: 600 });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.data).toMatchObject({ autoBlock: true, blockSeconds: 600 });
    const audit = await pool.query("select details from audit_logs where action = 'rule.updated' order by id desc limit 1");
    expect(audit.rows[0].details).toMatchObject({ autoBlock: { from: false, to: true } });
  });

  it('auto-blocks the attacking IP, never an allowlisted one; CampusHub pulls the active list', async () => {
    await reauth(ownerB, owner);
    const allow = await ownerB.post(`/api/security/allowlist?app=${APP}`, { cidr: '203.0.113.60', note: 'Campus lab gateway' });
    expect(allow.status, JSON.stringify(allow.body)).toBe(201);
    await send(Array.from({ length: 11 }, () => failedLogin('203.0.113.50')));
    await send(Array.from({ length: 11 }, () => failedLogin('203.0.113.60')));
    await send(Array.from({ length: 11 }, () => failedLogin('203.0.113.70', 'acct-default', { simulated: true })));
    const list = await blocklist();
    expect(list.status).toBe(200);
    const cidrs = list.body.data.blocks.map((b: { cidr: string }) => b.cidr);
    expect(cidrs).toContain('203.0.113.50/32');
    expect(cidrs).not.toContain('203.0.113.60/32');
    expect(cidrs).not.toContain('203.0.113.70/32'); // simulated attacks never block (or raise risk scores)
    expect((await pool.query("select 1 from suspicious_ips where ip = '203.0.113.70'")).rowCount).toBe(0);
    expect((await request(app).get('/ingest/v1/blocklist')).status).toBe(401); // unsigned
    const auto = (await pool.query("select source, rule_key from ip_blocks where cidr = '203.0.113.50/32'")).rows[0];
    expect(auto).toEqual({ source: 'rule', rule_key: 'brute_force_ip' });
    await pool.query("update detection_rules set auto_block = false where key = 'brute_force_ip'");
    invalidateRules();
  });

  it('manual blocks: owners only, confirmed, never too broad or over the allowlist, and liftable', async () => {
    const body = { cidr: '198.51.100.0/24', minutes: 60, reason: 'Scanner seen in logs' };
    expect((await analystB.post(`/api/security/blocks?app=${APP}`, body)).body.error.code).toBe('FORBIDDEN');
    await pool.query("update administrator_sessions set reauth_at = now() - interval '1 hour' where admin_id = $1", [owner.id]);
    expect((await ownerB.post(`/api/security/blocks?app=${APP}`, body)).body.error.code).toBe('REAUTH_REQUIRED');
    await reauth(ownerB, owner);
    expect((await ownerB.post(`/api/security/blocks?app=${APP}`, { ...body, cidr: '10.0.0.0/8' })).body.error.message).toMatch(/too broad/);
    expect((await ownerB.post(`/api/security/blocks?app=${APP}`, { ...body, cidr: 'not-an-ip' })).status).toBe(400);
    expect((await ownerB.post(`/api/security/blocks?app=${APP}`, { ...body, cidr: '203.0.113.0/24' })).body.error.message).toMatch(/allowlist/);
    const created = await ownerB.post(`/api/security/blocks?app=${APP}`, body);
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect(created.body.data).toMatchObject({ cidr: '198.51.100.0/24', source: 'manual', active: true });
    expect((await ownerB.post(`/api/security/blocks?app=${APP}`, body)).status).toBe(409);
    expect((await blocklist()).body.data.blocks.map((b: { cidr: string }) => b.cidr)).toContain('198.51.100.0/24');
    const lifted = await ownerB.post(`/api/security/blocks/${created.body.data.id}/lift?app=${APP}`);
    expect(lifted.body.data.active).toBe(false);
    expect((await blocklist()).body.data.blocks.map((b: { cidr: string }) => b.cidr)).not.toContain('198.51.100.0/24');
  });
});

describe('incidents', () => {
  it('group alerts, record notes, and keep the strong classifications for owners', async () => {
    const [bf] = await alertsFor('brute_force_ip', '203.0.113.10');
    const [spray] = await alertsFor('password_spraying', '198.51.100.7');
    const created = await analystB.post(`/api/security/incidents?app=${APP}`, {
      title: 'Credential attack on sign-in',
      severity: 'high',
      alertIds: [bf.id, spray.id],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const inc = created.body.data;
    expect(inc).toMatchObject({ reference: expect.stringMatching(/^INC-\d{4}$/), status: 'new', classification: 'suspicious', alertCount: 2 });
    expect((await analystB.post(`/api/security/incidents?app=${APP}`, { title: 'Dup', severity: 'low', alertIds: [bf.id] })).status).toBe(409);

    const patch = (b: typeof ownerB, body: object) =>
      b.agent.patch(`/api/security/incidents/${inc.id}?app=${APP}`).set('origin', 'http://localhost:5180').set('x-requested-with', 'sentinel').send(body);
    expect((await patch(analystB, { classification: 'compromise_confirmed' })).body.error.code).toBe('FORBIDDEN');
    expect((await patch(analystB, { status: 'investigating' })).body.data.status).toBe('investigating');
    const note = await analystB.post(`/api/security/incidents/${inc.id}/notes?app=${APP}`, { body: 'All attempts failed; no successful sign-in from these IPs.' });
    expect(note.body.data.notes).toHaveLength(1);
    const done = await patch(ownerB, { classification: 'policy_violation', status: 'resolved' });
    expect(done.body.data).toMatchObject({ status: 'resolved', classification: 'policy_violation' });
    expect(done.body.data.resolvedAt).not.toBeNull();
    const actions = (await pool.query("select action from audit_logs where target_id = $1 order by id", [inc.id])).rows.map((r) => r.action);
    expect(actions).toEqual(['incident.created', 'incident.updated', 'incident.note_added', 'incident.updated']);
  });
});

describe('dashboard reads', () => {
  it('overview: severity counts, active alerts, top endpoints, health derived from open alerts', async () => {
    const o = (await analystB.get(`/api/security/overview?app=${APP}&range=today`)).body.data;
    const db = (await pool.query("select count(*)::int as n from security_events where occurred_at >= date_trunc('day', now())")).rows[0].n;
    expect(o.events.total).toBe(db);
    expect(o.alerts.active).toBeGreaterThan(0);
    expect(o.alerts.openBySeverity.high).toBeGreaterThan(0);
    expect(o.health.status).toMatch(/warning|critical/);
    expect(o.health.reasons.join(' ')).toMatch(/open high alert/);
    expect(o.topEndpoints[0]).toMatchObject({ endpoint: '/api/auth/sign-in/email' });
    expect(o.incidents.resolved).toBe(1);
    expect(o.requests).toBeGreaterThanOrEqual(600);
  });

  it('timeline, event log filters, alert detail with evidence, suspicious IPs ranked by risk', async () => {
    const t = (await analystB.get(`/api/security/timeseries?app=${APP}&range=today`)).body.data;
    expect(t.points.reduce((n: number, p: { low: number }) => n + p.low, 0)).toBeGreaterThan(0);
    const ev1 = (await analystB.get(`/api/security/events?app=${APP}&range=today&ip=203.0.113.10&severity=low&pageSize=100`)).body;
    expect(ev1.meta.total).toBe(14);
    expect(ev1.data.every((e: { sourceIp: string }) => e.sourceIp === '203.0.113.10')).toBe(true);
    const net = (await analystB.get(`/api/security/events?app=${APP}&range=today&ip=192.0.2.0/24&pageSize=1`)).body.meta.total;
    expect(net).toBeGreaterThan(20);
    const [bf] = await alertsFor('brute_force_ip', '203.0.113.10');
    const detail = (await analystB.get(`/api/security/alerts/${bf.id}?app=${APP}`)).body.data;
    expect(detail.sampleEvents).toHaveLength(4);
    expect(detail.incident.reference).toMatch(/^INC-/);
    const ips = (await analystB.get(`/api/security/ips?app=${APP}&minScore=10`)).body.data;
    expect(ips[0].riskScore).toBeGreaterThanOrEqual(ips[ips.length - 1].riskScore);
    expect(ips.find((i: { ip: string }) => i.ip === '203.0.113.60')).toMatchObject({ allowlisted: true, blocked: false });
    const ipd = (await analystB.get(`/api/security/ips/203.0.113.50?app=${APP}`)).body.data;
    expect(ipd.blocks[0]).toMatchObject({ source: 'rule', active: true });
    expect((await request(app).get(`/api/security/overview?app=${APP}`)).status).toBe(401);
  });
});

describe('simulated attacks, live push, preferences, secret rotation', () => {
  it('simulated events raise a badge-marked alert but no email, and do not change the health status', async () => {
    const before = mails.length;
    await send(Array.from({ length: 11 }, () => failedLogin('203.0.113.77', 'acct-sim', { simulated: true })));
    const [a] = await alertsFor('brute_force_ip', '203.0.113.77');
    expect(a.simulated).toBe(true);
    await new Promise((r) => setTimeout(r, 300));
    expect(mails.length).toBe(before);
    expect((await pool.query('select count(*)::int as n from notification_log where alert_id = $1', [a.id])).rows[0].n).toBe(0);
  });

  it('real activity joining a simulated alert turns it real and is announced', async () => {
    const before = mails.length;
    await send([failedLogin('203.0.113.77', 'acct-sim')]); // same address, not simulated
    const [a] = await alertsFor('brute_force_ip', '203.0.113.77');
    expect(a.simulated).toBe(false);
    const sent = await eventually(
      async () => (await pool.query('select count(*)::int as n from notification_log where alert_id = $1', [a.id])).rows[0].n,
      (n) => n > 0,
    );
    expect(sent).toBeGreaterThan(0);
    expect(mails.length).toBeGreaterThan(before);
  });

  it('pushes a new alert to an open dashboard immediately (SSE)', async () => {
    const b = browser();
    await b.post('/api/auth/login', { email: owner.email, password: owner.password });
    await pool.query('update administrator_accounts set totp_last_step = 0 where id = $1', [owner.id]);
    const cookie = cookieOf(await b.post('/api/auth/mfa/verify', { code: nextCode(owner.secret!) }))!.split(';')[0]!;
    const server = app.listen(0);
    const { port } = server.address() as AddressInfo;
    try {
      const got = await new Promise<string>((resolve, reject) => {
        const req = http.get({ port, path: '/api/stream', headers: { cookie } }, (res) => {
          let buf = '';
          res.on('data', (chunk) => {
            buf += chunk;
            if (buf.includes('event: analytics') && !buf.includes('triggered')) {
              buf += 'triggered';
              void send(Array.from({ length: 11 }, () => failedLogin('203.0.113.88')));
            }
            if (buf.includes('event: alert')) {
              req.destroy();
              resolve(buf);
            }
          });
        });
        req.on('error', (e) => (/aborted|hang up/.test(e.message) ? undefined : reject(e)));
        setTimeout(() => reject(new Error('no alert event within 5 s')), 5000);
      });
      const data = JSON.parse(/event: alert\ndata: (.*)\n/.exec(got)![1]!);
      expect(data).toMatchObject({ severity: 'high', created: true, title: expect.stringMatching(/203\.0\.113\.88/) });
    } finally {
      server.close();
    }
  });

  it('each developer sets their own alert emails', async () => {
    const put = (body: object) => analystB.agent.put('/api/me/notifications').set('origin', 'http://localhost:5180').set('x-requested-with', 'sentinel').send(body);
    expect((await analystB.get('/api/me/notifications')).body.data).toMatchObject({ emailEnabled: true, minSeverity: 'high', quietHours: null });
    expect((await put({ emailEnabled: true, minSeverity: 'critical', quietHours: { start: '25:00', end: '07:00' } })).status).toBe(400);
    const ok = await put({ emailEnabled: true, minSeverity: 'critical', quietHours: { start: '22:00', end: '07:00' } });
    expect(ok.body.data).toMatchObject({ minSeverity: 'critical', quietHours: { start: '22:00', end: '07:00' } });
  });

  it('rotating the ingestion secret: owners only, shown once, the old secret stops working', async () => {
    expect((await analystB.post(`/api/apps/${APP}/rotate-secret`)).body.error.code).toBe('FORBIDDEN');
    await reauth(ownerB, owner);
    const res = await ownerB.post(`/api/apps/${APP}/rotate-secret`);
    expect(res.status).toBe(200);
    const { ingestKeyId, ingestSecret } = res.body.data;
    expect(ingestKeyId).toMatch(/^ik_/);
    expect((await ingest({ events: [] })).status).toBe(401); // old key + secret
    keyId = ingestKeyId;
    secret = ingestSecret;
    expect((await ingest({ events: [] })).status).toBe(200);
    const stored = (await pool.query('select ingest_secret from monitored_applications where slug = $1', [APP])).rows[0].ingest_secret;
    expect(stored).not.toContain(ingestSecret);
  });
});
