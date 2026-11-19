// Visitor analytics: the /collect beacon (sessions, privacy, rejection rules), the dashboard read API, live stream.
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { pool } from '../../src/db/pool.js';
import { registerApp } from '../../src/modules/apps/apps.service.js';
import { app, closePool, cookieOf, createAdmin, nextCode, browser, resetDb, signedIn } from '../helpers.js';

const SITE = 'http://localhost:5173';
const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
let siteKey: string;

function beacon(body: object | string, opts: { origin?: string | null; ua?: string; headers?: Record<string, string> } = {}) {
  let r = request(app).post('/collect').set('content-type', 'text/plain;charset=UTF-8').set('user-agent', opts.ua ?? CHROME);
  if (opts.origin !== null) r = r.set('origin', opts.origin ?? SITE);
  for (const [k, v] of Object.entries(opts.headers ?? {})) r = r.set(k, v);
  return r.send(typeof body === 'string' ? body : JSON.stringify(body));
}
const hit = (v: string, p: string, extra: object = {}) => ({ k: siteKey, v, t: 'pageview', p, ...extra });
const sessionsOf = async (visitorKey: string) =>
  (
    await pool.query(
      `select s.* from analytics_sessions s join analytics_visitors v on v.id = s.visitor_id where v.visitor_key = $1 order by s.started_at`,
      [visitorKey],
    )
  ).rows;

beforeAll(async () => {
  await resetDb();
  const out = await registerApp({ slug: 'campushub-test', name: 'CampusHub (tests)', origins: [SITE] });
  siteKey = out.app.siteKey;
});
afterAll(closePool);

describe('collect: sessions are built on the server', () => {
  const visitor = randomUUID();

  it('a first page view creates the visitor, a session and the page view', async () => {
    const res = await beacon(
      hit(visitor, '/bookings/3f2b6c1e-9a4d-4e8f-b1c2-0d9e8f7a6b5c?token=secret#x', { r: 'https://www.google.com/search?q=hall', w: 390 }),
      { ua: IPHONE },
    );
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBeUndefined(); // the page can't read the answer
    // …but the browser must be allowed to receive it: same-origin here logged ERR_BLOCKED_BY_RESPONSE on every page.
    expect(res.headers['cross-origin-resource-policy']).toBe('cross-origin');
    expect(res.headers['set-cookie']).toBeUndefined();
    const [s] = await sessionsOf(visitor);
    expect(s).toMatchObject({
      is_new_visitor: true,
      entry_path: '/bookings/:id',
      page_views: 1,
      referrer_host: 'google.com',
      referrer_source: 'search',
      device_type: 'mobile',
      browser: 'Safari',
      os: 'iOS',
      viewport: 'xs',
    });
    const paths = (await pool.query('select path from analytics_events where session_id = $1', [s.id])).rows.map((r) => r.path);
    expect(paths).toEqual(['/bookings/:id']); // no query string, no record id, no token
  });

  it('more page views within 30 minutes extend the same session; heartbeats only keep it alive', async () => {
    await beacon(hit(visitor, '/venues'));
    await beacon({ ...hit(visitor, '/venues'), t: 'heartbeat' });
    await beacon(hit(visitor, '/complaints'));
    const all = await sessionsOf(visitor);
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ page_views: 3, entry_path: '/bookings/:id', exit_path: '/complaints' });
  });

  it('after 30 idle minutes the next visit is a new session of a returning visitor', async () => {
    await pool.query(
      `update analytics_sessions set started_at = now() - interval '2 hours', last_activity_at = now() - interval '31 minutes'
        where visitor_id = (select id from analytics_visitors where visitor_key = $1)`,
      [visitor],
    );
    await beacon(hit(visitor, '/dashboard'));
    const all = await sessionsOf(visitor);
    expect(all).toHaveLength(2);
    expect(all[1]).toMatchObject({ is_new_visitor: false, entry_path: '/dashboard', referrer_source: 'direct' });
    const v = (await pool.query('select sessions_count from analytics_visitors where visitor_key = $1', [visitor])).rows[0];
    expect(v.sessions_count).toBe(2);
  });

  it('a heartbeat with no open session (tab came back after a long pause) starts one', async () => {
    const v2 = randomUUID();
    await beacon({ ...hit(v2, '/notifications'), t: 'heartbeat' });
    expect(await sessionsOf(v2)).toMatchObject([{ page_views: 1, entry_path: '/notifications' }]);
  });

  it('two tabs hitting at once still make one session', async () => {
    const v3 = randomUUID();
    await Promise.all([beacon(hit(v3, '/a')), beacon(hit(v3, '/b')), beacon(hit(v3, '/c'))]);
    const all = await sessionsOf(v3);
    expect(all).toHaveLength(1);
    expect(all[0].page_views).toBe(3);
  });
});

describe('collect: what is refused or dropped', () => {
  const v = randomUUID();
  it.each([
    ['another origin', () => beacon(hit(v, '/x'), { origin: 'https://evil.example' }), 403],
    ['no Origin header (not a browser beacon)', () => beacon(hit(v, '/x'), { origin: null }), 403],
    ['an unknown site key', () => beacon({ ...hit(v, '/x'), k: 'sk_unknownunknownunknown' }), 403],
    ['malformed JSON', () => beacon('{"k": nope'), 400],
    ['an unexpected field', () => beacon({ ...hit(v, '/x'), admin: true }), 400],
    ['a visitor id that is not a UUID', () => beacon({ ...hit(v, '/x'), v: "1' or '1'='1" }), 400],
    ['a body over 2 KB', () => beacon({ ...hit(v, '/x'), r: `https://x.example/${'a'.repeat(2100)}` }), 400],
  ])('refuses %s', async (_name, send, status) => {
    expect((await send()).status).toBe(status);
  });

  it.each([
    ['a headless browser', { ua: 'Mozilla/5.0 HeadlessChrome/131.0.0.0 Safari/537.36' }],
    ['a crawler', { ua: 'Mozilla/5.0 (compatible; Googlebot/2.1)' }],
    ['Do-Not-Track', { headers: { dnt: '1' } }],
    ['Global Privacy Control', { headers: { 'sec-gpc': '1' } }],
  ])('accepts but stores nothing for %s', async (_name, opts) => {
    const quiet = randomUUID();
    expect((await beacon(hit(quiet, '/x'), opts)).status).toBe(204);
    expect(await sessionsOf(quiet)).toHaveLength(0);
  });

  it('a session from an inactive app is refused', async () => {
    await pool.query("update monitored_applications set is_active = false where slug = 'campushub-test'");
    const { clearAppCache } = await import('../../src/modules/apps/apps.service.js');
    clearAppCache();
    expect((await beacon(hit(randomUUID(), '/x'))).status).toBe(403);
    await pool.query("update monitored_applications set is_active = true where slug = 'campushub-test'");
    clearAppCache();
  });
});

describe('collect: IP privacy and location', () => {
  it('keeps the /24 network and a keyed hash, never the full address', async () => {
    app.set('trust proxy', 1);
    try {
      const v = randomUUID();
      expect((await beacon(hit(v, '/'), { headers: { 'x-forwarded-for': '8.8.8.8' } })).status).toBe(204);
      const [s] = await sessionsOf(v);
      expect(s.ip_truncated).toBe('8.8.8.0');
      expect(s.ip_hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(JSON.stringify(s)).not.toContain('8.8.8.8');
      if (fs.existsSync(path.resolve(process.cwd(), '.geoip', 'dbip-country-lite.mmdb'))) expect(s.country).toBe('US');
    } finally {
      app.set('trust proxy', 0);
    }
  });
});

describe('dashboard read API', () => {
  let dev: Awaited<ReturnType<typeof signedIn>>;
  beforeAll(async () => {
    dev = await signedIn(await createAdmin('analytics@sentinel.dev', { role: 'analyst' }));
  });

  it('needs a signed-in developer', async () => {
    expect((await request(app).get('/api/analytics/overview')).status).toBe(401);
    expect((await request(app).get('/api/analytics/sessions')).status).toBe(401);
  });

  it('overview: visitors, new vs returning, sessions, page views, bounce rate, online now', async () => {
    const res = await dev.get('/api/analytics/overview?app=campushub-test&range=today');
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const o = res.body.data;
    const db = (
      await pool.query(
        `select count(*)::int as sessions, count(distinct visitor_id)::int as visitors,
                count(distinct visitor_id) filter (where is_new_visitor)::int as new_visitors
           from analytics_sessions where started_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC'`,
      )
    ).rows[0];
    expect(o).toMatchObject({ sessions: db.sessions, visitors: db.visitors, newVisitors: db.new_visitors, returningVisitors: db.visitors - db.new_visitors });
    expect(o.pageViews).toBeGreaterThanOrEqual(o.sessions);
    expect(o.online).toBeGreaterThan(0);
    expect(o.bounceRate).toBeGreaterThanOrEqual(0);
    expect(o.bounceRate).toBeLessThanOrEqual(100);
    expect(o.visitorsToday).toBeLessThanOrEqual(o.visitorsThisWeek);
    expect(o.visitorsThisWeek).toBeLessThanOrEqual(o.visitorsThisMonth);
  });

  it('timeseries: hourly for today, daily for 7 days, with empty buckets filled', async () => {
    const today = (await dev.get('/api/analytics/timeseries?app=campushub-test&range=today')).body.data;
    expect(today.granularity).toBe('hour');
    expect(today.points.length).toBe(new Date().getUTCHours() + 1);
    const week = (await dev.get('/api/analytics/timeseries?app=campushub-test&range=7d')).body.data;
    expect(week.granularity).toBe('day');
    expect(week.points).toHaveLength(7);
    expect(week.points.reduce((n: number, p: { sessions: number }) => n + p.sessions, 0)).toBeGreaterThan(0);
  });

  it('hour of day and breakdowns', async () => {
    const hours = (await dev.get('/api/analytics/hours?app=campushub-test&range=7d')).body.data.hours;
    expect(hours).toHaveLength(24);
    const devices = (await dev.get('/api/analytics/breakdown?app=campushub-test&range=7d&dimension=device')).body.data.rows;
    expect(devices.map((d: { key: string }) => d.key)).toEqual(expect.arrayContaining(['desktop', 'mobile']));
    const pages = (await dev.get('/api/analytics/breakdown?app=campushub-test&range=7d&dimension=page&limit=50')).body.data.rows;
    expect(pages.find((p: { key: string }) => p.key === '/bookings/:id')).toMatchObject({ pageViews: 1 });
    const sources = (await dev.get('/api/analytics/breakdown?app=campushub-test&range=7d&dimension=source')).body.data.rows;
    expect(sources.map((d: { key: string }) => d.key)).toEqual(expect.arrayContaining(['search', 'direct']));
    expect((await dev.get('/api/analytics/breakdown?app=campushub-test&dimension=password_hash')).status).toBe(400);
    expect((await dev.get('/api/analytics/breakdown?app=campushub-test&dimension=toString')).status).toBe(400);
  });

  it('sessions: live list and one session with its pages; IPs shown as networks only', async () => {
    const live = await dev.get('/api/analytics/sessions?app=campushub-test&live=true&pageSize=100');
    expect(live.body.data.length).toBeGreaterThan(0);
    expect(live.body.data.every((s: { online: boolean }) => s.online)).toBe(true);
    // The iPhone session was aged past 30 minutes above, so it is in the date range but no longer live.
    const week = (await dev.get('/api/analytics/sessions?app=campushub-test&range=7d&pageSize=100')).body.data;
    const iphone = week.find((s: { device: string; entryPath: string }) => s.device === 'mobile' && s.entryPath === '/bookings/:id');
    expect(iphone).toMatchObject({ browser: 'Safari 18', os: 'iOS', viewport: 'xs', referrer: { source: 'search' }, online: false });
    expect(live.body.data.find((s: { id: string }) => s.id === iphone.id)).toBeUndefined();
    expect(iphone.visitor.id).toHaveLength(8);
    const google = week.find((s: { ip: string | null }) => s.ip?.startsWith('8.8.8'));
    expect(google.ip).toBe('8.8.8.0/24');
    const detail = (await dev.get(`/api/analytics/sessions/${iphone.id}?app=campushub-test`)).body.data;
    expect(detail.pages.map((p: { path: string }) => p.path)).toEqual(['/bookings/:id', '/venues', '/complaints']);
    expect((await dev.get(`/api/analytics/sessions/${randomUUID()}?app=campushub-test`)).status).toBe(404);
  });

  it('validates custom ranges', async () => {
    expect((await dev.get('/api/analytics/overview?app=campushub-test&range=custom')).status).toBe(400);
    expect((await dev.get('/api/analytics/overview?app=campushub-test&range=custom&from=2026-11-10&to=2026-11-01')).status).toBe(400);
    expect((await dev.get('/api/analytics/overview?app=campushub-test&range=custom&from=2024-01-01&to=2026-11-01')).status).toBe(400);
    const ok = await dev.get('/api/analytics/overview?app=campushub-test&range=custom&from=2026-11-01&to=2026-11-30');
    expect(ok.status).toBe(200);
    expect(ok.body.data.range.from).toBe('2026-11-01T00:00:00.000Z');
  });

  it('lists the monitored apps (no secrets)', async () => {
    const res = await dev.get('/api/apps');
    expect(res.body.data.find((a: { slug: string }) => a.slug === 'campushub-test')).toMatchObject({ allowedOrigins: [SITE] });
    expect(JSON.stringify(res.body)).not.toMatch(/ingest|secret|site_?key/i);
  });
});

describe('live stream (Server-Sent Events)', () => {
  it('streams a summary to a signed-in developer and refuses everyone else', async () => {
    const owner = await createAdmin('stream@sentinel.dev');
    const b = browser();
    await b.post('/api/auth/login', { email: owner.email, password: owner.password });
    const verified = await b.post('/api/auth/mfa/verify', { code: nextCode(owner.secret!) });
    const cookie = cookieOf(verified)!.split(';')[0]!;

    const server = app.listen(0);
    const { port } = server.address() as AddressInfo;
    const read = (headers: Record<string, string>) =>
      new Promise<{ status: number; type: string | undefined; first: string }>((resolve, reject) => {
        const req = http.get({ port, path: '/api/stream', headers }, (res) => {
          if (res.statusCode !== 200) {
            res.resume();
            return resolve({ status: res.statusCode!, type: res.headers['content-type'], first: '' });
          }
          let buf = '';
          res.on('data', (chunk) => {
            buf += chunk;
            if (buf.includes('event: analytics')) {
              req.destroy();
              resolve({ status: 200, type: res.headers['content-type'], first: buf });
            }
          });
        });
        req.on('error', (e) => (e.message.includes('aborted') || e.message.includes('socket hang up') ? undefined : reject(e)));
      });
    try {
      expect((await read({})).status).toBe(401);
      const ok = await read({ cookie });
      expect(ok.status).toBe(200);
      expect(ok.type).toMatch(/text\/event-stream/);
      const data = JSON.parse(/event: analytics\ndata: (.*)\n/.exec(ok.first)![1]!);
      expect(data.apps['campushub-test']).toMatchObject({ online: expect.any(Number), pageViews5m: expect.any(Number) });
    } finally {
      server.close();
    }
  });
});
