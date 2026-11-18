// Security scan reports: signed upload from the app's tooling, dashboard reads, append-only storage.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { pool } from '../../src/db/pool.js';
import { registerApp, rotateIngestSecret } from '../../src/modules/apps/apps.service.js';
import { signRequest } from '../../src/modules/ingest/signature.js';
import { app, closePool, createAdmin, resetDb, signedIn } from '../helpers.js';

const APP = 'reports-test';
let keyId: string;
let secret: string;
let viewer: Awaited<ReturnType<typeof signedIn>>;

const report = (over: Record<string, unknown> = {}) => ({
  source: 'campushub security:audit',
  environment: 'local',
  gitCommit: 'abc1234',
  startedAt: new Date(Date.now() - 60_000).toISOString(),
  finishedAt: new Date().toISOString(),
  summary: { pass: 2, fail: 1, warn: 0, info: 1, skip: 0 },
  sections: [
    {
      name: 'Static analysis',
      kind: 'static',
      summary: { pass: 2, fail: 1, warn: 0, info: 1, skip: 0 },
      checks: [
        { id: 'eval', title: 'Dynamic code execution: none found', status: 'pass' },
        { id: 'tls-off', title: 'TLS checks off', status: 'fail', location: 'backend/src/x.ts:3', detail: 'rejectUnauthorized: false' },
        { id: 'SAST-00', title: 'Files analysed', status: 'info', detail: '219 files' },
        { id: 'cors', title: 'CORS', status: 'pass' },
      ],
    },
  ],
  ...over,
});

function upload(body: object | string, opts: { secret?: string } = {}) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  return request(app)
    .post('/ingest/v1/reports')
    .set('x-sentinel-key', keyId)
    .set('x-sentinel-signature', signRequest(opts.secret ?? secret, 'POST', '/ingest/v1/reports', raw))
    .set('content-type', 'application/json')
    .send(raw);
}

beforeAll(async () => {
  await resetDb();
  await registerApp({ slug: APP, name: 'Reports Test App', origins: ['http://localhost:5173'] });
  const creds = (await rotateIngestSecret(APP))!;
  keyId = creds.ingestKeyId;
  secret = creds.ingestSecret;
  viewer = await signedIn(await createAdmin('analyst@reports.dev', { role: 'analyst' }));
});
afterAll(closePool);

describe('scan report upload', () => {
  it('is refused without a valid signature', async () => {
    expect((await request(app).post('/ingest/v1/reports').set('content-type', 'application/json').send(report())).status).toBe(401);
    expect((await upload(report(), { secret: 'not-the-secret' })).status).toBe(401);
  });

  it('validates the report', async () => {
    const bad = await upload(report({ environment: 'moon' }));
    expect(bad.status).toBe(400);
    expect((await upload(report({ sections: [] }))).status).toBe(400);
    expect((await upload('{not json')).status).toBe(400);
  });

  it('stores a signed report, and analysts can list and open it', async () => {
    const res = await upload(report());
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const id = res.body.data.id;

    const list = await viewer.get(`/api/security/reports?app=${APP}`);
    expect(list.status).toBe(200);
    expect(list.body.meta.total).toBe(1);
    expect(list.body.data[0]).toMatchObject({ id, environment: 'local', gitCommit: 'abc1234', summary: { fail: 1 } });
    expect(list.body.data[0].sections[0]).toEqual({ name: 'Static analysis', kind: 'static', summary: { pass: 2, fail: 1, warn: 0, info: 1, skip: 0 } });

    const one = await viewer.get(`/api/security/reports/${id}?app=${APP}`);
    expect(one.status).toBe(200);
    expect(one.body.data.sections[0].checks).toHaveLength(4);
    expect(one.body.data.sections[0].checks[1]).toMatchObject({ status: 'fail', location: 'backend/src/x.ts:3' });
  });

  it('is not readable without a dashboard session', async () => {
    expect((await request(app).get(`/api/security/reports?app=${APP}`)).status).toBe(401);
  });

  it('cuts over-long text instead of refusing the report', async () => {
    const long = report();
    long.sections[0]!.checks[0]!.title = 'x'.repeat(1000);
    const res = await upload(long);
    expect(res.status).toBe(201);
    const one = await viewer.get(`/api/security/reports/${res.body.data.id}?app=${APP}`);
    expect(one.body.data.sections[0].checks[0].title).toHaveLength(300);
  });

  it('refuses a report over 1 MB', async () => {
    const huge = report();
    huge.sections[0]!.checks = Array.from({ length: 1000 }, (_, i) => ({ id: `c${i}`, title: 'y'.repeat(300), status: 'info', detail: 'z'.repeat(800) }));
    const res = await upload(huge);
    expect(res.status).toBe(400);
    expect(res.body.error.message).toBe('Request too large');
  });

  it('is append-only, for the app role and the owner alike', async () => {
    const err = await pool.query("update scan_reports set environment = 'production'").catch((e) => e);
    expect(err.code).toBe('SA001');
    const del = await pool.query('delete from scan_reports').catch((e) => e);
    expect(del.code).toBe('SA001');
  });
});
