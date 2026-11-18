// /api routes and their guards. Thin handlers: validation → service → JSON.
import { Router, type Express, type Response } from 'express';
import { z } from 'zod';
import { config } from './config/env.js';
import { appError } from './errors/app-error.js';
import { geoipInfo } from './lib/geoip.js';
import { limits } from './middleware/rate-limiters.js';
import { parseCookies, requireSameOrigin, validate } from './middleware/basics.js';
import { loadSession, requireRecentReauth, requireRole, requireSession } from './middleware/session.js';
import { actorOf, listAudit, writeAudit } from './modules/audit/audit.service.js';
import { pool } from './db/pool.js';
import { getPreferences, setPreferences } from './modules/notify/notifier.js';
import { securityRouter } from './modules/security/security.routes.js';
import * as auth from './modules/auth/auth.service.js';
import { clearSessionCookie, findSession, setSessionCookie } from './modules/auth/sessions.js';
import * as admins from './modules/admins/admins.service.js';
import * as analytics from './modules/analytics/analytics.service.js';
import { liveHub } from './modules/analytics/live.js';
import { listApps, resolveApp, rotateIngestSecret } from './modules/apps/apps.service.js';

const email = z.string().trim().toLowerCase().max(254).pipe(z.email('Enter a valid email'));
const code = z.strictObject({
  code: z
    .string()
    .trim()
    .transform((v) => v.replace(/\s+/g, ''))
    .pipe(z.string().regex(/^(\d{6}|[A-Za-z0-9]{5}-?[A-Za-z0-9]{5})$/, 'Enter the 6-digit code or a recovery code')),
});
const idParam = z.object({ id: z.uuid() });

function authRouter() {
  const r = Router();
  r.post('/login', limits.login, validate({ body: z.strictObject({ email, password: z.string().min(1).max(128) }) }), async (req, res) => {
    const { token, state } = await auth.login(req.valid.body, actorOf(req));
    setSessionCookie(res, token);
    res.json({ data: { state } });
  });

  r.get('/session', requireSession('password_change', 'mfa_enroll', 'mfa_verify', 'active'), (req, res) => {
    res.json({ data: auth.sessionView(req.session!, req.admin!, config.REAUTH_MINUTES) });
  });

  // Each step answers with the next state; reaching 'active' replaces the cookie (new token).
  const stepReply = (res: Response, out: { state: string; token: string | null }, extra: object = {}) => {
    if (out.token) setSessionCookie(res, out.token);
    res.json({ data: { state: out.state, ...extra } });
  };

  r.post(
    '/password',
    limits.sensitive,
    requireSession('password_change', 'active'),
    validate({ body: z.strictObject({ currentPassword: z.string().min(1).max(128), newPassword: z.string().min(1).max(128) }) }),
    async (req, res) => stepReply(res, await auth.changePassword(req.session!, req.admin!, req.valid.body, actorOf(req))),
  );
  r.post('/mfa/setup', limits.mfa, requireSession('mfa_enroll'), async (req, res) => {
    res.json({ data: await auth.mfaSetup(req.admin!, actorOf(req)) });
  });
  r.post('/mfa/enable', limits.mfa, requireSession('mfa_enroll'), validate({ body: code }), async (req, res) => {
    const out = await auth.mfaEnable(req.session!, req.admin!, req.valid.body.code, actorOf(req));
    stepReply(res, out, { recoveryCodes: out.recoveryCodes });
  });
  r.post('/mfa/verify', limits.mfa, requireSession('mfa_verify'), validate({ body: code }), async (req, res) => {
    const out = await auth.mfaVerify(req.session!, req.admin!, req.valid.body.code, actorOf(req));
    stepReply(res, out, { usedRecoveryCode: out.usedRecoveryCode, recoveryCodesLeft: out.recoveryCodesLeft });
  });
  r.post(
    '/reauth',
    limits.mfa,
    requireSession('active'),
    validate({ body: z.strictObject({ password: z.string().min(1).max(128), code: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code') }) }),
    async (req, res) => {
      await auth.reauth(req.session!, req.admin!, req.valid.body, actorOf(req));
      res.status(204).end();
    },
  );
  r.post('/logout', requireSession('password_change', 'mfa_enroll', 'mfa_verify', 'active'), async (req, res) => {
    await auth.logout(req.session!, actorOf(req));
    clearSessionCookie(res);
    res.status(204).end();
  });
  return r;
}

function adminsRouter() {
  const r = Router();
  r.use(requireSession('active'), requireRole('owner'));
  r.get('/', async (_req, res) => void res.json({ data: await admins.listAdmins() }));
  r.post(
    '/',
    limits.sensitive,
    requireRecentReauth,
    validate({
      body: z.strictObject({
        email,
        displayName: z.string().trim().min(2).max(100),
        role: z.enum(['owner', 'analyst']),
      }),
    }),
    async (req, res) => void res.status(201).json({ data: await admins.createAdmin(actorOf(req), req.valid.body) }),
  );
  r.post('/:id/deactivate', limits.sensitive, requireRecentReauth, validate({ params: idParam }), async (req, res) => {
    res.json({ data: await admins.deactivateAdmin(actorOf(req), req.valid.params.id) });
  });
  r.post('/:id/reset-mfa', limits.sensitive, requireRecentReauth, validate({ params: idParam }), async (req, res) => {
    res.json({ data: await admins.resetAdminMfa(actorOf(req), req.valid.params.id) });
  });
  return r;
}

function auditRouter() {
  const r = Router();
  r.use(requireSession('active'));
  const query = z.strictObject({
    page: z.coerce.number().int().min(1).max(10_000).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(50),
    action: z.string().regex(/^[a-z][a-z_]*\.[a-z][a-z_]*$/).optional(),
    outcome: z.enum(['success', 'failure']).optional(),
    adminId: z.uuid().optional(),
    from: z.iso.datetime({ offset: true }).optional(),
    to: z.iso.datetime({ offset: true }).optional(),
  });
  r.get('/', validate({ query }), async (req, res) => void res.json(await listAudit(req.valid.query)));
  return r;
}

const rangeQuery = {
  app: z.string().regex(/^[a-z][a-z0-9-]{1,40}$/).optional(),
  range: z.enum(analytics.RANGES).default('7d'),
  from: z.iso.date().optional(),
  to: z.iso.date().optional(),
};

/** The app and time range of an analytics request (404 when no app is registered yet). */
async function scope(q: { app?: string } & analytics.RangeQuery) {
  const target = await resolveApp(q.app);
  if (!target) throw appError('NOT_FOUND', 'No monitored application is registered yet (npm run app:register).');
  return { app: target, range: await analytics.resolveRange(q) };
}

function analyticsRouter() {
  const r = Router();
  r.use(requireSession('active'));
  r.get('/overview', validate({ query: z.strictObject(rangeQuery) }), async (req, res) => {
    const s = await scope(req.valid.query);
    res.json({ data: await analytics.overview(s.app, s.range) });
  });
  r.get('/timeseries', validate({ query: z.strictObject(rangeQuery) }), async (req, res) => {
    const s = await scope(req.valid.query);
    res.json({ data: await analytics.timeseries(s.app, s.range) });
  });
  r.get('/hours', validate({ query: z.strictObject(rangeQuery) }), async (req, res) => {
    const s = await scope(req.valid.query);
    res.json({ data: await analytics.hourOfDay(s.app, s.range) });
  });
  r.get(
    '/breakdown',
    validate({ query: z.strictObject({ ...rangeQuery, dimension: z.enum(analytics.DIMENSIONS), limit: z.coerce.number().int().min(1).max(50).default(10) }) }),
    async (req, res) => {
      const s = await scope(req.valid.query);
      res.json({ data: await analytics.breakdown(s.app, s.range, req.valid.query.dimension, req.valid.query.limit) });
    },
  );
  r.get(
    '/sessions',
    validate({
      query: z.strictObject({
        ...rangeQuery,
        live: z.enum(['true', 'false']).default('false').transform((v) => v === 'true'),
        page: z.coerce.number().int().min(1).max(10_000).default(1),
        pageSize: z.coerce.number().int().min(1).max(100).default(25),
        country: z.string().regex(/^[A-Z]{2}$/).optional(),
        device: z.enum(['desktop', 'mobile', 'tablet', 'unknown']).optional(),
      }),
    }),
    async (req, res) => {
      const s = await scope(req.valid.query);
      res.json(await analytics.listSessions(s.app, s.range, req.valid.query));
    },
  );
  r.get('/sessions/:id', validate({ params: idParam, query: z.strictObject({ app: rangeQuery.app }) }), async (req, res) => {
    const target = await resolveApp(req.valid.query.app);
    if (!target) throw appError('NOT_FOUND');
    res.json({ data: await analytics.getSession(target, req.valid.params.id) });
  });
  return r;
}

function appsRouter() {
  const r = Router();
  r.use(requireSession('active'));
  r.get('/', async (_req, res) => {
    const geo = geoipInfo();
    res.json({ data: (await listApps()).map(({ id, slug, name, allowedOrigins, isActive }) => ({ id, slug, name, allowedOrigins, isActive })), geoip: geo });
  });
  // New ingestion credentials (owners, fresh confirmation). Shown once; the old ones stop working immediately.
  r.post(
    '/:slug/rotate-secret',
    requireRole('owner'),
    limits.sensitive,
    requireRecentReauth,
    validate({ params: z.object({ slug: z.string().regex(/^[a-z][a-z0-9-]{1,40}$/) }) }),
    async (req, res) => {
      const out = await rotateIngestSecret(req.valid.params.slug);
      if (!out) throw appError('NOT_FOUND', 'Application not found.');
      await writeAudit(pool, actorOf(req), {
        action: 'app.secret_rotated',
        targetType: 'application',
        targetId: out.appId,
        details: { slug: req.valid.params.slug, keyId: out.ingestKeyId },
      });
      res.json({ data: { ingestKeyId: out.ingestKeyId, ingestSecret: out.ingestSecret } });
    },
  );
  return r;
}

/** The signed-in developer's own alert email preferences. */
function meRouter() {
  const r = Router();
  r.use(requireSession('active'));
  r.get('/notifications', async (req, res) => void res.json({ data: await getPreferences(req.admin!.id) }));
  r.put(
    '/notifications',
    limits.sensitive,
    validate({
      body: z.strictObject({
        emailEnabled: z.boolean(),
        minSeverity: z.enum(['medium', 'high', 'critical']),
        quietHours: z
          .strictObject({ start: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/), end: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/) })
          .refine((q) => q.start !== q.end, 'Start and end must differ')
          .nullable(),
      }),
    }),
    async (req, res) => {
      const out = await setPreferences(req.admin!.id, req.valid.body);
      await writeAudit(pool, actorOf(req), { action: 'preferences.updated', details: { emailEnabled: out.emailEnabled, minSeverity: out.minSeverity } });
      res.json({ data: out });
    },
  );
  return r;
}

/** Server-Sent Events: live analytics (and, from Phase 5, security alerts) for the signed-in developer. */
function streamRouter() {
  const r = Router();
  r.get('/', requireSession('active'), async (req, res) => {
    const token = parseCookies(req.get('cookie'))[config.SESSION_COOKIE]!;
    await liveHub.open(req, res, async () => (await findSession(token))?.session.state === 'active');
  });
  return r;
}

export function mountApi(app: Express) {
  const api = Router();
  // Every /api request: session cookie read, CSRF check on state-changing methods, no caching.
  api.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  api.use(requireSameOrigin, loadSession);
  api.use('/auth', authRouter());
  api.use('/admins', adminsRouter());
  api.use('/audit-logs', auditRouter());
  api.use('/apps', appsRouter());
  api.use('/me', meRouter());
  api.use('/analytics', analyticsRouter());
  api.use('/security', securityRouter());
  api.use('/stream', streamRouter());
  app.use('/api', api);
}
