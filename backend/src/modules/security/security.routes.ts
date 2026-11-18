// /api/security: the dashboard's threat monitoring. Everyone signed in can view and triage (alert status, incidents,
// notes). Changing what Sentinel enforces or how it detects (blocks, the allowlist, rules) is for owners, after a
// fresh password + code confirmation. Every change is written to the audit log.
import { Router } from 'express';
import { z } from 'zod';
import { appError } from '../../errors/app-error.js';
import { validate } from '../../middleware/basics.js';
import { limits } from '../../middleware/rate-limiters.js';
import { requireRecentReauth, requireRole, requireSession } from '../../middleware/session.js';
import { withTransaction } from '../../db/pool.js';
import { resolveRange, RANGES } from '../analytics/analytics.service.js';
import { resolveApp } from '../apps/apps.service.js';
import { actorOf, writeAudit } from '../audit/audit.service.js';
import * as alerts from './alerts.service.js';
import * as incidents from './incidents.service.js';
import * as ips from './ips.service.js';
import * as overview from './overview.service.js';
import { allRules, invalidateRules, updateRule } from './rules.js';

const SEV = ['info', 'low', 'medium', 'high', 'critical'] as const;
const csv = <T extends string>(values: readonly [T, ...T[]]) =>
  z
    .string()
    .transform((s) => s.split(',').map((x) => x.trim()).filter(Boolean))
    .pipe(z.array(z.enum(values)).max(values.length))
    .optional();
const appQ = { app: z.string().regex(/^[a-z][a-z0-9-]{1,40}$/).optional() };
const rangeQ = { ...appQ, range: z.enum(RANGES).default('7d'), from: z.iso.date().optional(), to: z.iso.date().optional() };
const paging = { page: z.coerce.number().int().min(1).max(10_000).default(1), pageSize: z.coerce.number().int().min(1).max(100).default(25) };
const idParam = z.object({ id: z.uuid() });
const ipAddr = z.union([z.ipv4(), z.ipv6()]);

async function target(slug?: string) {
  const app = await resolveApp(slug);
  if (!app) throw appError('NOT_FOUND', 'No monitored application is registered yet (npm run app:register).');
  return app;
}

export function securityRouter() {
  const r = Router();
  r.use(requireSession('active'));

  // ── overview, timeline, events ──
  r.get('/overview', validate({ query: z.strictObject(rangeQ) }), async (req, res) => {
    const app = await target(req.valid.query.app);
    res.json({ data: await overview.securityOverview(app, await resolveRange(req.valid.query)) });
  });
  r.get('/timeseries', validate({ query: z.strictObject(rangeQ) }), async (req, res) => {
    const app = await target(req.valid.query.app);
    res.json({ data: await overview.securityTimeseries(app, await resolveRange(req.valid.query)) });
  });
  r.get('/status', validate({ query: z.strictObject(appQ) }), async (req, res) => {
    res.json({ data: await overview.healthStatus((await target(req.valid.query.app)).id) });
  });
  r.get(
    '/events',
    validate({
      query: z.strictObject({
        ...rangeQ,
        ...paging,
        severity: csv(SEV),
        category: z.string().regex(/^[a-z][a-z_]*\.[a-z][a-z_]*$/).optional(),
        ip: z.union([ipAddr, z.string().regex(/^[0-9a-fA-F.:]+\/\d{1,3}$/)]).optional(),
        userRef: z.string().max(64).optional(),
        route: z.string().max(200).optional(),
        simulated: z.enum(['true', 'false']).transform((v) => v === 'true').optional(),
      }),
    }),
    async (req, res) => {
      const app = await target(req.valid.query.app);
      res.json(await overview.listEvents(app, await resolveRange(req.valid.query), req.valid.query));
    },
  );
  r.get('/events/:id', validate({ params: idParam, query: z.strictObject(appQ) }), async (req, res) => {
    res.json({ data: await overview.getEvent((await target(req.valid.query.app)).id, req.valid.params.id) });
  });

  // ── alerts (triage: any developer) ──
  r.get(
    '/alerts',
    validate({ query: z.strictObject({ ...appQ, ...paging, status: csv(['open', 'acknowledged', 'resolved', 'false_positive'] as const), severity: csv(SEV) }) }),
    async (req, res) => {
      res.json(await alerts.listAlerts((await target(req.valid.query.app)).id, req.valid.query));
    },
  );
  r.get('/alerts/:id', validate({ params: idParam, query: z.strictObject(appQ) }), async (req, res) => {
    res.json({ data: await alerts.getAlert((await target(req.valid.query.app)).id, req.valid.params.id) });
  });
  r.patch(
    '/alerts/:id',
    limits.sensitive,
    validate({
      params: idParam,
      query: z.strictObject(appQ),
      body: z.strictObject({ status: z.enum(['open', 'acknowledged', 'resolved', 'false_positive']), note: z.string().trim().max(500).optional() }),
    }),
    async (req, res) => {
      const app = await target(req.valid.query.app);
      await alerts.setAlertStatus(app.id, req.valid.params.id, req.valid.body.status, actorOf(req), req.valid.body.note);
      res.json({ data: await alerts.getAlert(app.id, req.valid.params.id) });
    },
  );

  // ── incidents ──
  const severity = z.enum(['low', 'medium', 'high', 'critical']);
  r.get('/incidents', validate({ query: z.strictObject({ ...appQ, ...paging, status: csv(incidents.INCIDENT_STATUSES) }) }), async (req, res) => {
    res.json(await incidents.listIncidents((await target(req.valid.query.app)).id, req.valid.query));
  });
  r.post(
    '/incidents',
    limits.sensitive,
    validate({
      query: z.strictObject(appQ),
      body: z.strictObject({
        title: z.string().trim().min(3).max(200),
        summary: z.string().trim().max(5000).optional(),
        severity,
        classification: z.enum(incidents.CLASSIFICATIONS).default('suspicious'),
        alertIds: z.array(z.uuid()).max(100).default([]),
      }),
    }),
    async (req, res) => {
      const app = await target(req.valid.query.app);
      res.status(201).json({ data: await incidents.createIncident(app.id, req.valid.body, actorOf(req), req.admin!.role) });
    },
  );
  r.get('/incidents/:id', validate({ params: idParam, query: z.strictObject(appQ) }), async (req, res) => {
    res.json({ data: await incidents.getIncident((await target(req.valid.query.app)).id, req.valid.params.id) });
  });
  r.patch(
    '/incidents/:id',
    limits.sensitive,
    validate({
      params: idParam,
      query: z.strictObject(appQ),
      body: z
        .strictObject({
          title: z.string().trim().min(3).max(200).optional(),
          summary: z.string().trim().max(5000).nullable().optional(),
          status: z.enum(incidents.INCIDENT_STATUSES).optional(),
          severity: severity.optional(),
          classification: z.enum(incidents.CLASSIFICATIONS).optional(),
          ownerId: z.uuid().nullable().optional(),
          addAlertIds: z.array(z.uuid()).max(100).optional(),
        })
        .refine((v) => Object.values(v).some((x) => x !== undefined), 'Nothing to change'),
    }),
    async (req, res) => {
      const app = await target(req.valid.query.app);
      res.json({ data: await incidents.updateIncident(app.id, req.valid.params.id, req.valid.body, actorOf(req), req.admin!.role) });
    },
  );
  r.post(
    '/incidents/:id/notes',
    limits.sensitive,
    validate({ params: idParam, query: z.strictObject(appQ), body: z.strictObject({ body: z.string().trim().min(1).max(5000) }) }),
    async (req, res) => {
      const app = await target(req.valid.query.app);
      res.status(201).json({ data: await incidents.addNote(app.id, req.valid.params.id, req.valid.body.body, actorOf(req)) });
    },
  );

  // ── suspicious IPs ──
  r.get('/ips', validate({ query: z.strictObject({ ...appQ, ...paging, minScore: z.coerce.number().min(0).max(1000).default(5) }) }), async (req, res) => {
    res.json(await ips.listSuspicious((await target(req.valid.query.app)).id, req.valid.query));
  });
  r.get('/ips/:ip', validate({ params: z.object({ ip: ipAddr }), query: z.strictObject(appQ) }), async (req, res) => {
    res.json({ data: await ips.ipDetail((await target(req.valid.query.app)).id, req.valid.params.ip) });
  });

  // ── blocks and allowlist (owners, fresh confirmation) ──
  r.get('/blocks', validate({ query: z.strictObject({ ...appQ, active: z.enum(['true', 'false']).default('true').transform((v) => v === 'true') }) }), async (req, res) => {
    res.json({ data: await ips.listBlocks((await target(req.valid.query.app)).id, req.valid.query.active) });
  });
  r.post(
    '/blocks',
    requireRole('owner'),
    limits.sensitive,
    requireRecentReauth,
    validate({
      query: z.strictObject(appQ),
      body: z.strictObject({
        cidr: z.string().trim().min(3).max(50),
        minutes: z.number().int().min(15).max(7 * 24 * 60),
        reason: z.string().trim().min(3).max(300),
      }),
    }),
    async (req, res) => {
      const app = await target(req.valid.query.app);
      res.status(201).json({ data: await ips.manualBlock(app.id, req.valid.body, actorOf(req)) });
    },
  );
  r.post('/blocks/:id/lift', requireRole('owner'), limits.sensitive, validate({ params: idParam, query: z.strictObject(appQ) }), async (req, res) => {
    // Lifting a block only loosens enforcement, so it needs no fresh confirmation (it may be urgent).
    res.json({ data: await ips.liftBlock((await target(req.valid.query.app)).id, req.valid.params.id, actorOf(req)) });
  });
  r.get('/allowlist', validate({ query: z.strictObject(appQ) }), async (req, res) => {
    res.json({ data: await ips.listAllowlist((await target(req.valid.query.app)).id) });
  });
  r.post(
    '/allowlist',
    requireRole('owner'),
    limits.sensitive,
    requireRecentReauth,
    validate({ query: z.strictObject(appQ), body: z.strictObject({ cidr: z.string().trim().min(3).max(50), note: z.string().trim().min(2).max(200) }) }),
    async (req, res) => {
      const app = await target(req.valid.query.app);
      res.status(201).json({ data: await ips.addAllowlist(app.id, req.valid.body, actorOf(req)) });
    },
  );
  r.delete('/allowlist/:id', requireRole('owner'), limits.sensitive, requireRecentReauth, validate({ params: idParam, query: z.strictObject(appQ) }), async (req, res) => {
    await ips.removeAllowlist((await target(req.valid.query.app)).id, req.valid.params.id, actorOf(req));
    res.status(204).end();
  });

  // ── detection rules ──
  r.get('/rules', async (_req, res) => void res.json({ data: await allRules() }));
  r.patch(
    '/rules/:key',
    requireRole('owner'),
    limits.sensitive,
    requireRecentReauth,
    validate({
      params: z.object({ key: z.string().regex(/^[a-z][a-z0-9_]{2,60}$/) }),
      body: z
        .strictObject({
          enabled: z.boolean().optional(),
          severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
          threshold: z.number().int().min(1).max(100_000).optional(),
          windowSeconds: z.number().int().min(10).max(86_400).optional(),
          cooldownSeconds: z.number().int().min(0).max(86_400).optional(),
          autoBlock: z.boolean().optional(),
          blockSeconds: z.number().int().min(60).max(86_400).optional(),
        })
        .refine((v) => Object.values(v).some((x) => x !== undefined), 'Nothing to change'),
    }),
    async (req, res) => {
      const out = await withTransaction(async (tx) => {
        const changed = await updateRule(req.valid.params.key, req.valid.body, req.admin!.id, tx);
        if (!changed) throw appError('NOT_FOUND', 'Rule not found.');
        await writeAudit(tx, actorOf(req), {
          action: 'rule.updated',
          targetType: 'detection_rule',
          targetId: req.valid.params.key,
          details: Object.fromEntries(
            Object.keys(req.valid.body).map((k) => [k, { from: (changed.before as any)[k], to: (changed.after as any)[k] }]),
          ),
        });
        return changed.after;
      });
      invalidateRules(); // again after commit, so no reader caches the old values in between
      res.json({ data: out });
    },
  );
  return r;
}
