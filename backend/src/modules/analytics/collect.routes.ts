// POST /collect — page views and heartbeats from the monitored site's browsers.
//
// Public by nature (it's called from visitors' browsers), so it holds no secret and can do nothing but add page
// views. Defences:
//  - the site key must belong to an active app, and the browser's Origin must be one of that app's origins;
//  - the body is at most 2 KB and strictly shaped;
//  - rate limits per visitor and, loosely, per IP (a whole campus can share one address);
//  - bots, Do-Not-Track and Global Privacy Control requests are accepted and dropped (nothing stored);
//  - no CORS headers: the browser sends the beacon (text/plain, no preflight) but can't read the answer.
import express, { Router, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { config } from '../../config/env.js';
import { appError } from '../../errors/app-error.js';
import { logger } from '../../lib/logger.js';
import { clientIp } from '../audit/audit.service.js';
import { appBySiteKey } from '../apps/apps.service.js';
import { recordHit } from './collect.service.js';
import { liveHub } from './live.js';
import { parseUserAgent } from './parse.js';

const short = z.string().trim().max(100).optional();
export const hitSchema = z.strictObject({
  k: z.string().regex(/^sk_[A-Za-z0-9_-]{16,64}$/), // site key
  v: z.uuid(), // visitor id (random, kept in the visitor's browser)
  t: z.enum(['pageview', 'heartbeat']),
  p: z.string().min(1).max(2000), // path; normalised (no query, ids → :id) before storage
  r: z.string().max(1000).optional(), // referrer (only its host is kept)
  w: z.number().int().min(0).max(20_000).optional(), // viewport width (bucketed)
  us: short,
  um: short,
  uc: short,
  u: z.string().regex(/^[A-Za-z0-9-]{1,64}$/).optional(), // CampusHub user id, only when linking is switched on
});

const disabled = config.NODE_ENV === 'test' && process.env.RATE_LIMIT_TESTS !== '1';
const tooMany = (_req: Request, res: Response) => void res.status(429).end();

const perIp = rateLimit({ windowMs: 60_000, limit: 5_000, skip: () => disabled, standardHeaders: false, legacyHeaders: false, handler: tooMany });
const perVisitor = rateLimit({
  windowMs: 60_000,
  limit: config.COLLECT_RATE_PER_MINUTE,
  skip: () => disabled,
  standardHeaders: false,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}|${(req.valid?.body as { v?: string } | undefined)?.v ?? '-'}`,
  validate: { keyGeneratorIpFallback: false },
  handler: tooMany,
});

export function collectRouter() {
  const r = Router();
  r.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  r.post(
    '/',
    perIp,
    express.text({ type: () => true, limit: '2kb' }),
    (req, _res, next) => {
      let raw: unknown;
      try {
        raw = JSON.parse(typeof req.body === 'string' ? req.body : '');
      } catch {
        return next(appError('VALIDATION_ERROR', 'Malformed beacon'));
      }
      const parsed = hitSchema.safeParse(raw);
      if (!parsed.success) return next(appError('VALIDATION_ERROR', 'Malformed beacon'));
      req.valid.body = parsed.data;
      next();
    },
    perVisitor,
    async (req, res) => {
      const b = req.valid.body as z.infer<typeof hitSchema>;
      // Visitors who asked not to be tracked: accept and store nothing.
      if (req.get('dnt') === '1' || req.get('sec-gpc') === '1') return void res.status(204).end();
      const app = await appBySiteKey(b.k);
      if (!app || !app.isActive) throw appError('FORBIDDEN', 'Unknown site');
      const origin = req.get('origin');
      if (!origin || !app.allowedOrigins.includes(origin)) throw appError('FORBIDDEN', 'Origin not allowed');
      const userAgent = req.get('user-agent') ?? null;
      if (parseUserAgent(userAgent).isBot) return void res.status(204).end();

      await recordHit({
        app,
        type: b.t,
        visitorKey: b.v,
        path: b.p,
        referrer: b.r,
        viewportWidth: b.w,
        utm: { source: b.us || undefined, medium: b.um || undefined, campaign: b.uc || undefined },
        userRef: b.u,
        ip: clientIp(req),
        userAgent,
      }).catch((err) => {
        logger.warn({ err }, 'collect: hit not recorded');
        throw appError('SERVICE_UNAVAILABLE');
      });
      liveHub.notify();
      res.status(204).end();
    },
  );
  return r;
}
