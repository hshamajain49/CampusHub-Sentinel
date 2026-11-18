// /ingest/v1: server-to-server only (HMAC-signed by the monitored app's API; see signature.ts). Never reachable with
// a browser session, and the ingestion secret can only add events and read the blocklist: it can't read, change or
// delete anything else in Sentinel.
import express, { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../../config/env.js';
import { appError } from '../../errors/app-error.js';
import { activeBlocklist } from '../security/ips.service.js';
import { batchSchema, ingestBatch } from './ingest.service.js';
import { requireSignature } from './signature.js';

const disabled = config.NODE_ENV === 'test' && process.env.RATE_LIMIT_TESTS !== '1';

export function ingestRouter() {
  const r = Router();
  r.use(
    rateLimit({
      windowMs: 60_000,
      limit: 600,
      skip: () => disabled,
      standardHeaders: 'draft-7',
      legacyHeaders: false,
      handler: (_req, res) => void res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many ingestion requests.', details: null } }),
    }),
  );
  r.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  // The signature covers the exact bytes, so the body is read raw and parsed after verification.
  r.use(express.raw({ type: () => true, limit: '256kb' }));

  r.post('/events', requireSignature, async (req, res) => {
    let raw: unknown;
    try {
      raw = JSON.parse(req.rawBody!.toString('utf8') || '{}');
    } catch {
      throw appError('VALIDATION_ERROR', 'Malformed JSON body');
    }
    const parsed = batchSchema.safeParse(raw);
    if (!parsed.success) {
      const fieldErrors: Record<string, string[]> = {};
      for (const i of parsed.error.issues.slice(0, 20)) (fieldErrors[i.path.join('.') || '_'] ??= []).push(i.message);
      throw appError('VALIDATION_ERROR', 'Invalid batch.', { fieldErrors });
    }
    res.json({ data: await ingestBatch(req.ingestApp!.id, parsed.data) });
  });

  r.get('/blocklist', requireSignature, async (req, res) => {
    res.json({ data: { generatedAt: new Date().toISOString(), blocks: await activeBlocklist(req.ingestApp!.id) } });
  });
  return r;
}
