// /ingest/v1: server-to-server only (HMAC-signed by the monitored app's API; see signature.ts). Never reachable with
// a browser session, and the ingestion secret can only add events and scan reports and read the blocklist: it
// can't read, change or delete anything else in Sentinel.
import express, { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../../config/env.js';
import { appError } from '../../errors/app-error.js';
import { activeBlocklist } from '../security/ips.service.js';
import { batchSchema, ingestBatch } from './ingest.service.js';
import { reportSchema, storeReport } from '../reports/reports.service.js';
import { requireSignature } from './signature.js';

const disabled = config.NODE_ENV === 'test' && process.env.RATE_LIMIT_TESTS !== '1';

function parseJson(raw: Buffer): unknown {
  try {
    return JSON.parse(raw.toString('utf8') || '{}');
  } catch {
    throw appError('VALIDATION_ERROR', 'Malformed JSON body');
  }
}

function invalid(issues: { path: PropertyKey[]; message: string }[], message: string) {
  const fieldErrors: Record<string, string[]> = {};
  for (const i of issues.slice(0, 20)) (fieldErrors[i.path.map(String).join('.') || '_'] ??= []).push(i.message);
  return appError('VALIDATION_ERROR', message, { fieldErrors });
}

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
  // Scan reports are larger than event batches (up to 1 MB); they get their own raw parser, before the shared one.
  r.post('/reports', express.raw({ type: () => true, limit: '1mb' }), requireSignature, async (req, res) => {
    const parsed = reportSchema.safeParse(parseJson(req.rawBody!));
    if (!parsed.success) throw invalid(parsed.error.issues, 'Invalid report.');
    res.status(201).json({ data: await storeReport(req.ingestApp!.id, parsed.data) });
  });

  // The signature covers the exact bytes, so the body is read raw and parsed after verification.
  r.use(express.raw({ type: () => true, limit: '256kb' }));

  r.post('/events', requireSignature, async (req, res) => {
    const parsed = batchSchema.safeParse(parseJson(req.rawBody!));
    if (!parsed.success) throw invalid(parsed.error.issues, 'Invalid batch.');
    res.json({ data: await ingestBatch(req.ingestApp!.id, parsed.data) });
  });

  r.get('/blocklist', requireSignature, async (req, res) => {
    res.json({ data: { generatedAt: new Date().toISOString(), blocks: await activeBlocklist(req.ingestApp!.id) } });
  });
  return r;
}
