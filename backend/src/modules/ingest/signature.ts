// Server-to-server authentication for /ingest/v1/*: an HMAC-SHA256 signature with the app's ingestion secret.
//
//   X-Sentinel-Key:        ik_…                (which app; public)
//   X-Sentinel-Signature:  t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<METHOD>.<path>.<raw body>")>
//
// The timestamp must be within 5 minutes. Signing the method and path means a captured request can't be replayed
// against another endpoint; replays of the same request are harmless (event ids dedupe; traffic counts overwrite).
// The secret never travels: only CampusHub's API and Sentinel know it (stored encrypted here).
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { RequestHandler } from 'express';
import { pool } from '../../db/pool.js';
import { appError } from '../../errors/app-error.js';
import { decrypt } from '../../lib/crypto.js';
import { logger } from '../../lib/logger.js';

export const MAX_SKEW_SECONDS = 300;

export function signRequest(secret: string, method: string, path: string, body: string | Buffer, t = Math.floor(Date.now() / 1000)): string {
  const mac = createHmac('sha256', secret).update(`${t}.${method.toUpperCase()}.${path}.`).update(body).digest('hex');
  return `t=${t},v1=${mac}`;
}

export function verifySignature(
  secret: string,
  header: string | undefined,
  method: string,
  path: string,
  body: Buffer,
  nowSeconds = Math.floor(Date.now() / 1000),
): 'ok' | 'malformed' | 'stale' | 'mismatch' {
  const m = /^t=(\d{9,11}),v1=([0-9a-f]{64})$/.exec(header ?? '');
  if (!m) return 'malformed';
  const t = Number(m[1]);
  if (Math.abs(nowSeconds - t) > MAX_SKEW_SECONDS) return 'stale';
  const expected = Buffer.from(signRequest(secret, method, path, body, t).slice(-64), 'hex');
  const given = Buffer.from(m[2]!, 'hex');
  return expected.length === given.length && timingSafeEqual(expected, given) ? 'ok' : 'mismatch';
}

interface IngestApp {
  id: string;
  slug: string;
  secret: string;
  isActive: boolean;
}

// Secrets are decrypted once per minute per key, not on every request.
const cache = new Map<string, { app: IngestApp | null; at: number }>();
export function clearIngestCache() {
  cache.clear();
}

async function appByKey(keyId: string): Promise<IngestApp | null> {
  const hit = cache.get(keyId);
  if (hit && Date.now() - hit.at < 60_000) return hit.app;
  const { rows } = await pool.query('select id, slug, ingest_secret, is_active from public.monitored_applications where ingest_key_id = $1', [keyId]);
  const app = rows[0] ? { id: rows[0].id, slug: rows[0].slug, secret: decrypt(rows[0].ingest_secret, 'ingest-secret'), isActive: rows[0].is_active } : null;
  if (cache.size > 100) cache.clear();
  cache.set(keyId, { app, at: Date.now() });
  return app;
}

/** Needs express.raw() before it: the signature covers the exact bytes received. */
export const requireSignature: RequestHandler = async (req, _res, next) => {
  const keyId = req.get('x-sentinel-key') ?? '';
  const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const app = /^ik_[A-Za-z0-9_-]{8,40}$/.test(keyId) ? await appByKey(keyId) : null;
  const result = app ? verifySignature(app.secret, req.get('x-sentinel-signature'), req.method, req.originalUrl.split('?')[0]!, body) : 'unknown-key';
  if (result !== 'ok') {
    logger.warn({ result, keyId: keyId.slice(0, 12), ip: req.ip }, 'ingest: signature rejected');
    return next(appError('UNAUTHENTICATED', 'Invalid signature.'));
  }
  if (!app!.isActive) return next(appError('FORBIDDEN', 'This application is inactive.'));
  req.ingestApp = { id: app!.id, slug: app!.slug };
  req.rawBody = body;
  next();
};
