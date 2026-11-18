// Small request-level middleware: request id, cookie parsing, CSRF (same-origin) check, Zod validation.
import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';
import type { ZodType } from 'zod';
import { config } from '../config/env.js';
import { appError } from '../errors/app-error.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const requestId: RequestHandler = (req, res, next) => {
  const incoming = req.get('x-request-id');
  req.id = incoming && UUID_RE.test(incoming) ? incoming : randomUUID();
  req.valid = { params: {}, query: {}, body: {} };
  res.setHeader('X-Request-Id', req.id);
  next();
};

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const name = part.slice(0, i).trim();
    if (!name || name in out) continue; // first wins (a later duplicate can't shadow it)
    try {
      out[name] = decodeURIComponent(part.slice(i + 1).trim());
    } catch {
      /* malformed value: ignore */
    }
  }
  return out;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
export const CSRF_HEADER = 'x-requested-with';
export const CSRF_HEADER_VALUE = 'sentinel';

/**
 * State-changing requests must come from the dashboard itself. Three independent checks:
 *  1. the session cookie is SameSite=Strict (browsers don't attach it cross-site);
 *  2. Origin must be APP_ORIGIN (or, when a browser omits Origin, Sec-Fetch-Site must be same-origin);
 *  3. a custom header, which a cross-site form or <img> can't send and a cross-origin fetch can't add without a
 *     CORS preflight this API never approves.
 */
export const requireSameOrigin: RequestHandler = (req, _res, next) => {
  if (SAFE_METHODS.has(req.method)) return next();
  const origin = req.get('origin');
  const fetchSite = req.get('sec-fetch-site');
  const originOk = origin ? origin === config.APP_ORIGIN : fetchSite ? fetchSite === 'same-origin' : false;
  if (!originOk || req.get(CSRF_HEADER) !== CSRF_HEADER_VALUE) return next(appError('CSRF_REJECTED'));
  next();
};

export function validate(schemas: { params?: ZodType; query?: ZodType; body?: ZodType }): RequestHandler {
  return (req, _res, next) => {
    for (const part of ['params', 'query', 'body'] as const) {
      const schema = schemas[part];
      if (!schema) continue;
      const input = part === 'body' ? (req.body ?? {}) : part === 'query' ? req.query : req.params;
      const result = schema.safeParse(input);
      if (!result.success) {
        const fieldErrors: Record<string, string[]> = {};
        for (const issue of result.error.issues) (fieldErrors[issue.path.map(String).join('.') || '_'] ??= []).push(issue.message);
        return next(appError('VALIDATION_ERROR', undefined, { fieldErrors }));
      }
      req.valid[part] = result.data;
    }
    next();
  };
}
