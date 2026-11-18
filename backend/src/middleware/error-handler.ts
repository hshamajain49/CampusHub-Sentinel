import type { ErrorRequestHandler, RequestHandler } from 'express';
import { AppError, appError } from '../errors/app-error.js';
import { logger } from '../lib/logger.js';

const CONNECTION = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'ECONNRESET', 'ENOTFOUND', '57P01', '53300']);

export const notFound: RequestHandler = (_req, _res, next) => next(appError('NOT_FOUND'));

/** Responses carry a code, a safe message and the request id; stack traces and SQL errors stay in the log. */
export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  let e: AppError | null = err instanceof AppError ? err : null;
  if (!e && err?.type === 'entity.parse.failed') e = appError('VALIDATION_ERROR', 'Malformed JSON body');
  if (!e && err?.type === 'entity.too.large') e = appError('VALIDATION_ERROR', 'Request too large');
  if (!e && typeof err?.code === 'string' && (CONNECTION.has(err.code) || err.code.startsWith('08'))) e = appError('SERVICE_UNAVAILABLE');
  if (!e) {
    logger.error({ err, reqId: req.id, path: req.path }, 'unhandled error');
    e = appError('INTERNAL_ERROR');
  } else if (e.status >= 500) {
    logger.error({ code: e.code, reqId: req.id, err: err instanceof AppError ? undefined : err }, 'server error');
  }
  if (res.headersSent) return;
  res.status(e.status).json({ error: { code: e.code, message: e.message, details: e.details ?? null, requestId: req.id } });
};
