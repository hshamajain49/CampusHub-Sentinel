// Express app. One origin serves the dashboard and its API, so there is no CORS at all: browsers refuse
// cross-origin reads, and the session cookie is SameSite=Strict + HttpOnly + Secure.
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { appVersion, config } from './config/env.js';
import { pool } from './db/pool.js';
import { logger } from './lib/logger.js';
import { requestId } from './middleware/basics.js';
import { errorHandler, notFound } from './middleware/error-handler.js';
import { limits } from './middleware/rate-limiters.js';
import { collectRouter } from './modules/analytics/collect.routes.js';
import { ingestRouter } from './modules/ingest/ingest.routes.js';
import { mountApi } from './routes.js';

/**
 * The dashboard (frontend/dist) from the same origin as the API: one origin means first-party HttpOnly cookies and
 * no CORS. Hashed assets are cached for a year; index.html never (a deploy takes effect on the next load).
 */
function serveDashboard(app: express.Express) {
  const dist = [path.resolve(process.cwd(), '..', 'frontend', 'dist'), path.resolve(process.cwd(), 'frontend', 'dist')].find((d) => fs.existsSync(path.join(d, 'index.html')));
  if (!dist) return;
  const index = path.join(dist, 'index.html');
  app.use('/assets', express.static(path.join(dist, 'assets'), { immutable: true, maxAge: '365d', index: false, fallthrough: false }));
  app.use(express.static(dist, { index: false, maxAge: '1h' }));
  // Client-side routes (anything that isn't the API, ingestion, beacons or a file) get the app shell.
  app.get(/^\/(?!api\/|ingest\/|collect|health|assets\/).*/, (req, res, next) => {
    if (path.extname(req.path)) return next();
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(index);
  });
}

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.TRUST_PROXY);
  app.use(requestId);
  app.use(
    pinoHttp({
      logger,
      genReqId: (req) => (req as express.Request).id,
      customProps: (req) => ({ adminId: (req as express.Request).admin?.id }),
      autoLogging: { ignore: (req) => req.url === '/health' },
      serializers: { req: (req) => ({ method: req.method, url: req.url }), res: (res) => ({ statusCode: res.statusCode }) },
    }),
  );
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'", "'unsafe-inline'"], // chart libraries set inline style attributes
          'img-src': ["'self'", 'data:'],
          'font-src': ["'self'"],
          'connect-src': ["'self'"],
          'object-src': ["'none'"],
          'base-uri': ["'none'"],
          'form-action': ["'self'"],
          'frame-ancestors': ["'none'"],
          ...(config.production ? { 'upgrade-insecure-requests': [] } : {}),
        },
      },
      referrerPolicy: { policy: 'no-referrer' },
      xFrameOptions: { action: 'deny' },
      strictTransportSecurity: config.production ? { maxAge: 63_072_000, includeSubDomains: true } : false,
      crossOriginResourcePolicy: { policy: 'same-origin' },
    }),
  );
  app.use((_req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    next();
  });
  // Browser beacons have their own per-visitor limits (a whole campus can share one IP address);
  // server-to-server ingestion has its own limits and HMAC authentication.
  app.use(
    '/collect',
    // Beacons come from the monitored site, a different origin (no-cors requests). With helmet's same-origin
    // resource policy the browser refuses the response and logs ERR_BLOCKED_BY_RESPONSE on every page view.
    // The response is empty, so letting other origins receive it exposes nothing.
    (_req, res, next) => {
      res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      next();
    },
    collectRouter(),
  );
  app.use('/ingest/v1', ingestRouter());
  app.use(limits.global);

  // Health checks: /health never touches the database (Render's probe); /health/ready does.
  app.get('/health', (_req, res) => void res.json({ status: 'ok', version: appVersion }));
  app.get('/health/ready', async (_req, res) => {
    try {
      await pool.query('select 1');
      res.json({ status: 'ok', db: 'ok' });
    } catch {
      res.status(503).json({ status: 'degraded', db: 'error' });
    }
  });

  app.use('/api', express.json({ limit: '64kb' }));
  mountApi(app);
  serveDashboard(app);
  app.use(notFound);
  app.use(errorHandler);
  return app;
}
