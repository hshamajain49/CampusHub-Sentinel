// IP and session rate limits (in memory: valid for the single Render instance). Sign-in also has a per-account
// counter in Postgres (modules/auth/login-throttle.ts) that survives restarts.
import rateLimit from 'express-rate-limit';
import { config } from '../config/env.js';

const disabled = config.NODE_ENV === 'test' && process.env.RATE_LIMIT_TESTS !== '1';
const MIN = 60_000;

function limiter(windowMs: number, limit: number, key: 'ip' | 'session' = 'ip') {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skip: () => disabled,
    keyGenerator: key === 'session' ? (req) => req.session?.id ?? req.ip ?? 'anon' : undefined,
    validate: { keyGeneratorIpFallback: false },
    handler: (req, res, _next, options) => {
      res.setHeader('Retry-After', Math.ceil(options.windowMs / 1000));
      res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many requests. Please wait a moment and try again.', details: null, requestId: req.id } });
    },
  });
}

export const limits = {
  global: limiter(15 * MIN, 600),
  login: limiter(15 * MIN, 20),
  mfa: limiter(5 * MIN, 15, 'session'),
  sensitive: limiter(15 * MIN, 30, 'session'),
};
