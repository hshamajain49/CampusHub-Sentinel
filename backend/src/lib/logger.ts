import pino from 'pino';
import { config } from '../config/env.js';

export const logger = pino({
  level: config.LOG_LEVEL,
  base: { service: 'sentinel-api' },
  redact: {
    paths: [
      'req.headers.cookie',
      'req.headers.authorization',
      'req.headers["x-sentinel-signature"]',
      'res.headers["set-cookie"]',
      '*.password',
      '*.currentPassword',
      '*.newPassword',
      '*.code',
      '*.recoveryCodes',
      '*.secret',
      'password',
      'code',
    ],
    censor: '[redacted]',
  },
});
