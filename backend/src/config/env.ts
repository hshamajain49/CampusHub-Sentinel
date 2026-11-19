// Zod-validated environment. Nothing else reads process.env. The service refuses to start on a missing or weak
// secret rather than running half-configured.
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';

/** Local runs read backend/.env (tests: .env.test); file values win over the shell. Render has no file. */
function loadEnvFile() {
  const name = process.env.ENV_FILE ?? (process.env.VITEST ? '.env.test' : '.env');
  if (name === 'none') return;
  const file = [path.resolve(process.cwd(), name), path.resolve(process.cwd(), 'backend', name)].find((f) => fs.existsSync(f));
  if (!file) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (line.trimStart().startsWith('#')) continue;
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (m) process.env[m[1]!] = m[2]!.replace(/^(['"])(.*)\1$/, '$2');
  }
}
loadEnvFile();

const optional = z.preprocess((v) => (v === '' ? undefined : v), z.string().optional());
const bool = z.preprocess((v) => (typeof v === 'string' ? v === 'true' || v === '1' : v), z.boolean());

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().default(4100),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    APP_VERSION: optional,
    RENDER_GIT_COMMIT: optional,
    APP_ORIGIN: z.url().transform((u) => new URL(u).origin),
    TRUST_PROXY: z.coerce.number().int().min(0).max(5).default(0),
    DATABASE_URL: z.string().min(1),
    DATABASE_SSL: bool.default(false),
    DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(20).default(5),
    DATA_ENCRYPTION_KEY: z
      .string()
      .refine((s) => /^[A-Za-z0-9+/]+=*$/.test(s) && Buffer.from(s, 'base64').length >= 32, 'DATA_ENCRYPTION_KEY must be base64 of at least 32 random bytes'),
    SESSION_IDLE_MINUTES: z.coerce.number().int().min(5).max(240).default(30),
    SESSION_ABSOLUTE_HOURS: z.coerce.number().int().min(1).max(24).default(12),
    REAUTH_MINUTES: z.coerce.number().int().min(1).max(60).default(10),
    /**
     * Two-step verification (authenticator codes) at sign-in and for sensitive actions. Off by default (owner decision,
     * 2026-11-19: password only for now). 'required' turns it back on; developers who already set up an authenticator
     * keep it, the others are asked to set one up at their next sign-in.
     */
    MFA_MODE: z.enum(['required', 'off']).default('off'),
    // Visitor analytics (Phase 4)
    /** DB-IP Lite edition: country (~8 MB in memory), city (~130 MB; use on a paid instance), or off. */
    GEOIP_EDITION: z.enum(['country', 'city', 'off']).default('country'),
    GEOIP_DIR: z.string().default('.geoip'),
    /** Timezone for "today", daily buckets and hour-of-day charts. */
    REPORT_TIMEZONE: z.string().default('UTC'),
    /** Page-view/heartbeat beacons accepted per IP per minute. */
    COLLECT_RATE_PER_MINUTE: z.coerce.number().int().min(10).max(10_000).default(120),
    // Alert notifications (Phase 5): brevo sends email; log only writes to the log (default); off sends nothing.
    EMAIL_TRANSPORT: z.enum(['brevo', 'log', 'off']).default('log'),
    BREVO_API_KEY: optional,
    ALERT_EMAIL_FROM: optional,
    ALERT_EMAIL_FROM_NAME: z.string().default('CampusHub Sentinel'),
  })
  .superRefine((v, ctx) => {
    if (v.NODE_ENV === 'production' && !v.APP_ORIGIN.startsWith('https://')) {
      ctx.addIssue({ code: 'custom', path: ['APP_ORIGIN'], message: 'APP_ORIGIN must be https in production' });
    }
    if (v.EMAIL_TRANSPORT === 'brevo' && (!v.BREVO_API_KEY || !v.ALERT_EMAIL_FROM)) {
      ctx.addIssue({ code: 'custom', path: ['BREVO_API_KEY'], message: 'EMAIL_TRANSPORT=brevo needs BREVO_API_KEY and ALERT_EMAIL_FROM' });
    }
    try {
      new Intl.DateTimeFormat('en', { timeZone: v.REPORT_TIMEZONE });
    } catch {
      ctx.addIssue({ code: 'custom', path: ['REPORT_TIMEZONE'], message: 'Unknown IANA timezone' });
    }
    if (v.NODE_ENV === 'production' && /replace-with|test-only/.test(Buffer.from(v.DATA_ENCRYPTION_KEY, 'base64').toString('latin1'))) {
      ctx.addIssue({ code: 'custom', path: ['DATA_ENCRYPTION_KEY'], message: 'DATA_ENCRYPTION_KEY is a placeholder' });
    }
  });

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid environment configuration:');
  for (const issue of parsed.error.issues) console.error(`  ${issue.path.join('.')}: ${issue.message}`);
  process.exit(1);
}

export const config = {
  ...parsed.data,
  production: parsed.data.NODE_ENV === 'production',
  /** __Host- cookies must be Secure; plain-http local development uses an unprefixed name. */
  SESSION_COOKIE: parsed.data.NODE_ENV === 'production' ? '__Host-sentinel_session' : 'sentinel_session',
};
export type Config = typeof config;

export const appVersion = config.APP_VERSION ?? (config.RENDER_GIT_COMMIT ? `0.1.0+${config.RENDER_GIT_COMMIT.slice(0, 7)}` : '0.1.0');
