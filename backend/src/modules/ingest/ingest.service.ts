// Stores a signed batch from a monitored app (security events + per-minute traffic counters), then runs detection.
// Replays are harmless: events dedupe on (app, event id) and a minute's counters are overwritten, not added.
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import { logger } from '../../lib/logger.js';
import { liveHub } from '../analytics/live.js';
import { evaluateEvent, evaluateTraffic, type StoredEvent } from '../security/engine.js';
import { recordSuspicious } from '../security/ips.service.js';
import { allRules } from '../security/rules.js';

const ip = z.union([z.ipv4(), z.ipv6()]);
const count = z.number().int().min(0).max(10_000_000);

export const eventSchema = z.strictObject({
  id: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/),
  occurredAt: z.iso.datetime({ offset: true }),
  category: z.string().max(60).regex(/^[a-z][a-z_]*\.[a-z][a-z_]*$/),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']),
  sourceIp: ip.optional(),
  userRef: z.string().max(64).optional(),
  actorRole: z.string().max(40).optional(),
  method: z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']).optional(),
  route: z.string().max(200).optional(),
  path: z.string().max(300).optional(),
  statusCode: z.number().int().min(100).max(599).optional(),
  description: z.string().min(1).max(500),
  details: z.record(z.string(), z.unknown()).optional(),
  simulated: z.boolean().optional(),
});

export const batchSchema = z.strictObject({
  events: z.array(eventSchema).max(500).default([]),
  traffic: z
    .array(
      z.strictObject({
        minute: z.iso.datetime({ offset: true }),
        requests: count,
        status2xx: count.default(0),
        status3xx: count.default(0),
        status4xx: count.default(0),
        status5xx: count.default(0),
      }),
    )
    .max(120)
    .default([]),
});
export type Batch = z.infer<typeof batchSchema>;

const MAX_AGE_MS = 7 * 86_400_000;
const SECRET_KEY = /pass(word|wd)?|secret|token|authori[sz]ation|cookie|api[-_]?key|session|otp|totp|recovery/i;

/** Defence in depth: whatever the sender puts in details, credential-looking fields never reach storage. */
export function redactDetails(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[truncated]';
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redactDetails(v, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value).slice(0, 40)) out[k.slice(0, 60)] = SECRET_KEY.test(k) && k !== 'accountKey' ? '[redacted]' : redactDetails(v, depth + 1);
    return out;
  }
  if (typeof value === 'string') return value.slice(0, 500);
  return typeof value === 'number' || typeof value === 'boolean' || value === null ? value : String(value).slice(0, 100);
}

function safeDetails(d: Record<string, unknown> | undefined): Record<string, unknown> {
  const red = redactDetails(d ?? {}) as Record<string, unknown>;
  return JSON.stringify(red).length > 6000 ? { truncated: true } : red;
}

export async function ingestBatch(appId: string, batch: Batch) {
  const now = Date.now();
  const stored: StoredEvent[] = [];
  let duplicates = 0;
  let dropped = 0;
  const watched = new Set((await allRules()).filter((r) => r.enabled).flatMap((r) => r.categories));

  const ordered = [...batch.events].sort((a, b) => Date.parse(a.occurredAt) - Date.parse(b.occurredAt));
  for (const e of ordered) {
    const at = Date.parse(e.occurredAt);
    if (now - at > MAX_AGE_MS) {
      dropped++;
      continue;
    }
    const occurredAt = new Date(Math.min(at, now)); // a sender clock running ahead can't place events in the future
    const details = safeDetails(e.details);
    const { rows } = await pool.query<{ id: string }>(
      `insert into public.security_events
         (app_id, event_id, occurred_at, category, severity, source_ip, user_ref, actor_role, method, route, path, status_code, description, details, simulated)
       values ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11, $12, $13, $14, $15)
       on conflict (app_id, event_id) do nothing returning id`,
      [
        appId,
        e.id,
        occurredAt,
        e.category,
        e.severity,
        e.sourceIp ?? null,
        e.userRef ?? null,
        e.actorRole ?? null,
        e.method ?? null,
        e.route ?? null,
        e.path ?? null,
        e.statusCode ?? null,
        e.description,
        JSON.stringify(details),
        e.simulated ?? false,
      ],
    );
    if (!rows[0]) {
      duplicates++;
      continue;
    }
    stored.push({
      id: rows[0].id,
      appId,
      category: e.category,
      severity: e.severity,
      occurredAt,
      sourceIp: e.sourceIp ?? null,
      userRef: e.userRef ?? null,
      actorRole: e.actorRole ?? null,
      route: e.route ?? null,
      path: e.path ?? null,
      details,
      simulated: e.simulated ?? false,
    });
  }

  for (const t of batch.traffic) {
    await pool.query(
      `insert into public.traffic_minutes as t (app_id, minute, requests, status_2xx, status_3xx, status_4xx, status_5xx)
       values ($1, date_trunc('minute', $2::timestamptz), $3, $4, $5, $6, $7)
       on conflict (app_id, minute) do update set requests = excluded.requests, status_2xx = excluded.status_2xx,
         status_3xx = excluded.status_3xx, status_4xx = excluded.status_4xx, status_5xx = excluded.status_5xx`,
      [appId, t.minute, t.requests, t.status2xx, t.status3xx, t.status4xx, t.status5xx],
    );
  }
  await pool.query(
    `update public.monitored_applications set last_ingest_at = now()
      where id = $1 and (last_ingest_at is null or last_ingest_at < now() - interval '15 seconds')`,
    [appId],
  );

  // Detection runs after storage: a failing rule never loses an event.
  let alerts = 0;
  for (const ev of stored) {
    try {
      if (ev.sourceIp && !ev.simulated) await recordSuspicious(pool, appId, ev.sourceIp, ev.severity, ev.category);
      if (watched.has(ev.category)) alerts += (await evaluateEvent(ev)).filter((a) => a.created || a.escalated).length;
    } catch (err) {
      logger.error({ err, event: ev.id }, 'detection failed for event');
    }
  }
  const latest = [...batch.traffic].sort((a, b) => Date.parse(b.minute) - Date.parse(a.minute))[0];
  if (latest) {
    const spike = await evaluateTraffic(appId, new Date(Math.floor(Date.parse(latest.minute) / 60_000) * 60_000), latest.requests).catch((err) => {
      logger.error({ err }, 'traffic detection failed');
      return null;
    });
    if (spike?.created || spike?.escalated) alerts++;
  }
  if (stored.length || batch.traffic.length) liveHub.notify();
  return { accepted: stored.length, duplicates, dropped, alerts };
}
