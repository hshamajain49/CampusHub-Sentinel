// Records one page view or heartbeat. Sessions are built here, not in the browser: a visitor's session continues
// while hits keep arriving within 30 minutes; after that the next hit starts a new one. Upserting the visitor row
// locks it, so two tabs of the same visitor can't open two sessions at once.
import { withTransaction } from '../../db/pool.js';
import { keyedHash } from '../../lib/crypto.js';
import { lookupIp } from '../../lib/geoip.js';
import type { MonitoredApp } from '../apps/apps.service.js';
import { classifyReferrer, normalizePath, parseUserAgent, truncateIp, viewportBucket } from './parse.js';

export const SESSION_TIMEOUT_MINUTES = 30;

export interface Hit {
  app: MonitoredApp;
  type: 'pageview' | 'heartbeat';
  visitorKey: string;
  path: string;
  referrer?: string;
  viewportWidth?: number;
  utm: { source?: string; medium?: string; campaign?: string };
  userRef?: string;
  ip: string | null;
  userAgent: string | null;
}

export async function recordHit(h: Hit): Promise<{ sessionId: string; newSession: boolean; newVisitor: boolean }> {
  const path = normalizePath(h.path);
  return withTransaction(async (tx) => {
    const visitor = (
      await tx.query<{ id: number; sessions_count: number }>(
        `insert into public.analytics_visitors as v (app_id, visitor_key) values ($1, $2)
         on conflict (app_id, visitor_key) do update set last_seen_at = now()
         returning id, sessions_count`,
        [h.app.id, h.visitorKey],
      )
    ).rows[0]!;

    const current = (
      await tx.query<{ id: string }>(
        `select id from public.analytics_sessions
          where visitor_id = $1 and last_activity_at > now() - make_interval(mins => $2)
          order by last_activity_at desc limit 1`,
        [visitor.id, SESSION_TIMEOUT_MINUTES],
      )
    ).rows[0];

    if (current) {
      if (h.type === 'pageview') {
        await tx.query(
          `update public.analytics_sessions
              set page_views = page_views + 1, exit_path = $2, last_activity_at = now(), user_ref = coalesce($3, user_ref)
            where id = $1`,
          [current.id, path, h.userRef ?? null],
        );
        await tx.query('insert into public.analytics_events (app_id, session_id, path) values ($1, $2, $3)', [h.app.id, current.id, path]);
      } else {
        await tx.query('update public.analytics_sessions set last_activity_at = now() where id = $1', [current.id]);
      }
      return { sessionId: current.id, newSession: false, newVisitor: false };
    }

    // A new session (a heartbeat after a long pause counts as viewing the page it's on).
    const agent = parseUserAgent(h.userAgent);
    const geo = lookupIp(h.ip);
    const campaign = !!(h.utm.source || h.utm.medium || h.utm.campaign);
    const ref = classifyReferrer(h.referrer, h.app.allowedOrigins, campaign);
    const newVisitor = visitor.sessions_count === 0;
    const session = (
      await tx.query<{ id: string }>(
        `insert into public.analytics_sessions
           (app_id, visitor_id, is_new_visitor, entry_path, exit_path, page_views, referrer_host, referrer_source,
            utm_source, utm_medium, utm_campaign, device_type, browser, browser_version, os, viewport,
            country, region, city, ip_truncated, ip_hash, user_ref)
         values ($1, $2, $3, $4, $4, 1, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18::inet, $19, $20)
         returning id`,
        [
          h.app.id,
          visitor.id,
          newVisitor,
          path,
          ref.host,
          ref.source,
          h.utm.source ?? null,
          h.utm.medium ?? null,
          h.utm.campaign ?? null,
          agent.deviceType,
          agent.browser,
          agent.browserVersion,
          agent.os,
          viewportBucket(h.viewportWidth),
          geo?.country ?? null,
          geo?.region ?? null,
          geo?.city ?? null,
          truncateIp(h.ip),
          h.ip ? keyedHash(h.ip, 'ip-hash') : null,
          h.userRef ?? null,
        ],
      )
    ).rows[0]!;
    await tx.query('update public.analytics_visitors set sessions_count = sessions_count + 1 where id = $1', [visitor.id]);
    await tx.query('insert into public.analytics_events (app_id, session_id, path) values ($1, $2, $3)', [h.app.id, session.id, path]);
    return { sessionId: session.id, newSession: true, newVisitor };
  });
}
