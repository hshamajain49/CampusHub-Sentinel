// Live updates for the dashboard over Server-Sent Events. Page views mark the hub dirty; at most every 2 seconds one
// summary query runs and is pushed to every open dashboard (no per-client polling of the database). Each stream
// re-checks its session every minute and closes when it has ended.
import type { Request, Response } from 'express';
import { pool } from '../../db/pool.js';
import { logger } from '../../lib/logger.js';

interface Client {
  res: Response;
  stillValid: () => Promise<boolean>;
}

export interface LiveSummary {
  at: string;
  apps: Record<
    string,
    {
      online: number;
      pageViews5m: number;
      lastPath: string | null;
      openAlerts: { critical: number; high: number; medium: number; low: number };
      events5m: number;
      lastIngestAt: string | null;
    }
  >;
}

const ONLINE_WINDOW = "interval '2 minutes'";

export async function liveSummary(): Promise<LiveSummary> {
  const { rows } = await pool.query(
    `select a.slug, a.last_ingest_at,
            (select count(*)::int from public.analytics_sessions s where s.app_id = a.id and s.last_activity_at > now() - ${ONLINE_WINDOW}) as online,
            (select count(*)::int from public.analytics_events e where e.app_id = a.id and e.occurred_at > now() - interval '5 minutes') as page_views_5m,
            (select e.path from public.analytics_events e where e.app_id = a.id order by e.occurred_at desc limit 1) as last_path,
            (select count(*)::int from public.security_events e where e.app_id = a.id and e.received_at > now() - interval '5 minutes') as events_5m,
            (select jsonb_build_object(
                      'critical', count(*) filter (where severity = 'critical'), 'high', count(*) filter (where severity = 'high'),
                      'medium', count(*) filter (where severity = 'medium'), 'low', count(*) filter (where severity = 'low'))
               from public.security_alerts al where al.app_id = a.id and al.status in ('open', 'acknowledged')) as open_alerts
       from public.monitored_applications a where a.is_active`,
  );
  return {
    at: new Date().toISOString(),
    apps: Object.fromEntries(
      rows.map((r) => [
        r.slug,
        {
          online: r.online,
          pageViews5m: r.page_views_5m,
          lastPath: r.last_path,
          openAlerts: r.open_alerts,
          events5m: r.events_5m,
          lastIngestAt: r.last_ingest_at ? new Date(r.last_ingest_at).toISOString() : null,
        },
      ]),
    ),
  };
}

class LiveHub {
  private clients = new Set<Client>();
  private dirty = false;
  private timers: NodeJS.Timeout[] = [];

  get size() {
    return this.clients.size;
  }

  /** Something changed (a page view, a security event): push a fresh summary on the next tick. */
  notify() {
    this.dirty = true;
  }

  /** A new or escalated alert: pushed at once (the dashboard shows a notification), then the summary refreshes. */
  alert(payload: { id: string; severity: string; title: string; created: boolean; simulated: boolean }) {
    for (const c of this.clients) this.send(c, 'alert', { ...payload, at: new Date().toISOString() });
    this.dirty = true;
  }

  private send(c: Client, event: string, data: unknown) {
    c.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  private ensureTimers() {
    if (this.timers.length) return;
    const tick = setInterval(() => void this.flush(), 2_000);
    const ping = setInterval(() => {
      for (const c of this.clients) c.res.write(': keep-alive\n\n');
    }, 25_000);
    const check = setInterval(() => void this.revalidate(), 60_000);
    for (const t of [tick, ping, check]) t.unref();
    this.timers = [tick, ping, check];
  }

  private stopTimersIfIdle() {
    if (this.clients.size) return;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
  }

  private async flush() {
    if (!this.dirty || !this.clients.size) return;
    this.dirty = false;
    try {
      const summary = await liveSummary();
      for (const c of this.clients) this.send(c, 'analytics', summary);
    } catch (err) {
      logger.warn({ err }, 'live summary failed');
    }
  }

  private async revalidate() {
    for (const c of [...this.clients]) {
      if (!(await c.stillValid().catch(() => false))) {
        this.send(c, 'session-ended', {});
        c.res.end();
        this.clients.delete(c);
      }
    }
    this.stopTimersIfIdle();
  }

  async open(req: Request, res: Response, stillValid: () => Promise<boolean>) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no', // no proxy buffering
    });
    res.write('retry: 5000\n\n');
    const client: Client = { res, stillValid };
    this.clients.add(client);
    this.ensureTimers();
    this.send(client, 'analytics', await liveSummary());
    req.on('close', () => {
      this.clients.delete(client);
      this.stopTimersIfIdle();
    });
  }
}

export const liveHub = new LiveHub();
