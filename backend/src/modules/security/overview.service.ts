// Read side of security monitoring: overview numbers, timeline, the event log, and the health status. The status is
// derived from real signals only (open alerts, ingestion freshness), never set by hand.
import { pool } from '../../db/pool.js';
import { appError } from '../../errors/app-error.js';
import type { MonitoredApp } from '../apps/apps.service.js';
import type { Range } from '../analytics/analytics.service.js';
import { config } from '../../config/env.js';

const STALE_MINUTES = 10;

export async function healthStatus(appId: string) {
  const { rows } = await pool.query(
    `select a.last_ingest_at,
            count(al.*) filter (where al.severity = 'critical' and not al.simulated)::int as critical,
            count(al.*) filter (where al.severity = 'high' and not al.simulated)::int as high
       from public.monitored_applications a
       left join public.security_alerts al on al.app_id = a.id and al.status in ('open', 'acknowledged')
      where a.id = $1 group by a.id`,
    [appId],
  );
  const r = rows[0];
  const reasons: string[] = [];
  let status: 'healthy' | 'warning' | 'critical' = 'healthy';
  if (r.critical > 0) {
    status = 'critical';
    reasons.push(`${r.critical} open critical alert${r.critical === 1 ? '' : 's'}`);
  }
  if (r.high > 0) {
    if (status === 'healthy') status = 'warning';
    reasons.push(`${r.high} open high alert${r.high === 1 ? '' : 's'}`);
  }
  const last = r.last_ingest_at ? new Date(r.last_ingest_at) : null;
  const stale = !last || Date.now() - last.getTime() > STALE_MINUTES * 60_000;
  if (stale) {
    if (status === 'healthy') status = 'warning';
    reasons.push(last ? `No security data from the application for ${Math.round((Date.now() - last.getTime()) / 60_000)} minutes` : 'The application has never sent security data');
  }
  return { status, reasons, lastIngestAt: last?.toISOString() ?? null };
}

export async function securityOverview(app: MonitoredApp, r: Range) {
  const args = [app.id, r.from, r.to];
  const [bySeverity, alertsOpen, alertsOpened, incidents, suspicious, blocks, endpoints, categories, recent, requests, health] = await Promise.all([
    pool.query(
      `select severity, count(*)::int as n, count(*) filter (where simulated)::int as simulated
         from public.security_events where app_id = $1 and occurred_at >= $2 and occurred_at < $3 group by 1`,
      args,
    ),
    pool.query(
      "select severity, count(*)::int as n from public.security_alerts where app_id = $1 and status in ('open', 'acknowledged') group by 1",
      [app.id],
    ),
    pool.query('select count(*)::int as n from public.security_alerts where app_id = $1 and first_seen_at >= $2 and first_seen_at < $3', args),
    pool.query(
      `select count(*) filter (where status in ('new', 'investigating'))::int as open,
              count(*) filter (where status = 'resolved' and resolved_at >= $2 and resolved_at < $3)::int as resolved,
              count(*) filter (where status = 'false_positive' and resolved_at >= $2 and resolved_at < $3)::int as false_positive,
              count(*) filter (where classification in ('unauthorized_access_verified', 'compromise_confirmed') and status <> 'false_positive')::int as confirmed
         from public.security_incidents where app_id = $1`,
      args,
    ),
    pool.query(
      `select count(*)::int as n from public.suspicious_ips
        where app_id = $1 and risk_score * power(0.5, extract(epoch from now() - last_detected_at) / 86400) >= 10`,
      [app.id],
    ),
    pool.query('select count(*)::int as n from public.ip_blocks where app_id = $1 and lifted_at is null and expires_at > now()', [app.id]),
    pool.query(
      `select coalesce(route, path) as endpoint, count(*)::int as events, count(distinct source_ip)::int as ips,
              max(public.severity_rank(severity)) as worst
         from public.security_events
        where app_id = $1 and occurred_at >= $2 and occurred_at < $3 and severity <> 'info' and coalesce(route, path) is not null
        group by 1 order by 2 desc limit 10`,
      args,
    ),
    pool.query(
      `select category, count(*)::int as n from public.security_events
        where app_id = $1 and occurred_at >= $2 and occurred_at < $3 group by 1 order by 2 desc limit 15`,
      args,
    ),
    pool.query(
      `select id, occurred_at, category, severity, host(source_ip) as source_ip, user_ref, method, route, status_code, description, simulated
         from public.security_events where app_id = $1 order by occurred_at desc limit 15`,
      [app.id],
    ),
    pool.query('select coalesce(sum(requests), 0)::int as n from public.traffic_minutes where app_id = $1 and minute >= $2 and minute < $3', args),
    healthStatus(app.id),
  ]);
  const sev = Object.fromEntries(bySeverity.rows.map((x) => [x.severity, x.n]));
  const open = Object.fromEntries(alertsOpen.rows.map((x) => [x.severity, x.n]));
  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  return {
    range: { from: r.from.toISOString(), to: r.to.toISOString() },
    health,
    events: {
      total: bySeverity.rows.reduce((n, x) => n + x.n, 0),
      simulated: bySeverity.rows.reduce((n, x) => n + x.simulated, 0),
      bySeverity: Object.fromEntries(levels.map((l) => [l, sev[l] ?? 0])),
    },
    alerts: {
      active: alertsOpen.rows.reduce((n, x) => n + x.n, 0),
      openBySeverity: Object.fromEntries(levels.slice(1).map((l) => [l, open[l] ?? 0])),
      openedInRange: alertsOpened.rows[0].n,
    },
    incidents: incidents.rows[0] as { open: number; resolved: number; false_positive: number; confirmed: number },
    suspiciousIps: suspicious.rows[0].n,
    activeBlocks: blocks.rows[0].n,
    requests: requests.rows[0].n,
    // severity_rank() is 1-based (array_position), the levels list 0-based
    topEndpoints: endpoints.rows.map((x) => ({ endpoint: x.endpoint, events: x.events, ips: x.ips, worstSeverity: levels[x.worst - 1] ?? 'info' })),
    topCategories: categories.rows.map((x) => ({ category: x.category, events: x.n })),
    recentEvents: recent.rows.map(toEvent),
  };
}

export async function securityTimeseries(app: MonitoredApp, r: Range) {
  const { rows } = await pool.query(
    `with b as (
       select generate_series(date_trunc($4::text, $2::timestamptz at time zone $5),
                              date_trunc($4::text, ($3::timestamptz - interval '1 microsecond') at time zone $5),
                              ('1 ' || $4)::interval) as k),
     e as (
       select date_trunc($4::text, occurred_at at time zone $5) as k,
              count(*) filter (where severity in ('info', 'low'))::int as low,
              count(*) filter (where severity = 'medium')::int as medium,
              count(*) filter (where severity in ('high', 'critical'))::int as high
         from public.security_events where app_id = $1 and occurred_at >= $2 and occurred_at < $3 group by 1),
     a as (
       select date_trunc($4::text, first_seen_at at time zone $5) as k, count(*)::int as alerts
         from public.security_alerts where app_id = $1 and first_seen_at >= $2 and first_seen_at < $3 group by 1),
     t as (
       select date_trunc($4::text, minute at time zone $5) as k, sum(requests)::int as requests
         from public.traffic_minutes where app_id = $1 and minute >= $2 and minute < $3 group by 1)
     select to_char(b.k, 'YYYY-MM-DD"T"HH24:MI') as bucket, coalesce(e.low, 0) as low, coalesce(e.medium, 0) as medium,
            coalesce(e.high, 0) as high, coalesce(a.alerts, 0) as alerts, coalesce(t.requests, 0) as requests
       from b left join e on e.k = b.k left join a on a.k = b.k left join t on t.k = b.k order by b.k`,
    [app.id, r.from, r.to, r.granularity, config.REPORT_TIMEZONE],
  );
  return { granularity: r.granularity, timezone: config.REPORT_TIMEZONE, points: rows };
}

function toEvent(e: any) {
  return {
    id: e.id,
    occurredAt: new Date(e.occurred_at).toISOString(),
    receivedAt: e.received_at ? new Date(e.received_at).toISOString() : undefined,
    category: e.category,
    severity: e.severity,
    sourceIp: e.source_ip,
    userRef: e.user_ref,
    actorRole: e.actor_role,
    method: e.method,
    route: e.route,
    path: e.path,
    statusCode: e.status_code,
    description: e.description,
    details: e.details,
    simulated: e.simulated,
    alerts: e.alerts,
  };
}

export async function listEvents(
  app: MonitoredApp,
  r: Range,
  q: { severity?: string[]; category?: string; ip?: string; userRef?: string; route?: string; simulated?: boolean; page: number; pageSize: number },
) {
  const params: unknown[] = [app.id, r.from, r.to];
  const where = ['app_id = $1', 'occurred_at >= $2', 'occurred_at < $3'];
  const add = (sql: string, v: unknown) => {
    params.push(v);
    where.push(sql.replace('$?', `$${params.length}`));
  };
  if (q.severity?.length) add('severity = any($?::text[])', q.severity);
  if (q.category) add('category = $?', q.category);
  if (q.ip) add('source_ip <<= $?::inet', q.ip);
  if (q.userRef) add('user_ref = $?', q.userRef);
  if (q.route) add("coalesce(route, path) like $? || '%'", q.route.replace(/[\\%_]/g, (c) => `\\${c}`));
  if (q.simulated !== undefined) add('simulated = $?', q.simulated);
  const filter = `where ${where.join(' and ')}`;
  const total = (await pool.query<{ n: number }>(`select count(*)::int as n from public.security_events ${filter}`, params)).rows[0]!.n;
  params.push(q.pageSize, (q.page - 1) * q.pageSize);
  const limit = `$${params.length - 1}`;
  const offset = `$${params.length}`;
  const { rows } = await pool.query(
    `select id, occurred_at, received_at, category, severity, host(source_ip) as source_ip, user_ref, actor_role, method, route, path,
            status_code, description, simulated
       from public.security_events ${filter} order by occurred_at desc limit ${limit} offset ${offset}`,
    params,
  );
  return { data: rows.map(toEvent), meta: { page: q.page, pageSize: q.pageSize, total, totalPages: Math.max(1, Math.ceil(total / q.pageSize)) } };
}

export async function getEvent(appId: string, id: string) {
  const { rows } = await pool.query(
    `select e.id, e.occurred_at, e.received_at, e.category, e.severity, host(e.source_ip) as source_ip, e.user_ref, e.actor_role, e.method,
            e.route, e.path, e.status_code, e.description, e.details, e.simulated,
            coalesce((select jsonb_agg(jsonb_build_object('id', a.id, 'title', a.title, 'status', a.status, 'severity', a.severity))
                        from public.alert_events ae join public.security_alerts a on a.id = ae.alert_id where ae.event_id = e.id), '[]') as alerts
       from public.security_events e where e.app_id = $1 and e.id = $2`,
    [appId, id],
  );
  if (!rows[0]) throw appError('NOT_FOUND', 'Event not found.');
  return toEvent(rows[0]);
}
