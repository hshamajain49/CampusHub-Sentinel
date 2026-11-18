// Read side of visitor analytics. Every query is scoped to one app and a time range; "today", daily buckets and
// hour-of-day use REPORT_TIMEZONE. Dimensions come from a fixed map, never from the request text.
import { config } from '../../config/env.js';
import { pool } from '../../db/pool.js';
import { appError } from '../../errors/app-error.js';
import type { MonitoredApp } from '../apps/apps.service.js';

export const RANGES = ['today', '7d', '30d', '90d', 'custom'] as const;
export type RangeName = (typeof RANGES)[number];
export interface RangeQuery {
  range: RangeName;
  from?: string; // YYYY-MM-DD (custom)
  to?: string; // YYYY-MM-DD (custom, inclusive)
}
export interface Range {
  from: Date;
  to: Date;
  granularity: 'hour' | 'day';
}

const DAYS: Record<Exclude<RangeName, 'custom'>, number> = { today: 0, '7d': 6, '30d': 29, '90d': 89 };
const ONLINE_MINUTES = 2;

export async function resolveRange(q: RangeQuery): Promise<Range> {
  const tz = config.REPORT_TIMEZONE;
  if (q.range === 'custom') {
    if (!q.from || !q.to) throw appError('VALIDATION_ERROR', 'A custom range needs from and to.', { fieldErrors: { from: ['Required'] } });
    const span = (Date.parse(q.to) - Date.parse(q.from)) / 86_400_000;
    if (span < 0) throw appError('VALIDATION_ERROR', 'The range ends before it starts.', { fieldErrors: { to: ['Must be on or after from'] } });
    if (span > 400) throw appError('VALIDATION_ERROR', 'Choose at most 400 days.', { fieldErrors: { to: ['At most 400 days'] } });
  }
  const { rows } = await pool.query<{ from_ts: Date; to_ts: Date }>(
    `select case when $1 = 'custom' then ($3::date)::timestamp at time zone $2
                 else (date_trunc('day', now() at time zone $2) - make_interval(days => $5)) at time zone $2 end as from_ts,
            case when $1 = 'custom' then (($4::date + 1)::timestamp) at time zone $2 else now() end as to_ts`,
    [q.range, tz, q.from ?? null, q.to ?? null, q.range === 'custom' ? 0 : DAYS[q.range]],
  );
  const { from_ts, to_ts } = rows[0]!;
  const hours = (to_ts.getTime() - from_ts.getTime()) / 3_600_000;
  return { from: from_ts, to: to_ts, granularity: hours <= 48 ? 'hour' : 'day' };
}

export async function overview(app: MonitoredApp, r: Range) {
  const tz = config.REPORT_TIMEZONE;
  const [range, pageViews, online, windows, totals] = await Promise.all([
    pool.query(
      `select count(*)::int as sessions,
              count(distinct visitor_id)::int as visitors,
              count(distinct visitor_id) filter (where is_new_visitor)::int as new_visitors,
              coalesce(round(avg(extract(epoch from last_activity_at - started_at)))::int, 0) as avg_session_seconds,
              coalesce(round(avg((page_views <= 1)::int) * 100, 1), 0)::float8 as bounce_rate
         from public.analytics_sessions where app_id = $1 and started_at >= $2 and started_at < $3`,
      [app.id, r.from, r.to],
    ),
    pool.query<{ n: number }>('select count(*)::int as n from public.analytics_events where app_id = $1 and occurred_at >= $2 and occurred_at < $3', [
      app.id,
      r.from,
      r.to,
    ]),
    pool.query<{ n: number }>(
      'select count(*)::int as n from public.analytics_sessions where app_id = $1 and last_activity_at > now() - make_interval(mins => $2)',
      [app.id, ONLINE_MINUTES],
    ),
    pool.query(
      `with b as (select date_trunc('day', now() at time zone $2) as today)
       select count(distinct s.visitor_id) filter (where s.started_at >= (b.today at time zone $2))::int as today,
              count(distinct s.visitor_id) filter (where s.started_at >= ((b.today - interval '6 days') at time zone $2))::int as week,
              count(distinct s.visitor_id)::int as month
         from b, public.analytics_sessions s
        where s.app_id = $1 and s.started_at >= ((b.today - interval '29 days') at time zone $2)`,
      [app.id, tz],
    ),
    pool.query(
      `select (select count(*)::int from public.analytics_visitors where app_id = $1) as visitors,
              (select count(*)::int from public.analytics_events where app_id = $1) as page_views`,
      [app.id],
    ),
  ]);
  const s = range.rows[0];
  return {
    range: { from: r.from.toISOString(), to: r.to.toISOString(), timezone: tz },
    visitors: s.visitors,
    newVisitors: s.new_visitors,
    returningVisitors: Math.max(0, s.visitors - s.new_visitors),
    sessions: s.sessions,
    pageViews: pageViews.rows[0]!.n,
    avgSessionSeconds: s.avg_session_seconds,
    bounceRate: s.bounce_rate,
    online: online.rows[0]!.n,
    visitorsToday: windows.rows[0].today,
    visitorsThisWeek: windows.rows[0].week,
    visitorsThisMonth: windows.rows[0].month,
    allTime: { visitors: totals.rows[0].visitors, pageViews: totals.rows[0].page_views },
  };
}

export async function timeseries(app: MonitoredApp, r: Range) {
  const { rows } = await pool.query(
    `with b as (
       select generate_series(date_trunc($4::text, $2::timestamptz at time zone $5),
                              date_trunc($4::text, ($3::timestamptz - interval '1 microsecond') at time zone $5),
                              ('1 ' || $4)::interval) as k),
     s as (
       select date_trunc($4::text, started_at at time zone $5) as k, count(*)::int as sessions, count(distinct visitor_id)::int as visitors
         from public.analytics_sessions where app_id = $1 and started_at >= $2 and started_at < $3 group by 1),
     e as (
       select date_trunc($4::text, occurred_at at time zone $5) as k, count(*)::int as page_views
         from public.analytics_events where app_id = $1 and occurred_at >= $2 and occurred_at < $3 group by 1)
     select to_char(b.k, 'YYYY-MM-DD"T"HH24:MI') as bucket, coalesce(s.visitors, 0) as visitors,
            coalesce(s.sessions, 0) as sessions, coalesce(e.page_views, 0) as page_views
       from b left join s on s.k = b.k left join e on e.k = b.k order by b.k`,
    [app.id, r.from, r.to, r.granularity, config.REPORT_TIMEZONE],
  );
  return {
    granularity: r.granularity,
    timezone: config.REPORT_TIMEZONE,
    points: rows.map((x) => ({ bucket: x.bucket, visitors: x.visitors, sessions: x.sessions, pageViews: x.page_views })),
  };
}

export async function hourOfDay(app: MonitoredApp, r: Range) {
  const { rows } = await pool.query(
    `select h as hour, coalesce(x.n, 0)::int as sessions
       from generate_series(0, 23) h
       left join (select extract(hour from started_at at time zone $4)::int as hr, count(*) as n
                    from public.analytics_sessions where app_id = $1 and started_at >= $2 and started_at < $3 group by 1) x on x.hr = h
      order by h`,
    [app.id, r.from, r.to, config.REPORT_TIMEZONE],
  );
  return { timezone: config.REPORT_TIMEZONE, hours: rows.map((x) => ({ hour: x.hour, sessions: x.sessions })) };
}

/** Session-level dimensions: column expressions picked from this map only. */
const SESSION_DIMENSIONS = {
  device: 'device_type',
  browser: 'browser',
  os: 'os',
  country: 'country',
  city: "nullif(concat_ws(', ', city, country), '')",
  source: 'referrer_source',
  referrer: 'referrer_host',
  viewport: 'viewport',
  entry: 'entry_path',
  exit: 'exit_path',
  visitor_type: "case when is_new_visitor then 'new' else 'returning' end",
} as const;
export const DIMENSIONS = ['page', ...Object.keys(SESSION_DIMENSIONS)] as [string, ...string[]];

export async function breakdown(app: MonitoredApp, r: Range, dimension: string, limit: number) {
  if (dimension === 'page') {
    const { rows } = await pool.query(
      `select path as key, count(*)::int as page_views, count(distinct session_id)::int as sessions
         from public.analytics_events where app_id = $1 and occurred_at >= $2 and occurred_at < $3
        group by 1 order by 2 desc, 1 limit $4`,
      [app.id, r.from, r.to, limit],
    );
    return { dimension, rows: rows.map((x) => ({ key: x.key, pageViews: x.page_views, sessions: x.sessions })) };
  }
  if (!Object.hasOwn(SESSION_DIMENSIONS, dimension)) throw appError('VALIDATION_ERROR', 'Unknown dimension');
  const dim = dimension as keyof typeof SESSION_DIMENSIONS;
  const { rows } = await pool.query(
    `select coalesce(${SESSION_DIMENSIONS[dim]}, 'unknown') as key, count(*)::int as sessions, count(distinct visitor_id)::int as visitors
       from public.analytics_sessions where app_id = $1 and started_at >= $2 and started_at < $3
      group by 1 order by 2 desc, 1 limit $4`,
    [app.id, r.from, r.to, limit],
  );
  return { dimension, rows: rows.map((x) => ({ key: x.key, sessions: x.sessions, visitors: x.visitors })) };
}

const SESSION_COLUMNS = `
  s.id, v.visitor_key, v.first_seen_at, s.started_at, s.last_activity_at, s.page_views, s.entry_path, s.exit_path,
  s.referrer_host, s.referrer_source, s.utm_source, s.utm_medium, s.utm_campaign, s.device_type, s.browser,
  s.browser_version, s.os, s.viewport, s.country, s.region, s.city, host(s.ip_truncated) as ip, s.is_new_visitor,
  s.user_ref, s.simulated, (s.last_activity_at > now() - interval '2 minutes') as online`;

function toSession(r: any) {
  return {
    id: r.id,
    visitor: { id: String(r.visitor_key).slice(0, 8), firstSeenAt: new Date(r.first_seen_at).toISOString(), isNew: r.is_new_visitor },
    startedAt: new Date(r.started_at).toISOString(),
    lastActivityAt: new Date(r.last_activity_at).toISOString(),
    durationSeconds: Math.round((new Date(r.last_activity_at).getTime() - new Date(r.started_at).getTime()) / 1000),
    pageViews: r.page_views,
    entryPath: r.entry_path,
    exitPath: r.exit_path,
    referrer: { host: r.referrer_host, source: r.referrer_source },
    utm: r.utm_source || r.utm_medium || r.utm_campaign ? { source: r.utm_source, medium: r.utm_medium, campaign: r.utm_campaign } : null,
    device: r.device_type,
    browser: r.browser ? `${r.browser}${r.browser_version ? ` ${r.browser_version}` : ''}` : null,
    os: r.os,
    viewport: r.viewport,
    location: { country: r.country, region: r.region, city: r.city },
    ip: r.ip ? `${r.ip}/${r.ip.includes(':') ? 48 : 24}` : null, // the network only, never the full address
    userRef: r.user_ref,
    simulated: r.simulated,
    online: r.online,
  };
}

export async function listSessions(app: MonitoredApp, r: Range, q: { live: boolean; page: number; pageSize: number; country?: string; device?: string }) {
  const params: unknown[] = [app.id];
  const where: string[] = ['s.app_id = $1'];
  const add = (sql: string, v: unknown) => {
    params.push(v);
    where.push(sql.replace('$?', `$${params.length}`));
  };
  if (q.live) add('s.last_activity_at > now() - make_interval(mins => $?)', ONLINE_MINUTES);
  else {
    add('s.started_at >= $?', r.from);
    add('s.started_at < $?', r.to);
  }
  if (q.country) add('s.country = $?', q.country);
  if (q.device) add('s.device_type = $?', q.device);
  const filter = `where ${where.join(' and ')}`;
  const total = (await pool.query<{ n: number }>(`select count(*)::int as n from public.analytics_sessions s ${filter}`, params)).rows[0]!.n;
  params.push(q.pageSize, (q.page - 1) * q.pageSize);
  const limit = `$${params.length - 1}`;
  const offset = `$${params.length}`;
  const { rows } = await pool.query(
    `select ${SESSION_COLUMNS} from public.analytics_sessions s join public.analytics_visitors v on v.id = s.visitor_id
     ${filter} order by s.last_activity_at desc limit ${limit} offset ${offset}`,
    params,
  );
  return { data: rows.map(toSession), meta: { page: q.page, pageSize: q.pageSize, total, totalPages: Math.max(1, Math.ceil(total / q.pageSize)) } };
}

export async function getSession(app: MonitoredApp, id: string) {
  const { rows } = await pool.query(
    `select ${SESSION_COLUMNS} from public.analytics_sessions s join public.analytics_visitors v on v.id = s.visitor_id
      where s.app_id = $1 and s.id = $2`,
    [app.id, id],
  );
  if (!rows[0]) throw appError('NOT_FOUND', 'Session not found.');
  const pages = await pool.query('select path, occurred_at from public.analytics_events where session_id = $1 order by occurred_at, id limit 500', [id]);
  return { ...toSession(rows[0]), pages: pages.rows.map((p) => ({ path: p.path, at: new Date(p.occurred_at).toISOString() })) };
}
