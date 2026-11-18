// Rule-based detection. For each new event, every enabled rule listening to its category counts matching events in
// the rule's window (measured back from the event's own time, so late batches are judged correctly), grouped by IP,
// user, account or route. Reaching the threshold raises an alert, or adds to the one already open for that group.
// Rules only ever say "suspicious" or "policy violation": verified access and compromise are a person's call.
import { pool } from '../../db/pool.js';
import { logger } from '../../lib/logger.js';
import { raiseAlert, type RaisedAlert } from './alerts.service.js';
import { autoBlock, boostForAlert } from './ips.service.js';
import { allRules, rank, type Rule } from './rules.js';

export interface StoredEvent {
  id: string;
  appId: string;
  category: string;
  severity: string;
  occurredAt: Date;
  sourceIp: string | null;
  userRef: string | null;
  actorRole: string | null;
  route: string | null;
  path: string | null;
  details: Record<string, unknown>;
  simulated: boolean;
}

/**
 * Which events belong to the same group, as SQL over security_events ($5, $6 = the group's values). Every variant
 * mentions both parameters with a type: Postgres refuses a statement with an unused, untyped parameter.
 */
const GROUP_SQL = {
  source_ip: 'source_ip = $5::inet and $6::text is null',
  user_ref: 'user_ref = $5::text and $6::text is null',
  account: "details ->> 'accountKey' = $5::text and $6::text is null",
  source_ip_route: 'source_ip = $5::inet and route = $6::text',
  app: "$5::text = 'app' and $6::text is null",
} as const;

const DISTINCT_SQL = {
  account: "details ->> 'accountKey'",
  source_ip: 'source_ip',
  user_ref: 'user_ref',
  route: 'route',
} as const;

function groupValues(rule: Rule, ev: StoredEvent): [string, string | null] | null {
  switch (rule.groupBy) {
    case 'source_ip':
      return ev.sourceIp ? [ev.sourceIp, null] : null;
    case 'user_ref':
      return ev.userRef ? [ev.userRef, null] : null;
    case 'account':
      return typeof ev.details.accountKey === 'string' ? [ev.details.accountKey, null] : null;
    case 'source_ip_route':
      return ev.sourceIp && ev.route ? [ev.sourceIp, ev.route] : null;
    case 'app':
      return ['app', null];
  }
}

const escapeLike = (s: string) => s.replace(/[\\%_]/g, (c) => `\\${c}`);
const windowText = (s: number) => (s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`);
const groupLabel = (rule: Rule, values: [string, string | null]) =>
  rule.groupBy === 'account' ? `account ${values[0].slice(0, 10)}…` : rule.groupBy === 'app' ? 'the application' : values.filter(Boolean).join(' ');

/** Does this event fall under the rule's extra conditions (route prefix, actor role)? */
function eventMatchesParams(rule: Rule, ev: StoredEvent): boolean {
  const prefix = rule.params.route_prefix;
  if (typeof prefix === 'string' && !(ev.route ?? ev.path ?? '').startsWith(prefix)) return false;
  const role = rule.params.role;
  if (typeof role === 'string' && ev.actorRole !== role) return false;
  return true;
}

async function evaluateRule(rule: Rule, ev: StoredEvent): Promise<RaisedAlert | null> {
  if (!eventMatchesParams(rule, ev)) return null;
  const values = groupValues(rule, ev);
  if (!values) return null;

  // Super Admin from a new IP: a sign-in from an address not seen for that account in the lookback period
  // (the very first recorded sign-in is not "new": there is nothing to compare with).
  if (typeof rule.params.lookback_days === 'number') {
    if (!ev.sourceIp || !ev.userRef) return null;
    const { rows } = await pool.query<{ total: number; same: number }>(
      `select count(*)::int as total, count(*) filter (where source_ip = $4::inet)::int as same
         from public.security_events
        where app_id = $1 and category = 'auth.login_succeeded' and user_ref = $2 and id <> $3
          and occurred_at > $5::timestamptz - make_interval(days => $6) and occurred_at <= $5`,
      [ev.appId, ev.userRef, ev.id, ev.sourceIp, ev.occurredAt, rule.params.lookback_days],
    );
    const r = rows[0]!;
    if (r.total === 0 || r.same > 0) return null;
    return raiseAlert({
      appId: ev.appId,
      rule,
      groupKey: values[0],
      severity: rule.severity,
      title: `${rule.name}: ${ev.userRef}`,
      reason: `${ev.userRef} (${ev.actorRole}) signed in from ${ev.sourceIp}, an address not seen for this account in the last ${rule.params.lookback_days} days.`,
      eventId: ev.id,
      count: 1,
      simulated: ev.simulated,
    });
  }

  const prefix = typeof rule.params.route_prefix === 'string' ? escapeLike(rule.params.route_prefix) : null;
  const role = typeof rule.params.role === 'string' ? rule.params.role : null;
  const { rows } = await pool.query<{ n: number; d: number; ips: number }>(
    `select count(*)::int as n, count(distinct ${rule.distinctField ? DISTINCT_SQL[rule.distinctField] : 'null::text'})::int as d,
            count(distinct source_ip)::int as ips
       from public.security_events
      where app_id = $1 and category = any($2::text[])
        and occurred_at > $3::timestamptz - make_interval(secs => $4) and occurred_at <= $3
        and ${GROUP_SQL[rule.groupBy]}
        and ($7::text is null or coalesce(route, path, '') like $7 || '%')
        and ($8::text is null or actor_role = $8)`,
    [ev.appId, rule.categories, ev.occurredAt, rule.windowSeconds, values[0], values[1], prefix, role],
  );
  const c = rows[0]!;
  const measured = rule.distinctField ? c.d : c.n;
  if (measured < rule.threshold) return null;
  const minIps = rule.params.min_distinct_ips;
  if (typeof minIps === 'number' && c.ips < minIps) return null;

  let severity = rule.severity;
  if (typeof rule.params.escalate_at === 'number' && c.n >= rule.params.escalate_at && rank(rule.params.escalate_severity) > rank(severity)) {
    severity = rule.params.escalate_severity;
  }
  const what = rule.distinctField
    ? `${c.d} different ${rule.distinctField === 'account' ? 'accounts' : `${rule.distinctField}s`} (${c.n} ${rule.categories.join('/')} events)`
    : `${c.n} ${rule.categories.join('/')} events`;
  const extra = typeof minIps === 'number' ? ` from ${c.ips} IP addresses` : '';
  return raiseAlert({
    appId: ev.appId,
    rule,
    groupKey: values.filter(Boolean).join(' '),
    severity,
    title: `${rule.name}: ${groupLabel(rule, values)}`,
    reason: `${what}${extra} for ${groupLabel(rule, values)} within ${windowText(rule.windowSeconds)} (threshold ${rule.threshold}${
      typeof minIps === 'number' ? `, at least ${minIps} IPs` : ''
    }).`,
    eventId: ev.id,
    count: measured,
    simulated: ev.simulated,
  });
}

/** Runs every enabled rule that listens to this event's category. A failing rule never stops the others. */
export async function evaluateEvent(ev: StoredEvent): Promise<RaisedAlert[]> {
  const out: RaisedAlert[] = [];
  for (const rule of await allRules()) {
    if (!rule.enabled || !rule.categories.includes(ev.category)) continue;
    try {
      const alert = await evaluateRule(rule, ev);
      if (!alert) continue;
      out.push(alert);
      // Simulated (test) traffic raises simulated alerts only: it never changes an address's risk score or blocks it.
      if (ev.simulated) continue;
      if ((alert.created || alert.escalated) && ev.sourceIp && (rule.groupBy === 'source_ip' || rule.groupBy === 'source_ip_route')) {
        await boostForAlert(ev.appId, ev.sourceIp, rule.key);
      }
      if (rule.autoBlock && ev.sourceIp && (rule.groupBy === 'source_ip' || rule.groupBy === 'source_ip_route') && !alert.suppressed) {
        await autoBlock(ev.appId, ev.sourceIp, rule, alert.id);
      }
    } catch (err) {
      logger.error({ err, rule: rule.key, event: ev.id }, 'detection rule failed');
    }
  }
  return out;
}

/** Traffic spike: the newest minute against the median of the hour before it (needs 15+ minutes of history). */
export async function evaluateTraffic(appId: string, minute: Date, requests: number): Promise<RaisedAlert | null> {
  const rule = (await allRules()).find((r) => r.key === 'traffic_spike' && r.enabled);
  if (!rule) return null;
  const multiplier = Number(rule.params.multiplier ?? 5);
  const minRpm = Number(rule.params.min_rpm ?? 300);
  if (requests <= minRpm) return null;
  const { rows } = await pool.query<{ median: number | null; n: number }>(
    `select percentile_cont(0.5) within group (order by requests)::float8 as median, count(*)::int as n
       from public.traffic_minutes where app_id = $1 and minute >= $2::timestamptz - interval '60 minutes' and minute < $2`,
    [appId, minute],
  );
  const { median, n } = rows[0]!;
  if (n < 15 || median === null || requests <= multiplier * median) return null;
  return raiseAlert({
    appId,
    rule,
    groupKey: 'app',
    severity: rule.severity,
    title: `${rule.name}: ${requests} requests/min`,
    reason: `${requests} requests in the minute starting ${minute.toISOString()}, ${(requests / Math.max(median, 1)).toFixed(1)}× the median of the previous hour (${median}); thresholds: ${multiplier}× and over ${minRpm}/min.`,
    eventId: null,
    count: requests,
    simulated: false,
  });
}
