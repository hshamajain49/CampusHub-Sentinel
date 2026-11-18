// Alerts: one open alert per (app, rule, group). A repeat adds to it (occurrences, last seen) and can raise its
// severity but never lower it. After "false positive", the same rule and group stay quiet for the rule's cooldown;
// after "resolved", a new match opens a new alert straight away (the activity came back).
// New and escalated alerts are pushed to open dashboards at once and, if serious enough, emailed (notifier).
import { pool, withTransaction } from '../../db/pool.js';
import { appError } from '../../errors/app-error.js';
import { logger } from '../../lib/logger.js';
import { type AuditActor, writeAudit } from '../audit/audit.service.js';
import { liveHub } from '../analytics/live.js';
import { notifyAlert } from '../notify/notifier.js';
import { rank, type Rule } from './rules.js';

const SAMPLE_LIMIT = 50;

export interface AlertInput {
  appId: string;
  rule: Rule;
  groupKey: string;
  severity: Rule['severity'];
  title: string;
  reason: string;
  eventId: string | null;
  count: number;
  simulated: boolean;
}

export interface RaisedAlert {
  id: string;
  created: boolean;
  escalated: boolean;
  suppressed: boolean;
  severity: string;
}

export async function raiseAlert(a: AlertInput): Promise<RaisedAlert> {
  const out = await withTransaction(async (tx) => {
    const quiet = await tx.query(
      `select id from public.security_alerts
        where app_id = $1 and rule_key = $2 and group_key = $3 and status = 'false_positive'
          and resolved_at > now() - make_interval(secs => $4) limit 1`,
      [a.appId, a.rule.key, a.groupKey, a.rule.cooldownSeconds],
    );
    const before = (
      await tx.query<{ id: string; severity: string }>(
        `select id, severity from public.security_alerts
          where app_id = $1 and rule_key = $2 and group_key = $3 and status in ('open', 'acknowledged') for update`,
        [a.appId, a.rule.key, a.groupKey],
      )
    ).rows[0];
    if (!before && quiet.rowCount) return { id: quiet.rows[0].id as string, created: false, escalated: false, suppressed: true, severity: a.severity };

    const { rows } = await tx.query<{ id: string; severity: string }>(
      `insert into public.security_alerts as al
         (app_id, rule_id, rule_key, group_key, severity, classification, title, detection_reason, occurrences, simulated)
       values ($1, $2, $3, $4, $5, $6, $7, $8, greatest($9, 1), $10)
       on conflict (app_id, rule_key, group_key) where status in ('open', 'acknowledged')
       do update set occurrences = al.occurrences + 1,
                     last_seen_at = now(),
                     severity = case when public.severity_rank(excluded.severity) > public.severity_rank(al.severity) then excluded.severity else al.severity end,
                     detection_reason = excluded.detection_reason,
                     simulated = al.simulated and excluded.simulated
       returning id, severity`,
      [a.appId, a.rule.id, a.rule.key, a.groupKey, a.severity, a.rule.classification, a.title.slice(0, 200), a.reason.slice(0, 1000), a.count, a.simulated],
    );
    const row = rows[0]!;
    if (a.eventId) {
      await tx.query(
        `insert into public.alert_events (alert_id, event_id)
         select $1, $2 where (select count(*) from public.alert_events where alert_id = $1) < $3
         on conflict do nothing`,
        [row.id, a.eventId, SAMPLE_LIMIT],
      );
    }
    return { id: row.id, created: !before, escalated: !!before && rank(row.severity) > rank(before.severity), suppressed: false, severity: row.severity };
  });

  if (out.created || out.escalated) {
    liveHub.alert({ id: out.id, severity: out.severity, title: a.title, created: out.created, simulated: a.simulated });
    void notifyAlert(out.id).catch((err) => logger.error({ err, alert: out.id }, 'alert notification failed'));
  } else if (!out.suppressed) {
    liveHub.notify();
  }
  return out;
}

// ─────────────────────────── dashboard ───────────────────────────
const ALERT_COLUMNS = `a.id, a.rule_key, a.group_key, a.severity, a.classification, a.title, a.detection_reason, a.status, a.occurrences,
  a.first_seen_at, a.last_seen_at, a.last_notified_at, a.incident_id, a.resolved_at, a.simulated, r.name as rule_name,
  i.reference as incident_reference, ad.email as resolved_by_email`;
const ALERT_FROM = `public.security_alerts a
  left join public.detection_rules r on r.id = a.rule_id
  left join public.security_incidents i on i.id = a.incident_id
  left join public.administrator_accounts ad on ad.id = a.resolved_by`;

const iso = (d: Date | null) => (d ? new Date(d).toISOString() : null);
export function toAlert(r: any) {
  return {
    id: r.id,
    rule: { key: r.rule_key, name: r.rule_name },
    groupKey: r.group_key,
    severity: r.severity,
    classification: r.classification,
    title: r.title,
    detectionReason: r.detection_reason,
    status: r.status,
    occurrences: r.occurrences,
    firstSeenAt: iso(r.first_seen_at),
    lastSeenAt: iso(r.last_seen_at),
    lastNotifiedAt: iso(r.last_notified_at),
    incident: r.incident_id ? { id: r.incident_id, reference: r.incident_reference } : null,
    resolvedAt: iso(r.resolved_at),
    resolvedBy: r.resolved_by_email ?? null,
    simulated: r.simulated,
  };
}

export async function listAlerts(appId: string, q: { status?: string[]; severity?: string[]; page: number; pageSize: number }) {
  const params: unknown[] = [appId];
  const where = ['a.app_id = $1'];
  if (q.status?.length) {
    params.push(q.status);
    where.push(`a.status = any($${params.length}::text[])`);
  }
  if (q.severity?.length) {
    params.push(q.severity);
    where.push(`a.severity = any($${params.length}::text[])`);
  }
  const filter = `where ${where.join(' and ')}`;
  const total = (await pool.query<{ n: number }>(`select count(*)::int as n from public.security_alerts a ${filter}`, params)).rows[0]!.n;
  params.push(q.pageSize, (q.page - 1) * q.pageSize);
  const limit = `$${params.length - 1}`;
  const offset = `$${params.length}`;
  const { rows } = await pool.query(
    `select ${ALERT_COLUMNS} from ${ALERT_FROM} ${filter}
      order by (a.status in ('open', 'acknowledged')) desc, public.severity_rank(a.severity) desc, a.last_seen_at desc
      limit ${limit} offset ${offset}`,
    params,
  );
  return { data: rows.map(toAlert), meta: { page: q.page, pageSize: q.pageSize, total, totalPages: Math.max(1, Math.ceil(total / q.pageSize)) } };
}

export async function getAlert(appId: string, id: string) {
  const { rows } = await pool.query(`select ${ALERT_COLUMNS} from ${ALERT_FROM} where a.app_id = $1 and a.id = $2`, [appId, id]);
  if (!rows[0]) throw appError('NOT_FOUND', 'Alert not found.');
  const events = await pool.query(
    `select e.id, e.occurred_at, e.category, e.severity, host(e.source_ip) as source_ip, e.user_ref, e.method, e.route, e.status_code, e.description, e.simulated
       from public.alert_events ae join public.security_events e on e.id = ae.event_id
      where ae.alert_id = $1 order by e.occurred_at desc limit 50`,
    [id],
  );
  return {
    ...toAlert(rows[0]),
    sampleEvents: events.rows.map((e) => ({
      id: e.id,
      occurredAt: iso(e.occurred_at),
      category: e.category,
      severity: e.severity,
      sourceIp: e.source_ip,
      userRef: e.user_ref,
      method: e.method,
      route: e.route,
      statusCode: e.status_code,
      description: e.description,
      simulated: e.simulated,
    })),
  };
}

/** Triage: acknowledged (being looked at), resolved, false_positive, or back to open. */
export async function setAlertStatus(appId: string, id: string, status: 'open' | 'acknowledged' | 'resolved' | 'false_positive', actor: AuditActor, note?: string) {
  return withTransaction(async (tx) => {
    const cur = (await tx.query('select status from public.security_alerts where app_id = $1 and id = $2 for update', [appId, id])).rows[0];
    if (!cur) throw appError('NOT_FOUND', 'Alert not found.');
    const closing = status === 'resolved' || status === 'false_positive';
    if (!closing) {
      // Reopening must not collide with a newer open alert for the same rule and group.
      const clash = await tx.query(
        `select 1 from public.security_alerts o join public.security_alerts a on a.id = $1
          where o.app_id = a.app_id and o.rule_key = a.rule_key and o.group_key = a.group_key and o.id <> a.id and o.status in ('open', 'acknowledged')`,
        [id],
      );
      if (clash.rowCount) throw appError('CONFLICT', 'A newer alert for the same activity is already open.');
    }
    await tx.query(
      `update public.security_alerts
          set status = $3, resolved_at = case when $4::boolean then coalesce(resolved_at, now()) else null end,
              resolved_by = case when $4::boolean then $5::uuid else null end
        where app_id = $1 and id = $2`,
      [appId, id, status, closing, actor.adminId],
    );
    await writeAudit(tx, actor, { action: 'alert.status_changed', targetType: 'alert', targetId: id, details: { from: cur.status, to: status, ...(note ? { note } : {}) } });
    liveHub.notify();
  });
}
