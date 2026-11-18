// Incidents: a person's case file, grouping alerts with notes, an owner and a classification. Classifications go
// from "suspicious" up to "unauthorized access verified" and "compromise confirmed"; the last two are only ever set
// by an owner (the engine never claims a compromise). Notes are append-only.
import { pool, withTransaction } from '../../db/pool.js';
import { appError } from '../../errors/app-error.js';
import { type AuditActor, writeAudit } from '../audit/audit.service.js';
import { liveHub } from '../analytics/live.js';

export const INCIDENT_STATUSES = ['new', 'investigating', 'resolved', 'false_positive'] as const;
export const CLASSIFICATIONS = ['suspicious', 'policy_violation', 'unauthorized_access_verified', 'compromise_confirmed'] as const;
export const OWNER_ONLY_CLASSIFICATIONS = new Set(['unauthorized_access_verified', 'compromise_confirmed']);

const iso = (d: Date | null) => (d ? new Date(d).toISOString() : null);
function toIncident(r: any) {
  return {
    id: r.id,
    reference: r.reference,
    title: r.title,
    summary: r.summary,
    status: r.status,
    severity: r.severity,
    classification: r.classification,
    owner: r.owner_id ? { id: r.owner_id, email: r.owner_email, displayName: r.owner_name } : null,
    createdBy: r.created_by_email ?? 'detection engine',
    openedAt: iso(r.opened_at),
    updatedAt: iso(r.updated_at),
    resolvedAt: iso(r.resolved_at),
    alertCount: r.alert_count ?? 0,
  };
}

const INCIDENT_SELECT = `
  select i.*, o.email as owner_email, o.display_name as owner_name, c.email as created_by_email,
         (select count(*)::int from public.security_alerts a where a.incident_id = i.id) as alert_count
    from public.security_incidents i
    left join public.administrator_accounts o on o.id = i.owner_id
    left join public.administrator_accounts c on c.id = i.created_by`;

async function linkAlerts(tx: any, appId: string, incidentId: string, alertIds: string[]) {
  if (!alertIds.length) return 0;
  const res = await tx.query(
    'update public.security_alerts set incident_id = $3 where app_id = $1 and id = any($2::uuid[]) and (incident_id is null or incident_id = $3)',
    [appId, alertIds, incidentId],
  );
  if ((res.rowCount ?? 0) !== new Set(alertIds).size) throw appError('CONFLICT', 'Some alerts were not found or already belong to another incident.');
  return res.rowCount ?? 0;
}

export async function createIncident(
  appId: string,
  body: { title: string; summary?: string; severity: string; classification: string; alertIds: string[] },
  actor: AuditActor,
  actorRole: string,
) {
  if (OWNER_ONLY_CLASSIFICATIONS.has(body.classification) && actorRole !== 'owner') throw appError('FORBIDDEN', 'Only an owner can record verified access or a compromise.');
  const id = await withTransaction(async (tx) => {
    const { rows } = await tx.query(
      `insert into public.security_incidents (app_id, title, summary, severity, classification, owner_id, created_by)
       values ($1, $2, $3, $4, $5, $6, $6) returning id, reference`,
      [appId, body.title, body.summary ?? null, body.severity, body.classification, actor.adminId],
    );
    await linkAlerts(tx, appId, rows[0].id, body.alertIds);
    await writeAudit(tx, actor, {
      action: 'incident.created',
      targetType: 'incident',
      targetId: rows[0].id,
      details: { reference: rows[0].reference, classification: body.classification, alerts: body.alertIds.length },
    });
    return rows[0].id as string;
  });
  liveHub.notify();
  return getIncident(appId, id);
}

export async function listIncidents(appId: string, q: { status?: string[]; page: number; pageSize: number }) {
  const params: unknown[] = [appId];
  let filter = 'where i.app_id = $1';
  if (q.status?.length) {
    params.push(q.status);
    filter += ` and i.status = any($${params.length}::text[])`;
  }
  const total = (await pool.query<{ n: number }>(`select count(*)::int as n from public.security_incidents i ${filter}`, params)).rows[0]!.n;
  params.push(q.pageSize, (q.page - 1) * q.pageSize);
  const limit = `$${params.length - 1}`;
  const offset = `$${params.length}`;
  const { rows } = await pool.query(
    `${INCIDENT_SELECT} ${filter}
      order by (i.status in ('new', 'investigating')) desc, public.severity_rank(i.severity) desc, i.opened_at desc limit ${limit} offset ${offset}`,
    params,
  );
  return { data: rows.map(toIncident), meta: { page: q.page, pageSize: q.pageSize, total, totalPages: Math.max(1, Math.ceil(total / q.pageSize)) } };
}

export async function getIncident(appId: string, id: string) {
  const { rows } = await pool.query(`${INCIDENT_SELECT} where i.app_id = $1 and i.id = $2`, [appId, id]);
  if (!rows[0]) throw appError('NOT_FOUND', 'Incident not found.');
  const [alerts, notes] = await Promise.all([
    pool.query(
      `select id, rule_key, title, severity, status, occurrences, first_seen_at, last_seen_at, simulated
         from public.security_alerts where incident_id = $1 order by first_seen_at`,
      [id],
    ),
    pool.query(
      `select n.id, n.body, n.created_at, a.email, a.display_name from public.incident_notes n
         join public.administrator_accounts a on a.id = n.author_id where n.incident_id = $1 order by n.created_at, n.id`,
      [id],
    ),
  ]);
  return {
    ...toIncident(rows[0]),
    alerts: alerts.rows.map((a) => ({
      id: a.id,
      ruleKey: a.rule_key,
      title: a.title,
      severity: a.severity,
      status: a.status,
      occurrences: a.occurrences,
      firstSeenAt: iso(a.first_seen_at),
      lastSeenAt: iso(a.last_seen_at),
      simulated: a.simulated,
    })),
    notes: notes.rows.map((n) => ({ id: n.id, body: n.body, createdAt: iso(n.created_at), author: { email: n.email, displayName: n.display_name } })),
  };
}

export async function updateIncident(
  appId: string,
  id: string,
  patch: { title?: string; summary?: string | null; status?: string; severity?: string; classification?: string; ownerId?: string | null; addAlertIds?: string[] },
  actor: AuditActor,
  actorRole: string,
) {
  if (patch.classification && OWNER_ONLY_CLASSIFICATIONS.has(patch.classification) && actorRole !== 'owner') {
    throw appError('FORBIDDEN', 'Only an owner can record verified access or a compromise.');
  }
  await withTransaction(async (tx) => {
    const cur = (await tx.query('select * from public.security_incidents where app_id = $1 and id = $2 for update', [appId, id])).rows[0];
    if (!cur) throw appError('NOT_FOUND', 'Incident not found.');
    if (patch.ownerId) {
      const o = await tx.query('select 1 from public.administrator_accounts where id = $1 and is_active', [patch.ownerId]);
      if (!o.rowCount) throw appError('VALIDATION_ERROR', 'Choose an active developer.', { fieldErrors: { ownerId: ['Not an active developer'] } });
    }
    const next = {
      title: patch.title ?? cur.title,
      summary: patch.summary !== undefined ? patch.summary : cur.summary,
      status: patch.status ?? cur.status,
      severity: patch.severity ?? cur.severity,
      classification: patch.classification ?? cur.classification,
      owner_id: patch.ownerId !== undefined ? patch.ownerId : cur.owner_id,
    };
    const closed = next.status === 'resolved' || next.status === 'false_positive';
    await tx.query(
      `update public.security_incidents
          set title = $3, summary = $4, status = $5, severity = $6, classification = $7, owner_id = $8,
              resolved_at = case when $9::boolean then coalesce(resolved_at, now()) else null end
        where app_id = $1 and id = $2`,
      [appId, id, next.title, next.summary, next.status, next.severity, next.classification, next.owner_id, closed],
    );
    if (patch.addAlertIds?.length) await linkAlerts(tx, appId, id, patch.addAlertIds);
    const changed = Object.fromEntries(Object.entries(next).filter(([k, v]) => cur[k] !== v).map(([k, v]) => [k, { from: cur[k], to: v }]));
    await writeAudit(tx, actor, {
      action: 'incident.updated',
      targetType: 'incident',
      targetId: id,
      details: { reference: cur.reference, changed, ...(patch.addAlertIds?.length ? { addedAlerts: patch.addAlertIds.length } : {}) },
    });
  });
  liveHub.notify();
  return getIncident(appId, id);
}

export async function addNote(appId: string, id: string, body: string, actor: AuditActor) {
  await withTransaction(async (tx) => {
    const cur = (await tx.query('select reference from public.security_incidents where app_id = $1 and id = $2', [appId, id])).rows[0];
    if (!cur) throw appError('NOT_FOUND', 'Incident not found.');
    const { rows } = await tx.query('insert into public.incident_notes (incident_id, author_id, body) values ($1, $2, $3) returning id', [id, actor.adminId, body]);
    await writeAudit(tx, actor, { action: 'incident.note_added', targetType: 'incident', targetId: id, details: { reference: cur.reference, noteId: rows[0].id } });
  });
  return getIncident(appId, id);
}
