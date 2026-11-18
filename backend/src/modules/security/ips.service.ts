// Suspicious IPs, temporary blocks and the never-block allowlist.
//
// Risk score: each event from an IP adds a weight by severity (low 1, medium 3, high 8, critical 20; info nothing),
// an alert about it adds 10, and the score halves every day without activity. It ranks addresses; it is not proof.
// Blocks are temporary (15 minutes to 7 days), never cover an allowlisted address, and are never broader than an
// IPv4 /16 or IPv6 /48 (a typo can't block a whole provider). CampusHub pulls the active list and enforces it, and
// keeps working on its last copy if Sentinel is unreachable.
import { pool, withTransaction, type DbClient } from '../../db/pool.js';
import { appError } from '../../errors/app-error.js';
import { logger } from '../../lib/logger.js';
import { type AuditActor, writeAudit } from '../audit/audit.service.js';
import type { Rule } from './rules.js';

const WEIGHT: Record<string, number> = { info: 0, low: 1, medium: 3, high: 8, critical: 20 };
const ALERT_WEIGHT = 10;
const DECAYED = 'risk_score * power(0.5, extract(epoch from now() - last_detected_at) / 86400)';
const ENGINE: AuditActor = { adminId: null, adminEmail: 'detection-engine', ip: null, userAgent: null };

export async function recordSuspicious(db: DbClient, appId: string, ip: string, severity: string, reason: string): Promise<void> {
  const weight = WEIGHT[severity] ?? 0;
  if (!weight) return;
  await db.query(
    `insert into public.suspicious_ips as s (app_id, ip, event_count, risk_score, reasons) values ($1, $2::inet, 1, $3, array[$4])
     on conflict (app_id, ip) do update set
       event_count = s.event_count + 1,
       last_detected_at = now(),
       risk_score = least(1000, s.risk_score * power(0.5, extract(epoch from now() - s.last_detected_at) / 86400) + $3),
       reasons = case when $4 = any(s.reasons) or cardinality(s.reasons) >= 12 then s.reasons else s.reasons || $4 end`,
    [appId, ip, weight, reason],
  );
}

export async function boostForAlert(appId: string, ip: string, ruleKey: string): Promise<void> {
  await pool.query(
    `insert into public.suspicious_ips as s (app_id, ip, risk_score, reasons) values ($1, $2::inet, $3, array[$4])
     on conflict (app_id, ip) do update set
       last_detected_at = now(),
       risk_score = least(1000, s.risk_score * power(0.5, extract(epoch from now() - s.last_detected_at) / 86400) + $3),
       reasons = case when $4 = any(s.reasons) or cardinality(s.reasons) >= 12 then s.reasons else s.reasons || $4 end`,
    [appId, ip, ALERT_WEIGHT, `alert:${ruleKey}`],
  );
}

export const riskLevel = (score: number) => (score >= 60 ? 'critical' : score >= 30 ? 'high' : score >= 10 ? 'medium' : 'low');

export async function listSuspicious(appId: string, q: { minScore: number; page: number; pageSize: number }) {
  const total = (
    await pool.query<{ n: number }>(`select count(*)::int as n from public.suspicious_ips where app_id = $1 and ${DECAYED} >= $2`, [appId, q.minScore])
  ).rows[0]!.n;
  const { rows } = await pool.query(
    `select host(s.ip) as ip, s.event_count, round((${DECAYED})::numeric, 1)::float8 as risk, s.first_detected_at, s.last_detected_at, s.reasons,
            exists (select 1 from public.ip_blocks b where b.app_id = s.app_id and b.cidr >>= s.ip and b.lifted_at is null and b.expires_at > now()) as blocked,
            exists (select 1 from public.ip_allowlist w where w.app_id = s.app_id and w.cidr >>= s.ip) as allowlisted,
            (select count(*)::int from public.security_alerts a where a.app_id = s.app_id and a.status in ('open', 'acknowledged')
               and (a.group_key = host(s.ip) or a.group_key like host(s.ip) || ' %')) as open_alerts
       from public.suspicious_ips s where s.app_id = $1 and ${DECAYED} >= $2
      order by ${DECAYED} desc limit $3 offset $4`,
    [appId, q.minScore, q.pageSize, (q.page - 1) * q.pageSize],
  );
  return {
    data: rows.map((r) => ({
      ip: r.ip,
      eventCount: r.event_count,
      riskScore: r.risk,
      riskLevel: riskLevel(r.risk),
      firstDetectedAt: new Date(r.first_detected_at).toISOString(),
      lastDetectedAt: new Date(r.last_detected_at).toISOString(),
      reasons: r.reasons,
      blocked: r.blocked,
      allowlisted: r.allowlisted,
      openAlerts: r.open_alerts,
    })),
    meta: { page: q.page, pageSize: q.pageSize, total, totalPages: Math.max(1, Math.ceil(total / q.pageSize)) },
  };
}

export async function ipDetail(appId: string, ip: string) {
  const [summary, events, alerts, blocks] = await Promise.all([
    pool.query(
      `select host(ip) as ip, event_count, round((${DECAYED})::numeric, 1)::float8 as risk, first_detected_at, last_detected_at, reasons
         from public.suspicious_ips where app_id = $1 and ip = $2::inet`,
      [appId, ip],
    ),
    pool.query(
      `select id, occurred_at, category, severity, user_ref, method, route, status_code, description, simulated
         from public.security_events where app_id = $1 and source_ip = $2::inet order by occurred_at desc limit 100`,
      [appId, ip],
    ),
    pool.query(
      `select id, rule_key, severity, title, status, occurrences, first_seen_at, last_seen_at from public.security_alerts
        where app_id = $1 and (group_key = $2 or group_key like $2 || ' %') order by last_seen_at desc limit 50`,
      [appId, ip],
    ),
    pool.query(
      `select id, host(cidr) as host, masklen(cidr) as bits, reason, source, created_at, expires_at, lifted_at,
              (lifted_at is null and expires_at > now()) as active
         from public.ip_blocks where app_id = $1 and cidr >>= $2::inet order by created_at desc limit 20`,
      [appId, ip],
    ),
  ]);
  const s = summary.rows[0];
  return {
    ip,
    riskScore: s?.risk ?? 0,
    riskLevel: riskLevel(s?.risk ?? 0),
    eventCount: s?.event_count ?? 0,
    firstDetectedAt: s ? new Date(s.first_detected_at).toISOString() : null,
    lastDetectedAt: s ? new Date(s.last_detected_at).toISOString() : null,
    reasons: s?.reasons ?? [],
    events: events.rows.map((e) => ({
      id: e.id,
      occurredAt: new Date(e.occurred_at).toISOString(),
      category: e.category,
      severity: e.severity,
      userRef: e.user_ref,
      method: e.method,
      route: e.route,
      statusCode: e.status_code,
      description: e.description,
      simulated: e.simulated,
    })),
    alerts: alerts.rows.map((a) => ({ id: a.id, ruleKey: a.rule_key, severity: a.severity, title: a.title, status: a.status, occurrences: a.occurrences, lastSeenAt: new Date(a.last_seen_at).toISOString() })),
    blocks: blocks.rows.map(toBlockRow),
  };
}

// ─────────────────────────── blocks ───────────────────────────
function toBlockRow(r: any) {
  return {
    id: r.id,
    cidr: `${r.host}/${r.bits}`,
    reason: r.reason,
    source: r.source,
    ruleKey: r.rule_key ?? null,
    createdBy: r.created_by_email ?? null,
    createdAt: new Date(r.created_at).toISOString(),
    expiresAt: new Date(r.expires_at).toISOString(),
    liftedAt: r.lifted_at ? new Date(r.lifted_at).toISOString() : null,
    active: r.active,
  };
}

/** Normalises "203.0.113.9" or "203.0.113.0/24" and checks it's not too broad. */
async function normaliseCidr(db: DbClient, input: string): Promise<string> {
  try {
    const { rows } = await db.query<{ cidr: string; family: number; bits: number }>(
      'select network($1::inet)::text as cidr, family($1::inet) as family, masklen($1::inet) as bits',
      [input.trim()],
    );
    const r = rows[0]!;
    if ((r.family === 4 && r.bits < 16) || (r.family === 6 && r.bits < 48)) {
      throw appError('VALIDATION_ERROR', 'That range is too broad (at most an IPv4 /16 or an IPv6 /48).', { fieldErrors: { cidr: ['Too broad'] } });
    }
    return r.cidr;
  } catch (err: any) {
    if (err?.code === '22P02') throw appError('VALIDATION_ERROR', 'Enter an IP address or a CIDR range.', { fieldErrors: { cidr: ['Not an IP address or range'] } });
    throw err;
  }
}

async function createBlock(
  db: DbClient,
  input: { appId: string; cidr: string; seconds: number; reason: string; source: 'manual' | 'rule'; ruleKey?: string; createdBy: string | null },
) {
  const cidr = await normaliseCidr(db, input.cidr);
  await db.query('select pg_advisory_xact_lock(hashtext($1 || $2))', [input.appId, cidr]);
  const allow = await db.query('select host(cidr) || \'/\' || masklen(cidr) as c from public.ip_allowlist where app_id = $1 and cidr && $2::cidr limit 1', [
    input.appId,
    cidr,
  ]);
  if (allow.rowCount) {
    throw appError('CONFLICT', `This range overlaps the allowlist (${allow.rows[0].c}); allowlisted addresses are never blocked.`, {
      fieldErrors: { cidr: ['Overlaps the allowlist'] },
    });
  }
  const active = await db.query('select id from public.ip_blocks where app_id = $1 and cidr = $2::cidr and lifted_at is null and expires_at > now()', [
    input.appId,
    cidr,
  ]);
  if (active.rowCount) throw appError('CONFLICT', 'This range is already blocked.');
  const { rows } = await db.query(
    `insert into public.ip_blocks (app_id, cidr, reason, source, rule_key, created_by, expires_at)
     values ($1, $2::cidr, $3, $4, $5, $6, now() + make_interval(secs => $7))
     returning id, host(cidr) as host, masklen(cidr) as bits, reason, source, rule_key, created_at, expires_at, lifted_at, true as active`,
    [input.appId, cidr, input.reason, input.source, input.ruleKey ?? null, input.createdBy, input.seconds],
  );
  return toBlockRow(rows[0]);
}

export async function manualBlock(appId: string, body: { cidr: string; minutes: number; reason: string }, actor: AuditActor) {
  return withTransaction(async (tx) => {
    const block = await createBlock(tx, { appId, cidr: body.cidr, seconds: body.minutes * 60, reason: body.reason, source: 'manual', createdBy: actor.adminId });
    await writeAudit(tx, actor, { action: 'block.created', targetType: 'ip_block', targetId: block.id, details: { cidr: block.cidr, minutes: body.minutes } });
    return block;
  });
}

/** A rule with auto-block on: blocks the single address for the rule's block time (never an allowlisted one). */
export async function autoBlock(appId: string, ip: string, rule: Rule, alertId: string): Promise<void> {
  try {
    await withTransaction(async (tx) => {
      const covered = await tx.query(
        `select 1 from public.ip_allowlist where app_id = $1 and cidr >>= $2::inet
         union all select 1 from public.ip_blocks where app_id = $1 and cidr >>= $2::inet and lifted_at is null and expires_at > now()
         limit 1`,
        [appId, ip],
      );
      if (covered.rowCount) return;
      const block = await createBlock(tx, {
        appId,
        cidr: ip,
        seconds: rule.blockSeconds,
        reason: `Automatic: ${rule.name} (alert ${alertId.slice(0, 8)})`,
        source: 'rule',
        ruleKey: rule.key,
        createdBy: null,
      });
      await writeAudit(tx, ENGINE, { action: 'block.created', targetType: 'ip_block', targetId: block.id, details: { cidr: block.cidr, rule: rule.key, automatic: true } });
    });
  } catch (err) {
    logger.warn({ err, ip, rule: rule.key }, 'automatic block not created');
  }
}

export async function liftBlock(appId: string, id: string, actor: AuditActor) {
  return withTransaction(async (tx) => {
    const { rows } = await tx.query(
      `update public.ip_blocks set lifted_at = now(), lifted_by = $3 where app_id = $1 and id = $2 and lifted_at is null
       returning id, host(cidr) as host, masklen(cidr) as bits, reason, source, rule_key, created_at, expires_at, lifted_at, false as active`,
      [appId, id, actor.adminId],
    );
    if (!rows[0]) throw appError('NOT_FOUND', 'No active block with that id.');
    await writeAudit(tx, actor, { action: 'block.lifted', targetType: 'ip_block', targetId: id, details: { cidr: `${rows[0].host}/${rows[0].bits}` } });
    return toBlockRow(rows[0]);
  });
}

export async function listBlocks(appId: string, activeOnly: boolean) {
  const { rows } = await pool.query(
    `select b.id, host(b.cidr) as host, masklen(b.cidr) as bits, b.reason, b.source, b.rule_key, b.created_at, b.expires_at, b.lifted_at,
            (b.lifted_at is null and b.expires_at > now()) as active, a.email as created_by_email
       from public.ip_blocks b left join public.administrator_accounts a on a.id = b.created_by
      where b.app_id = $1 and (not $2::boolean or (b.lifted_at is null and b.expires_at > now()))
      order by b.created_at desc limit 200`,
    [appId, activeOnly],
  );
  return rows.map(toBlockRow);
}

/** What CampusHub enforces: active blocks only. */
export async function activeBlocklist(appId: string) {
  const { rows } = await pool.query(
    `select host(cidr) || '/' || masklen(cidr) as cidr, expires_at from public.ip_blocks
      where app_id = $1 and lifted_at is null and expires_at > now() order by expires_at`,
    [appId],
  );
  return rows.map((r) => ({ cidr: r.cidr as string, expiresAt: new Date(r.expires_at).toISOString() }));
}

// ─────────────────────────── allowlist ───────────────────────────
export async function listAllowlist(appId: string) {
  const { rows } = await pool.query(
    `select w.id, host(w.cidr) || '/' || masklen(w.cidr) as cidr, w.note, w.created_at, a.email as created_by
       from public.ip_allowlist w join public.administrator_accounts a on a.id = w.created_by where w.app_id = $1 order by w.created_at`,
    [appId],
  );
  return rows.map((r) => ({ id: r.id, cidr: r.cidr, note: r.note, createdAt: new Date(r.created_at).toISOString(), createdBy: r.created_by }));
}

/** Adding to the allowlist also lifts any active block it covers (that's usually why someone adds it). */
export async function addAllowlist(appId: string, body: { cidr: string; note: string }, actor: AuditActor) {
  return withTransaction(async (tx) => {
    const { rows } = await tx.query<{ cidr: string }>('select network($1::inet)::text as cidr', [body.cidr.trim()]).catch((err) => {
      if (err?.code === '22P02') throw appError('VALIDATION_ERROR', 'Enter an IP address or a CIDR range.', { fieldErrors: { cidr: ['Not an IP address or range'] } });
      throw err;
    });
    const cidr = rows[0]!.cidr;
    const ins = await tx.query(
      'insert into public.ip_allowlist (app_id, cidr, note, created_by) values ($1, $2::cidr, $3, $4) on conflict (app_id, cidr) do nothing returning id',
      [appId, cidr, body.note, actor.adminId],
    );
    if (!ins.rowCount) throw appError('CONFLICT', 'Already on the allowlist.');
    const lifted = await tx.query(
      'update public.ip_blocks set lifted_at = now(), lifted_by = $3 where app_id = $1 and cidr && $2::cidr and lifted_at is null and expires_at > now()',
      [appId, cidr, actor.adminId],
    );
    await writeAudit(tx, actor, { action: 'allowlist.added', targetType: 'ip_allowlist', targetId: ins.rows[0].id, details: { cidr, liftedBlocks: lifted.rowCount } });
    return { id: ins.rows[0].id as string, cidr, liftedBlocks: lifted.rowCount ?? 0 };
  });
}

export async function removeAllowlist(appId: string, id: string, actor: AuditActor) {
  await withTransaction(async (tx) => {
    const { rows } = await tx.query("delete from public.ip_allowlist where app_id = $1 and id = $2 returning host(cidr) || '/' || masklen(cidr) as cidr", [appId, id]);
    if (!rows[0]) throw appError('NOT_FOUND');
    await writeAudit(tx, actor, { action: 'allowlist.removed', targetType: 'ip_allowlist', targetId: id, details: { cidr: rows[0].cidr } });
  });
}
