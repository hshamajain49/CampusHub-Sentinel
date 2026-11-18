// Dashboard audit log: every sign-in (success or failure), sign-in step, sign-out and change made through Sentinel.
// The table is append-only (database/migrations/…_least_privilege.sql); this module only inserts and reads.
import type { Request } from 'express';
import type { DbClient } from '../../db/pool.js';
import { pool } from '../../db/pool.js';

export interface AuditActor {
  adminId: string | null;
  adminEmail: string | null;
  ip: string | null;
  userAgent: string | null;
}

export interface AuditEntry {
  action: string; // "<area>.<what>", e.g. auth.login, admin.created
  outcome?: 'success' | 'failure';
  targetType?: string;
  targetId?: string;
  details?: Record<string, unknown>;
}

export function clientIp(req: Request): string | null {
  const ip = (req.ip ?? '').replace(/^::ffff:/, '');
  return /^[0-9a-fA-F.:]+$/.test(ip) && ip.length <= 45 ? ip : null;
}

export function actorOf(req: Request): AuditActor {
  return {
    adminId: req.admin?.id ?? null,
    adminEmail: req.admin?.email ?? null,
    ip: clientIp(req),
    userAgent: req.get('user-agent')?.slice(0, 300) ?? null,
  };
}

export async function writeAudit(db: DbClient, actor: AuditActor, e: AuditEntry): Promise<void> {
  await db.query(
    `insert into public.audit_logs (admin_id, admin_email, action, outcome, target_type, target_id, ip, user_agent, details)
     values ($1, $2, $3, $4, $5, $6, $7::inet, $8, $9)`,
    [
      actor.adminId,
      actor.adminEmail,
      e.action,
      e.outcome ?? 'success',
      e.targetType ?? null,
      e.targetId ?? null,
      actor.ip,
      actor.userAgent,
      JSON.stringify(e.details ?? {}),
    ],
  );
}

export interface AuditQuery {
  page: number;
  pageSize: number;
  action?: string;
  outcome?: 'success' | 'failure';
  adminId?: string;
  from?: string;
  to?: string;
}

export async function listAudit(q: AuditQuery) {
  const params: unknown[] = [];
  const where: string[] = [];
  const add = (sql: string, v: unknown) => {
    params.push(v);
    where.push(sql.replace('$?', `$${params.length}`));
  };
  if (q.action) add('action = $?', q.action);
  if (q.outcome) add('outcome = $?', q.outcome);
  if (q.adminId) add('admin_id = $?', q.adminId);
  if (q.from) add('occurred_at >= $?::timestamptz', q.from);
  if (q.to) add('occurred_at < $?::timestamptz', q.to);
  const filter = where.length ? `where ${where.join(' and ')}` : '';
  const total = (await pool.query<{ n: number }>(`select count(*)::int as n from public.audit_logs ${filter}`, params)).rows[0]!.n;
  params.push(q.pageSize, (q.page - 1) * q.pageSize);
  const limit = `$${params.length - 1}`;
  const offset = `$${params.length}`;
  const { rows } = await pool.query(
    `select id, occurred_at, admin_id, admin_email, action, outcome, target_type, target_id, host(ip) as ip, user_agent, details
       from public.audit_logs ${filter} order by occurred_at desc, id desc limit ${limit} offset ${offset}`,
    params,
  );
  return {
    data: rows.map((r) => ({
      id: r.id,
      occurredAt: new Date(r.occurred_at).toISOString(),
      admin: r.admin_id ? { id: r.admin_id, email: r.admin_email } : r.admin_email ? { id: null, email: r.admin_email } : null,
      action: r.action,
      outcome: r.outcome,
      target: r.target_type ? { type: r.target_type, id: r.target_id } : null,
      ip: r.ip,
      userAgent: r.user_agent,
      details: r.details,
    })),
    meta: { page: q.page, pageSize: q.pageSize, total, totalPages: Math.max(1, Math.ceil(total / q.pageSize)) },
  };
}
