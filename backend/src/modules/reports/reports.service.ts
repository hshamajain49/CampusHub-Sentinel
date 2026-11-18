// Security scan reports uploaded by a monitored app's tooling (POST /ingest/v1/reports, signed). Stored as sent,
// append-only, and shown on the dashboard's "Security Audit Reports" page.
import { z } from 'zod';
import { pool } from '../../db/pool.js';

const STATUSES = ['pass', 'fail', 'warn', 'info', 'skip'] as const;
const count = z.number().int().min(0).max(100_000);
const summary = z.strictObject({ pass: count, fail: count, warn: count, info: count, skip: count });
const text = (max: number) => z.string().max(max * 4).transform((s) => s.slice(0, max));

const check = z.object({
  id: text(80),
  title: text(300),
  status: z.enum(STATUSES),
  severity: text(20).optional(),
  location: text(300).optional(),
  detail: text(500).optional(),
});
const section = z.object({
  name: text(80),
  kind: text(40),
  startedAt: z.iso.datetime({ offset: true }).optional(),
  finishedAt: z.iso.datetime({ offset: true }).optional(),
  summary,
  checks: z.array(check).max(1000),
});
export const reportSchema = z.object({
  source: text(80).default('security:audit'),
  environment: z.enum(['local', 'staging', 'production', 'ci']),
  gitCommit: z
    .string()
    .regex(/^[0-9a-f]{4,40}$/)
    .nullable()
    .optional(),
  startedAt: z.iso.datetime({ offset: true }),
  finishedAt: z.iso.datetime({ offset: true }),
  summary,
  sections: z.array(section).min(1).max(20),
});
export type ScanReportInput = z.infer<typeof reportSchema>;

export async function storeReport(appId: string, r: ScanReportInput): Promise<{ id: string }> {
  const started = new Date(r.startedAt);
  const finished = new Date(Math.max(Date.parse(r.finishedAt), started.getTime()));
  const { rows } = await pool.query<{ id: string }>(
    `insert into public.scan_reports (app_id, started_at, finished_at, source, environment, git_commit, summary, sections)
     values ($1, $2, $3, $4, $5, $6, $7, $8) returning id`,
    [appId, started, finished, r.source, r.environment, r.gitCommit ?? null, JSON.stringify(r.summary), JSON.stringify(r.sections)],
  );
  return { id: rows[0]!.id };
}

export interface ScanReportRow {
  id: string;
  receivedAt: string;
  startedAt: string;
  finishedAt: string;
  source: string;
  environment: string;
  gitCommit: string | null;
  summary: z.infer<typeof summary>;
  sections: { name: string; kind: string; summary: z.infer<typeof summary> }[];
}

export async function listReports(appId: string, q: { page: number; pageSize: number }) {
  const [{ rows }, total] = await Promise.all([
    pool.query(
      `select id, received_at, started_at, finished_at, source, environment, git_commit, summary,
              (select coalesce(jsonb_agg(jsonb_build_object('name', s->'name', 'kind', s->'kind', 'summary', s->'summary')), '[]')
                 from jsonb_array_elements(sections) s) as sections
         from public.scan_reports where app_id = $1 order by received_at desc limit $2 offset $3`,
      [appId, q.pageSize, (q.page - 1) * q.pageSize],
    ),
    pool.query<{ n: number }>('select count(*)::int as n from public.scan_reports where app_id = $1', [appId]),
  ]);
  return {
    data: rows.map(
      (r): ScanReportRow => ({
        id: r.id,
        receivedAt: r.received_at.toISOString(),
        startedAt: r.started_at.toISOString(),
        finishedAt: r.finished_at.toISOString(),
        source: r.source,
        environment: r.environment,
        gitCommit: r.git_commit,
        summary: r.summary,
        sections: r.sections,
      }),
    ),
    meta: { page: q.page, pageSize: q.pageSize, total: total.rows[0]!.n, totalPages: Math.max(1, Math.ceil(total.rows[0]!.n / q.pageSize)) },
  };
}

export async function getReport(appId: string, id: string) {
  const { rows } = await pool.query(
    `select id, received_at, started_at, finished_at, source, environment, git_commit, summary, sections
       from public.scan_reports where app_id = $1 and id = $2`,
    [appId, id],
  );
  const r = rows[0];
  if (!r) return null;
  return {
    id: r.id as string,
    receivedAt: r.received_at.toISOString() as string,
    startedAt: r.started_at.toISOString() as string,
    finishedAt: r.finished_at.toISOString() as string,
    source: r.source as string,
    environment: r.environment as string,
    gitCommit: r.git_commit as string | null,
    summary: r.summary as z.infer<typeof summary>,
    sections: r.sections as z.infer<typeof section>[],
  };
}
