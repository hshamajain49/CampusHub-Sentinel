// Detection rules (table detection_rules), cached for 30 s; editing a rule clears the cache.
import { pool, type DbClient } from '../../db/pool.js';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
export const rank = (s: string) => SEVERITIES.indexOf(s as Severity);

export interface Rule {
  id: string;
  key: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: Exclude<Severity, 'info'>;
  classification: 'suspicious' | 'policy_violation';
  categories: string[];
  groupBy: 'source_ip' | 'user_ref' | 'account' | 'source_ip_route' | 'app';
  threshold: number;
  windowSeconds: number;
  distinctField: 'account' | 'source_ip' | 'user_ref' | 'route' | null;
  cooldownSeconds: number;
  autoBlock: boolean;
  blockSeconds: number;
  params: Record<string, any>;
  updatedAt: string;
}

export const toRule = (r: any): Rule => ({
  id: r.id,
  key: r.key,
  name: r.name,
  description: r.description,
  enabled: r.enabled,
  severity: r.severity,
  classification: r.classification,
  categories: r.categories,
  groupBy: r.group_by,
  threshold: r.threshold,
  windowSeconds: r.window_seconds,
  distinctField: r.distinct_field,
  cooldownSeconds: r.cooldown_seconds,
  autoBlock: r.auto_block,
  blockSeconds: r.block_seconds,
  params: r.params ?? {},
  updatedAt: new Date(r.updated_at).toISOString(),
});

let cache: { rules: Rule[]; at: number } | null = null;

export async function allRules(): Promise<Rule[]> {
  if (cache && Date.now() - cache.at < 30_000) return cache.rules;
  const { rows } = await pool.query('select * from public.detection_rules order by key');
  cache = { rules: rows.map(toRule), at: Date.now() };
  return cache.rules;
}

export function invalidateRules() {
  cache = null;
}

export interface RulePatch {
  enabled?: boolean;
  severity?: Rule['severity'];
  threshold?: number;
  windowSeconds?: number;
  cooldownSeconds?: number;
  autoBlock?: boolean;
  blockSeconds?: number;
}

/** Changes the tunable parts of a rule (what it counts and how it groups are fixed by its definition). */
export async function updateRule(key: string, patch: RulePatch, adminId: string | null, db: DbClient = pool): Promise<{ before: Rule; after: Rule } | null> {
  const cur = (await db.query('select * from public.detection_rules where key = $1 for update', [key])).rows[0];
  if (!cur) return null;
  const { rows } = await db.query(
    `update public.detection_rules
        set enabled = coalesce($2, enabled), severity = coalesce($3, severity), threshold = coalesce($4, threshold),
            window_seconds = coalesce($5, window_seconds), cooldown_seconds = coalesce($6, cooldown_seconds),
            auto_block = coalesce($7, auto_block), block_seconds = coalesce($8, block_seconds), updated_by = $9
      where key = $1 returning *`,
    [
      key,
      patch.enabled ?? null,
      patch.severity ?? null,
      patch.threshold ?? null,
      patch.windowSeconds ?? null,
      patch.cooldownSeconds ?? null,
      patch.autoBlock ?? null,
      patch.blockSeconds ?? null,
      adminId,
    ],
  );
  invalidateRules();
  return { before: toRule(cur), after: toRule(rows[0]) };
}
