// Monitored applications (CampusHub). The site key is public (it identifies the app in browser beacons); the
// ingestion secret is for server-to-server events (Phase 5), stored encrypted and shown once.
import { randomBytes } from 'node:crypto';
import { pool, withTransaction } from '../../db/pool.js';
import { encrypt, randomToken } from '../../lib/crypto.js';

export interface MonitoredApp {
  id: string;
  slug: string;
  name: string;
  siteKey: string;
  allowedOrigins: string[];
  isActive: boolean;
}

const toApp = (r: any): MonitoredApp => ({
  id: r.id,
  slug: r.slug,
  name: r.name,
  siteKey: r.site_key,
  allowedOrigins: r.allowed_origins,
  isActive: r.is_active,
});

// Beacons arrive on every page view: keep site-key lookups in memory for a minute.
const cache = new Map<string, { app: MonitoredApp | null; at: number }>();
const CACHE_MS = 60_000;

export async function appBySiteKey(siteKey: string): Promise<MonitoredApp | null> {
  const hit = cache.get(siteKey);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.app;
  const { rows } = await pool.query('select id, slug, name, site_key, allowed_origins, is_active from public.monitored_applications where site_key = $1', [siteKey]);
  const app = rows[0] ? toApp(rows[0]) : null;
  if (cache.size > 1000) cache.clear();
  cache.set(siteKey, { app, at: Date.now() });
  return app;
}

export function clearAppCache() {
  cache.clear();
}

export async function listApps(): Promise<MonitoredApp[]> {
  const { rows } = await pool.query('select id, slug, name, site_key, allowed_origins, is_active from public.monitored_applications order by created_at');
  return rows.map(toApp);
}

/** The app a dashboard query is about: by slug, or the first active one. */
export async function resolveApp(slug?: string): Promise<MonitoredApp | null> {
  const { rows } = await pool.query(
    `select id, slug, name, site_key, allowed_origins, is_active from public.monitored_applications
      where ($1::text is null or slug = $1) order by is_active desc, created_at limit 1`,
    [slug ?? null],
  );
  return rows[0] ? toApp(rows[0]) : null;
}

/**
 * New ingestion secret (and key id). The old pair stops working at once: update CampusHub's API environment right
 * after. The secret is returned once and stored only encrypted.
 */
export async function rotateIngestSecret(slug: string) {
  const ingestSecret = randomBytes(32).toString('base64url');
  const ingestKeyId = `ik_${randomToken(12)}`;
  const { rows } = await pool.query(
    `update public.monitored_applications set ingest_key_id = $2, ingest_secret = $3, ingest_secret_rotated_at = now()
      where slug = $1 returning id`,
    [slug, ingestKeyId, encrypt(ingestSecret, 'ingest-secret')],
  );
  if (!rows[0]) return null;
  const { clearIngestCache } = await import('../ingest/signature.js');
  clearIngestCache();
  return { appId: rows[0].id as string, ingestKeyId, ingestSecret };
}

/** Creates an app (keys and secret generated) or updates its name and allowed origins. */
export async function registerApp(input: { slug: string; name: string; origins: string[] }) {
  return withTransaction(async (tx) => {
    const existing = (await tx.query('select id from public.monitored_applications where slug = $1 for update', [input.slug])).rows[0];
    if (existing) {
      const { rows } = await tx.query(
        `update public.monitored_applications set name = $2, allowed_origins = $3 where id = $1
         returning id, slug, name, site_key, allowed_origins, is_active`,
        [existing.id, input.name, input.origins],
      );
      clearAppCache();
      return { app: toApp(rows[0]), created: false as const };
    }
    const ingestSecret = randomBytes(32).toString('base64url');
    const { rows } = await tx.query(
      `insert into public.monitored_applications (slug, name, site_key, allowed_origins, ingest_key_id, ingest_secret)
       values ($1, $2, $3, $4, $5, $6) returning id, slug, name, site_key, allowed_origins, is_active, ingest_key_id`,
      [input.slug, input.name, `sk_${randomToken(18)}`, input.origins, `ik_${randomToken(12)}`, encrypt(ingestSecret, 'ingest-secret')],
    );
    return { app: toApp(rows[0]), created: true as const, ingestKeyId: rows[0].ingest_key_id as string, ingestSecret };
  });
}
