// Issues a new ingestion key id and secret for an app (the old ones stop working at once). Printed once: put them in
// CampusHub's API environment (SENTINEL_INGEST_KEY_ID / SENTINEL_INGEST_SECRET) and redeploy it.
//   npm run app:rotate-secret -w @sentinel/backend -- --slug campushub
import { pool } from '../db/pool.js';
import { rotateIngestSecret } from '../modules/apps/apps.service.js';
import { writeAudit } from '../modules/audit/audit.service.js';

const i = process.argv.indexOf('--slug');
const slug = i >= 0 ? process.argv[i + 1] : undefined;

async function main() {
  if (!slug || !/^[a-z][a-z0-9-]{1,40}$/.test(slug)) {
    console.error('Usage: app:rotate-secret --slug <slug>');
    process.exit(1);
  }
  const out = await rotateIngestSecret(slug);
  if (!out) {
    console.error('No application with that slug.');
    process.exit(1);
  }
  await writeAudit(pool, { adminId: null, adminEmail: 'cli', ip: null, userAgent: 'app:rotate-secret script' }, {
    action: 'app.secret_rotated',
    targetType: 'application',
    targetId: out.appId,
    details: { slug, keyId: out.ingestKeyId },
  });
  console.log(`\nNew ingestion credentials for ${slug} (shown once; the old ones no longer work):`);
  console.log(`  SENTINEL_INGEST_KEY_ID=${out.ingestKeyId}`);
  console.log(`  SENTINEL_INGEST_SECRET=${out.ingestSecret}\n`);
}

main()
  .then(() => pool.end())
  .catch(async (err) => {
    console.error(err?.message || err?.code || err?.errors?.[0]?.message || err); // AggregateError (DB down) has an empty message
    await pool.end();
    process.exit(1);
  });
