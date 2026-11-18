// Registers the application Sentinel monitors (or updates its name and allowed origins).
//   npm run app:register -w @sentinel/backend -- --slug campushub --name CampusHub --origin https://campushub.pages.dev [--origin …]
// First run prints the public site key (for CampusHub's VITE_SENTINEL_SITE_KEY) and, once only, the ingestion key id
// and secret for CampusHub's API (Phase 5). Re-running never changes keys.
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { registerApp } from '../modules/apps/apps.service.js';

const args = process.argv.slice(2);
const values = (name: string) => args.flatMap((a, i) => (a === `--${name}` && args[i + 1] ? [args[i + 1]!] : []));

const input = z
  .object({
    slug: z.string().regex(/^[a-z][a-z0-9-]{1,40}$/),
    name: z.string().trim().min(2).max(80),
    origins: z
      .array(z.url().transform((u) => new URL(u).origin))
      .min(1)
      .max(10),
  })
  .safeParse({ slug: values('slug')[0] ?? '', name: values('name')[0] ?? '', origins: values('origin') });

async function main() {
  if (!input.success) {
    console.error('Usage: app:register --slug <slug> --name "<Name>" --origin <https://app.example> [--origin …]');
    for (const i of input.error.issues) console.error(`  ${i.path.join('.')}: ${i.message}`);
    process.exit(1);
  }
  const out = await registerApp(input.data);
  console.log(`\n${out.created ? 'Registered' : 'Updated'} ${out.app.name} (${out.app.slug}).`);
  console.log(`  Allowed origins: ${out.app.allowedOrigins.join(', ')}`);
  console.log(`  Site key (public, for VITE_SENTINEL_SITE_KEY): ${out.app.siteKey}`);
  if (out.created) {
    // Printed once; store them in CampusHub's API environment (Phase 5). Never commit them.
    console.log(`  Ingestion key id: ${out.ingestKeyId}`);
    console.log(`  Ingestion secret: ${out.ingestSecret}\n  (shown once)`);
  }
  console.log('');
}

main()
  .then(() => pool.end())
  .catch(async (err) => {
    console.error(err?.message || err?.code || err?.errors?.[0]?.message || err); // AggregateError (DB down) has an empty message
    await pool.end();
    process.exit(1);
  });
