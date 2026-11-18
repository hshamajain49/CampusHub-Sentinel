// Adds a developer account. Out-of-band only (also available to owners in the dashboard). The first account is
// always an owner. The temporary password is printed once; it is replaced, and an authenticator set up, at first
// sign-in.
//   npm run admin:create -w @sentinel/backend -- --email dev@college.edu --name "Dev Name" [--role owner|analyst]
// Against production: ENV_FILE=none with the production DATABASE_URL and DATA_ENCRYPTION_KEY in the environment.
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { createAdmin } from '../modules/admins/admins.service.js';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const input = z
    .object({
      email: z.string().trim().toLowerCase().pipe(z.email()),
      displayName: z.string().trim().min(2).max(100),
      role: z.enum(['owner', 'analyst']).default('analyst'),
    })
    .safeParse({ email: arg('email') ?? '', displayName: arg('name') ?? '', role: arg('role') });
  if (!input.success) {
    console.error('Usage: admin:create --email <email> --name "<Full Name>" [--role owner|analyst]');
    process.exit(1);
  }
  const { rows } = await pool.query<{ n: number }>("select count(*)::int as n from public.administrator_accounts where role = 'owner' and is_active");
  const role = rows[0]!.n === 0 ? 'owner' : input.data.role;
  if (role !== input.data.role) console.log('No active owner exists yet, so this account is created as an owner.');
  const out = await createAdmin({ adminId: null, adminEmail: 'cli', ip: null, userAgent: 'admin:create script' }, { ...input.data, role });
  // Printed once to the terminal; never logged or stored.
  process.stdout.write(
    `\nDeveloper account created.\n  Email:              ${out.admin.email}\n  Role:               ${out.admin.role}\n  Temporary password: ${out.temporaryPassword}\n` +
      'At first sign-in they choose a new password and set up an authenticator app.\n\n',
  );
}

main()
  .then(() => pool.end())
  .catch(async (err) => {
    console.error(err?.message || err?.code || err?.errors?.[0]?.message || err); // AggregateError (DB down) has an empty message
    await pool.end();
    process.exit(1);
  });
