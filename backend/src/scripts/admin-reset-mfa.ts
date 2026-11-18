// Lost authenticator (and no recovery codes): removes it and signs the account out everywhere. Out-of-band only.
//   npm run admin:reset-mfa -w @sentinel/backend -- --email dev@college.edu
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { resetAdminMfa } from '../modules/admins/admins.service.js';

const i = process.argv.indexOf('--email');
const email = z.string().trim().toLowerCase().pipe(z.email()).safeParse(i >= 0 ? process.argv[i + 1] : '');

async function main() {
  if (!email.success) {
    console.error('Usage: admin:reset-mfa --email <email>');
    process.exit(1);
  }
  const { rows } = await pool.query<{ id: string }>('select id from public.administrator_accounts where email = $1', [email.data]);
  if (!rows[0]) {
    console.error('No developer account with that email.');
    process.exit(1);
  }
  await resetAdminMfa({ adminId: null, adminEmail: 'cli', ip: null, userAgent: 'admin:reset-mfa script' }, rows[0].id);
  console.log('Authenticator removed and all sessions signed out. A new one is set up at the next sign-in.');
}

main()
  .then(() => pool.end())
  .catch(async (err) => {
    console.error(err?.message || err?.code || err?.errors?.[0]?.message || err); // AggregateError (DB down) has an empty message
    await pool.end();
    process.exit(1);
  });
