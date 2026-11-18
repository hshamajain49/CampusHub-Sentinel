// Developer accounts (owners only; every change needs a fresh password + code confirmation). Accounts are never
// deleted, only deactivated, so the audit trail always resolves to a person. At least one active owner always exists.
import { pool, withTransaction } from '../../db/pool.js';
import { appError } from '../../errors/app-error.js';
import { generatePassword, hashPassword } from '../../lib/passwords.js';
import type { AdminInfo } from '../../types/express.js';
import { type AuditActor, writeAudit } from '../audit/audit.service.js';
import { revokeAdminSessions } from '../auth/sessions.js';

function toAdmin(r: any) {
  return {
    id: r.id,
    email: r.email,
    displayName: r.display_name,
    role: r.role,
    isActive: r.is_active,
    totpEnabled: !!r.totp_enabled_at,
    mustChangePassword: r.must_change_password,
    lastLoginAt: r.last_login_at ? new Date(r.last_login_at).toISOString() : null,
    createdAt: new Date(r.created_at).toISOString(),
  };
}

const COLUMNS = 'id, email, display_name, role, is_active, totp_enabled_at, must_change_password, last_login_at, created_at';

export async function listAdmins() {
  const { rows } = await pool.query(`select ${COLUMNS} from public.administrator_accounts order by is_active desc, created_at`);
  return rows.map(toAdmin);
}

export async function createAdmin(actor: AuditActor, body: { email: string; displayName: string; role: AdminInfo['role'] }) {
  const temporaryPassword = generatePassword();
  const hash = await hashPassword(temporaryPassword);
  return withTransaction(async (tx) => {
    const exists = await tx.query('select 1 from public.administrator_accounts where email = $1', [body.email]);
    if (exists.rowCount) throw appError('CONFLICT', 'A developer with this email already exists.', { fieldErrors: { email: ['Already in use.'] } });
    const { rows } = await tx.query(
      `insert into public.administrator_accounts (email, display_name, role, password_hash, must_change_password, created_by)
       values ($1, $2, $3, $4, true, $5) returning ${COLUMNS}`,
      [body.email, body.displayName, body.role, hash, actor.adminId],
    );
    await writeAudit(tx, actor, { action: 'admin.created', targetType: 'administrator', targetId: rows[0].id, details: { email: body.email, role: body.role } });
    // Shown once. They replace it and set up an authenticator at first sign-in.
    return { admin: toAdmin(rows[0]), temporaryPassword };
  });
}

async function lockTarget(tx: any, id: string) {
  const { rows } = await tx.query(`select ${COLUMNS} from public.administrator_accounts where id = $1 for update`, [id]);
  if (!rows[0]) throw appError('NOT_FOUND', 'Developer not found.');
  return rows[0];
}

export async function deactivateAdmin(actor: AuditActor, id: string) {
  return withTransaction(async (tx) => {
    if (id === actor.adminId) throw appError('CONFLICT', "You can't deactivate your own account.");
    const t = await lockTarget(tx, id);
    if (!t.is_active) return toAdmin(t);
    if (t.role === 'owner') {
      // Lock every active owner row, so two owners deactivating each other at once can't leave none.
      const { rows } = await tx.query("select id from public.administrator_accounts where role = 'owner' and is_active for update");
      if (rows.length <= 1) throw appError('LAST_OWNER');
    }
    const { rows } = await tx.query(`update public.administrator_accounts set is_active = false where id = $1 returning ${COLUMNS}`, [id]);
    await revokeAdminSessions(tx, id);
    await writeAudit(tx, actor, { action: 'admin.deactivated', targetType: 'administrator', targetId: id, details: { email: t.email } });
    return toAdmin(rows[0]);
  });
}

/** Lost authenticator: removes it and signs the account out; a new one is set up at the next sign-in. */
export async function resetAdminMfa(actor: AuditActor, id: string) {
  return withTransaction(async (tx) => {
    const t = await lockTarget(tx, id);
    const { rows } = await tx.query(
      `update public.administrator_accounts
          set totp_secret = null, totp_pending_secret = null, totp_pending_at = null, totp_enabled_at = null,
              recovery_codes = '{}', mfa_failures = 0, mfa_locked_until = null
        where id = $1 returning ${COLUMNS}`,
      [id],
    );
    await revokeAdminSessions(tx, id);
    await writeAudit(tx, actor, { action: 'admin.mfa_reset', targetType: 'administrator', targetId: id, details: { email: t.email } });
    return toAdmin(rows[0]);
  });
}
