// Alert emails. Sent when an alert opens or its severity rises (never for every repeat), to each active developer
// whose preferences cover that severity (default: high and critical). Quiet hours hold back everything but critical.
// Alerts raised only by simulated test traffic are never emailed. Every attempt is recorded in notification_log.
import { config } from '../../config/env.js';
import { pool } from '../../db/pool.js';
import { logger } from '../../lib/logger.js';
import { rank } from '../security/rules.js';

export interface EmailMessage {
  to: { email: string; name: string };
  subject: string;
  text: string;
  html: string;
}

export interface EmailTransport {
  send(m: EmailMessage): Promise<void>;
}

const brevo: EmailTransport = {
  async send(m) {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': config.BREVO_API_KEY!, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        sender: { email: config.ALERT_EMAIL_FROM, name: config.ALERT_EMAIL_FROM_NAME },
        to: [m.to],
        subject: m.subject,
        textContent: m.text,
        htmlContent: m.html,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`Brevo HTTP ${res.status}`);
  },
};

const logOnly: EmailTransport = {
  async send(m) {
    logger.info({ to: m.to.email, subject: m.subject }, 'alert email (EMAIL_TRANSPORT=log: not sent)');
  },
};

let transport: EmailTransport | null = config.EMAIL_TRANSPORT === 'brevo' ? brevo : config.EMAIL_TRANSPORT === 'log' ? logOnly : null;

/** Tests swap the transport. */
export function setEmailTransport(t: EmailTransport | null) {
  transport = t;
}

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** Is "now" inside [start, end) in REPORT_TIMEZONE? Handles ranges that cross midnight (22:00–07:00). */
export function inQuietHours(start: string | null, end: string | null, now = new Date()): boolean {
  if (!start || !end) return false;
  const hm = new Intl.DateTimeFormat('en-GB', { timeZone: config.REPORT_TIMEZONE, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(now);
  const t = hm.slice(0, 5);
  const s = start.slice(0, 5);
  const e = end.slice(0, 5);
  return s <= e ? t >= s && t < e : t >= s || t < e;
}

export function renderAlertEmail(a: { id: string; severity: string; title: string; reason: string; app: string; firstSeen: Date; lastSeen: Date; occurrences: number }) {
  const url = `${config.APP_ORIGIN}/alerts/${a.id}`;
  const subject = `[Sentinel] ${a.severity.toUpperCase()}: ${a.title} (${a.app})`.slice(0, 200);
  const lines = [
    `${a.severity.toUpperCase()} alert for ${a.app}`,
    '',
    a.title,
    a.reason,
    '',
    `First seen: ${a.firstSeen.toISOString()}`,
    `Last seen:  ${a.lastSeen.toISOString()}`,
    `Occurrences: ${a.occurrences}`,
    '',
    `Investigate: ${url}`,
    '',
    'This is a detection, not proof of a compromise. Sign in to Sentinel to review the evidence.',
  ];
  const html = `<div style="font-family:system-ui,sans-serif;font-size:14px;line-height:1.5;color:#111">
<p><strong>${escapeHtml(a.severity.toUpperCase())}</strong> alert for ${escapeHtml(a.app)}</p>
<p style="font-size:16px"><strong>${escapeHtml(a.title)}</strong></p>
<p>${escapeHtml(a.reason)}</p>
<p style="color:#555">First seen ${escapeHtml(a.firstSeen.toISOString())} · last seen ${escapeHtml(a.lastSeen.toISOString())} · ${a.occurrences} occurrence(s)</p>
<p><a href="${escapeHtml(url)}">Investigate in Sentinel</a></p>
<p style="color:#777;font-size:12px">This is a detection, not proof of a compromise.</p></div>`;
  return { subject, text: lines.join('\n'), html };
}

export async function notifyAlert(alertId: string): Promise<{ sent: number; skipped: number; failed: number }> {
  const result = { sent: 0, skipped: 0, failed: 0 };
  const { rows } = await pool.query(
    `select a.id, a.severity, a.title, a.detection_reason, a.first_seen_at, a.last_seen_at, a.occurrences, a.simulated, m.name as app
       from public.security_alerts a join public.monitored_applications m on m.id = a.app_id where a.id = $1`,
    [alertId],
  );
  const a = rows[0];
  if (!a || a.simulated || !transport) return result;
  const recipients = await pool.query(
    `select ad.id, ad.email, ad.display_name, coalesce(p.email_enabled, true) as enabled, coalesce(p.min_severity, 'high') as min_severity,
            p.quiet_hours_start::text as qs, p.quiet_hours_end::text as qe
       from public.administrator_accounts ad left join public.notification_preferences p on p.admin_id = ad.id
      where ad.is_active`,
  );
  const mail = renderAlertEmail({
    id: a.id,
    severity: a.severity,
    title: a.title,
    reason: a.detection_reason,
    app: a.app,
    firstSeen: a.first_seen_at,
    lastSeen: a.last_seen_at,
    occurrences: a.occurrences,
  });
  for (const r of recipients.rows) {
    if (!r.enabled || rank(a.severity) < rank(r.min_severity)) continue;
    if (a.severity !== 'critical' && inQuietHours(r.qs, r.qe)) {
      await logNotification(a.id, r.id, 'skipped', 'quiet hours');
      result.skipped++;
      continue;
    }
    try {
      await transport.send({ to: { email: r.email, name: r.display_name }, ...mail });
      await logNotification(a.id, r.id, 'sent', null);
      result.sent++;
    } catch (err: any) {
      await logNotification(a.id, r.id, 'failed', String(err?.message ?? err).slice(0, 500));
      result.failed++;
    }
  }
  await pool.query('update public.security_alerts set last_notified_at = now() where id = $1', [a.id]);
  return result;
}

async function logNotification(alertId: string, adminId: string, status: 'sent' | 'failed' | 'skipped', error: string | null) {
  await pool.query("insert into public.notification_log (alert_id, admin_id, channel, status, error) values ($1, $2, 'email', $3, $4)", [
    alertId,
    adminId,
    status,
    error,
  ]);
}

// ─────────────────────────── preferences ───────────────────────────
export async function getPreferences(adminId: string) {
  const { rows } = await pool.query(
    'select email_enabled, min_severity, quiet_hours_start::text as qs, quiet_hours_end::text as qe from public.notification_preferences where admin_id = $1',
    [adminId],
  );
  const r = rows[0];
  return {
    emailEnabled: r?.email_enabled ?? true,
    minSeverity: (r?.min_severity ?? 'high') as 'medium' | 'high' | 'critical',
    quietHours: r?.qs ? { start: r.qs.slice(0, 5), end: r.qe.slice(0, 5) } : null,
    timezone: config.REPORT_TIMEZONE,
    transport: config.EMAIL_TRANSPORT,
  };
}

export async function setPreferences(
  adminId: string,
  p: { emailEnabled: boolean; minSeverity: 'medium' | 'high' | 'critical'; quietHours: { start: string; end: string } | null },
) {
  await pool.query(
    `insert into public.notification_preferences (admin_id, email_enabled, min_severity, quiet_hours_start, quiet_hours_end, updated_at)
     values ($1, $2, $3, $4::time, $5::time, now())
     on conflict (admin_id) do update set email_enabled = $2, min_severity = $3, quiet_hours_start = $4::time, quiet_hours_end = $5::time, updated_at = now()`,
    [adminId, p.emailEnabled, p.minSeverity, p.quietHours?.start ?? null, p.quietHours?.end ?? null],
  );
  return getPreferences(adminId);
}
