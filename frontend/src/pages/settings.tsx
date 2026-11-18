// Settings: your account and alert emails; developers, detection rules and the monitored application (owners change
// them, each change confirmed with password + code and written to the audit log).
import * as React from 'react';
import { useSearchParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, KeyRound, RotateCcw, UserPlus } from 'lucide-react';
import { toast } from 'sonner';
import { useReauth } from '@/auth/reauth';
import { useAdmin, useSession } from '@/auth/session';
import { api, ApiError, errorText, patch, post, put } from '@/lib/api';
import { ago, dateTimeFull } from '@/lib/format';
import type { Rule } from '@/lib/types';
import { Button, Card, Empty, Field, inputCls, Modal, Mono, PageHeader, Pill, Segmented, SeverityBadge, Spinner, Table, td } from '@/components/ui';

const cancelled = (e: unknown) => e instanceof ApiError && e.code === 'REAUTH_CANCELLED';
const fail = (e: unknown) => !cancelled(e) && toast.error(errorText(e));

function Account() {
  const { session } = useSession();
  const qc = useQueryClient();
  const prefs = useQuery({
    queryKey: ['prefs'],
    queryFn: () => api<{ emailEnabled: boolean; minSeverity: 'medium' | 'high' | 'critical'; quietHours: { start: string; end: string } | null; timezone: string; transport: string }>('/api/me/notifications'),
  });
  const [draft, setDraft] = React.useState<typeof prefs.data | null>(null);
  React.useEffect(() => {
    if (prefs.data) setDraft(prefs.data);
  }, [prefs.data]);
  const save = useMutation({
    mutationFn: () => put('/api/me/notifications', { emailEnabled: draft!.emailEnabled, minSeverity: draft!.minSeverity, quietHours: draft!.quietHours }),
    onSuccess: (p) => (qc.setQueryData(['prefs'], p), toast.success('Saved.')),
    onError: fail,
  });
  const [pw, setPw] = React.useState({ current: '', next: '' });
  const changePw = useMutation({
    mutationFn: () => post('/api/auth/password', { currentPassword: pw.current, newPassword: pw.next }),
    onSuccess: () => (setPw({ current: '', next: '' }), toast.success('Password changed. Your other sessions were signed out.')),
    onError: fail,
  });
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Card title="Your session">
        <dl className="grid gap-2 text-[13px]">
          <div>
            <dt className="text-muted">Signed in as</dt>
            <dd>
              {session?.admin.displayName} · {session?.admin.email} · <Pill>{session?.admin.role}</Pill>
            </dd>
          </div>
          <div>
            <dt className="text-muted">Session ends at the latest</dt>
            <dd>{dateTimeFull(session?.expiresAt)} (or after 30 minutes without activity)</dd>
          </div>
        </dl>
      </Card>
      <Card title="Alert emails" subtitle={prefs.data?.transport === 'brevo' ? 'Sent through Brevo' : 'Email isn’t configured on the server: alerts are only logged'}>
        {!draft ? (
          <Spinner />
        ) : (
          <form
            className="grid gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate();
            }}
          >
            <label className="flex items-center gap-2 text-[13px]">
              <input type="checkbox" className="size-4 accent-[var(--primary)]" checked={draft.emailEnabled} onChange={(e) => setDraft({ ...draft, emailEnabled: e.target.checked })} />
              Email me about new and escalated alerts
            </label>
            <Field label="Minimum severity">
              <Segmented
                label="Minimum severity"
                value={draft.minSeverity}
                onChange={(v) => setDraft({ ...draft, minSeverity: v })}
                options={[
                  { value: 'medium', label: 'Medium and up' },
                  { value: 'high', label: 'High and up' },
                  { value: 'critical', label: 'Critical only' },
                ]}
              />
            </Field>
            <Field label={`Quiet hours (${draft.timezone}); critical alerts still arrive`}>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  aria-label="Use quiet hours"
                  className="size-4 accent-[var(--primary)]"
                  checked={!!draft.quietHours}
                  onChange={(e) => setDraft({ ...draft, quietHours: e.target.checked ? { start: '22:00', end: '07:00' } : null })}
                />
                {draft.quietHours && (
                  <>
                    <input aria-label="Quiet from" type="time" className={`${inputCls} w-[120px]`} value={draft.quietHours.start} onChange={(e) => setDraft({ ...draft, quietHours: { ...draft.quietHours!, start: e.target.value } })} />
                    <span className="text-muted">to</span>
                    <input aria-label="Quiet until" type="time" className={`${inputCls} w-[120px]`} value={draft.quietHours.end} onChange={(e) => setDraft({ ...draft, quietHours: { ...draft.quietHours!, end: e.target.value } })} />
                  </>
                )}
              </div>
            </Field>
            <div>
              <Button type="submit" variant="primary" loading={save.isPending}>
                Save
              </Button>
            </div>
          </form>
        )}
      </Card>
      <Card title="Change password" subtitle="At least 12 characters; your other sessions are signed out">
        <form
          className="grid gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            changePw.mutate();
          }}
        >
          <Field label="Current password">
            <input type="password" autoComplete="current-password" className={inputCls} value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} />
          </Field>
          <Field label="New password">
            <input type="password" autoComplete="new-password" className={inputCls} value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
          </Field>
          <div>
            <Button type="submit" loading={changePw.isPending} disabled={!pw.current || pw.next.length < 12}>
              <KeyRound /> Change password
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

interface AdminRow {
  id: string;
  email: string;
  displayName: string;
  role: 'owner' | 'analyst';
  isActive: boolean;
  totpEnabled: boolean;
  mustChangePassword: boolean;
  lastLoginAt: string | null;
  createdAt: string;
}

function Developers() {
  const me = useAdmin();
  const qc = useQueryClient();
  const withReauth = useReauth();
  const q = useQuery({ queryKey: ['admins'], queryFn: () => api<AdminRow[]>('/api/admins') });
  const [form, setForm] = React.useState({ email: '', displayName: '', role: 'analyst' as 'owner' | 'analyst' });
  const [created, setCreated] = React.useState<{ email: string; temporaryPassword: string } | null>(null);
  const create = useMutation({
    mutationFn: () => withReauth(() => post<{ admin: AdminRow; temporaryPassword: string }>('/api/admins', form)),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ['admins'] });
      setCreated({ email: r.admin.email, temporaryPassword: r.temporaryPassword });
      setForm({ email: '', displayName: '', role: 'analyst' });
    },
    onError: fail,
  });
  const act = useMutation({
    mutationFn: ({ id, what }: { id: string; what: 'deactivate' | 'reset-mfa' }) => withReauth(() => post(`/api/admins/${id}/${what}`)),
    onSuccess: (_r, v) => (void qc.invalidateQueries({ queryKey: ['admins'] }), toast.success(v.what === 'deactivate' ? 'Deactivated and signed out.' : 'Authenticator reset; they set up a new one at next sign-in.')),
    onError: fail,
  });
  return (
    <div className="grid gap-3">
      <Card title="Developers" subtitle="Accounts are deactivated, never deleted, so the audit log always names a person">
        {!q.data ? (
          <Spinner />
        ) : (
          <Table head={['Name', 'Role', 'Two-step', 'Last sign-in', 'State', '']}>
            {q.data.map((a) => (
              <tr key={a.id}>
                <td className={td}>
                  <div>{a.displayName}</div>
                  <div className="text-[12px] text-muted">{a.email}</div>
                </td>
                <td className={td}>
                  <Pill>{a.role}</Pill>
                </td>
                <td className={td}>{a.totpEnabled ? <Pill tone="good">On</Pill> : <Pill tone="warning">Not set up</Pill>}</td>
                <td className={`${td} text-[12px] text-ink-2`}>{a.lastLoginAt ? ago(a.lastLoginAt) : 'never'}</td>
                <td className={td}>{a.isActive ? (a.mustChangePassword ? <Pill tone="warning">Temporary password</Pill> : <Pill tone="good">Active</Pill>) : <Pill>Deactivated</Pill>}</td>
                <td className={`${td} whitespace-nowrap text-right`}>
                  {a.isActive && (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => act.mutate({ id: a.id, what: 'reset-mfa' })} title="Lost phone: remove their authenticator">
                        <RotateCcw /> Reset 2FA
                      </Button>
                      {a.id !== me.id && (
                        <Button size="sm" variant="ghost" className="text-critical-text" onClick={() => confirm(`Deactivate ${a.email}?`) && act.mutate({ id: a.id, what: 'deactivate' })}>
                          Deactivate
                        </Button>
                      )}
                    </>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <Card title="Add a developer" subtitle="They get a temporary password, replace it at first sign-in and must set up an authenticator">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <Field label="Name">
            <input className={`${inputCls} w-[180px]`} value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
          </Field>
          <Field label="Email">
            <input type="email" className={`${inputCls} w-[240px]`} value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          </Field>
          <Field label="Role">
            <select className={`${inputCls} w-[130px]`} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as 'owner' | 'analyst' })}>
              <option value="analyst">Analyst</option>
              <option value="owner">Owner</option>
            </select>
          </Field>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={!form.email || form.displayName.trim().length < 2}>
            <UserPlus /> Add
          </Button>
        </form>
      </Card>
      <Modal open={!!created} onClose={() => setCreated(null)} title="Developer added">
        {created && (
          <div className="grid gap-3 text-[13px]">
            <p>Give {created.email} this temporary password through a private channel. It is shown only now.</p>
            <div className="flex items-center gap-2 rounded-[8px] bg-surface-2 px-3 py-2">
              <code className="flex-1 break-all font-mono">{created.temporaryPassword}</code>
              <Button size="sm" variant="ghost" aria-label="Copy password" onClick={() => void navigator.clipboard?.writeText(created.temporaryPassword).then(() => toast.success('Copied.'))}>
                <Copy />
              </Button>
            </div>
            <Button variant="primary" onClick={() => setCreated(null)}>
              Done
            </Button>
          </div>
        )}
      </Modal>
    </div>
  );
}

const windowText = (s: number) => (s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`);

function RuleRow({ rule, canEdit }: { rule: Rule; canEdit: boolean }) {
  const qc = useQueryClient();
  const withReauth = useReauth();
  const [edit, setEdit] = React.useState(false);
  const [d, setD] = React.useState({ threshold: rule.threshold, windowMinutes: Math.max(1, Math.round(rule.windowSeconds / 60)), severity: rule.severity, cooldownMinutes: Math.round(rule.cooldownSeconds / 60), autoBlock: rule.autoBlock });
  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => withReauth(() => patch<Rule>(`/api/security/rules/${rule.key}`, body)),
    onSuccess: () => (void qc.invalidateQueries({ queryKey: ['rules'] }), setEdit(false), toast.success(`${rule.name} updated.`)),
    onError: fail,
  });
  return (
    <tr>
      <td className={td}>
        <div className="font-medium">{rule.name}</div>
        <div className="max-w-[420px] text-[12px] text-muted">{rule.description}</div>
      </td>
      <td className={td}>
        <SeverityBadge severity={rule.severity} />
      </td>
      <td className={`${td} whitespace-nowrap text-[12.5px]`}>
        {edit ? (
          <div className="grid gap-1.5">
            <label className="flex items-center gap-1.5">
              ≥ <input aria-label="Threshold" type="number" min={1} className={`${inputCls} h-8 w-[80px]`} value={d.threshold} onChange={(e) => setD({ ...d, threshold: Number(e.target.value) })} />
            </label>
            <label className="flex items-center gap-1.5">
              in <input aria-label="Window minutes" type="number" min={1} max={1440} className={`${inputCls} h-8 w-[80px]`} value={d.windowMinutes} onChange={(e) => setD({ ...d, windowMinutes: Number(e.target.value) })} /> min
            </label>
          </div>
        ) : (
          <>
            ≥ {rule.threshold} in {windowText(rule.windowSeconds)}
          </>
        )}
      </td>
      <td className={`${td} text-[12.5px]`}>
        {edit ? (
          <div className="grid gap-1.5">
            <select aria-label="Severity" className={`${inputCls} h-8`} value={d.severity} onChange={(e) => setD({ ...d, severity: e.target.value as Rule['severity'] })}>
              {['low', 'medium', 'high', 'critical'].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
            <label className="flex items-center gap-1.5">
              <input type="checkbox" checked={d.autoBlock} onChange={(e) => setD({ ...d, autoBlock: e.target.checked })} /> auto-block IP
            </label>
          </div>
        ) : (
          <div className="grid gap-1">
            <span>{rule.enabled ? <Pill tone="good">On</Pill> : <Pill>Off</Pill>}</span>
            {rule.autoBlock && <Pill tone="warning">Auto-blocks {windowText(rule.blockSeconds)}</Pill>}
          </div>
        )}
      </td>
      <td className={`${td} whitespace-nowrap text-right`}>
        {canEdit &&
          (edit ? (
            <div className="flex justify-end gap-1">
              <Button size="sm" variant="ghost" onClick={() => setEdit(false)}>
                Cancel
              </Button>
              <Button
                size="sm"
                variant="primary"
                loading={save.isPending}
                onClick={() =>
                  save.mutate({ threshold: d.threshold, windowSeconds: d.windowMinutes * 60, severity: d.severity, cooldownSeconds: d.cooldownMinutes * 60, autoBlock: d.autoBlock })
                }
              >
                Save
              </Button>
            </div>
          ) : (
            <div className="flex justify-end gap-1">
              <Button size="sm" variant="ghost" onClick={() => save.mutate({ enabled: !rule.enabled })}>
                {rule.enabled ? 'Turn off' : 'Turn on'}
              </Button>
              <Button size="sm" onClick={() => setEdit(true)}>
                Edit
              </Button>
            </div>
          ))}
      </td>
    </tr>
  );
}

function Rules() {
  const admin = useAdmin();
  const q = useQuery({ queryKey: ['rules'], queryFn: () => api<Rule[]>('/api/security/rules') });
  return (
    <Card title="Detection rules" subtitle={admin.role === 'owner' ? 'Changes ask for your password and a code, and are audited' : 'Only owners can change rules'}>
      {!q.data ? (
        <Spinner />
      ) : (
        <Table head={['Rule', 'Severity', 'Fires at', 'State', '']}>
          {q.data.map((r) => (
            <RuleRow key={r.key} rule={r} canEdit={admin.role === 'owner'} />
          ))}
        </Table>
      )}
    </Card>
  );
}

function Application() {
  const admin = useAdmin();
  const withReauth = useReauth();
  const q = useQuery({
    queryKey: ['apps'],
    queryFn: () => api<{ data: { id: string; slug: string; name: string; allowedOrigins: string[]; isActive: boolean }[]; geoip: { edition: string; month: string } | null }>('/api/apps', { raw: true }),
  });
  const [secret, setSecret] = React.useState<{ ingestKeyId: string; ingestSecret: string } | null>(null);
  const rotate = useMutation({
    mutationFn: (slug: string) => withReauth(() => post<{ ingestKeyId: string; ingestSecret: string }>(`/api/apps/${slug}/rotate-secret`)),
    onSuccess: setSecret,
    onError: fail,
  });
  if (!q.data) return <Spinner />;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      {q.data.data.length ? (
        q.data.data.map((a) => (
          <Card key={a.id} title={a.name} subtitle={`slug ${a.slug}`}>
            <dl className="grid gap-2 text-[13px]">
              <div>
                <dt className="text-muted">Page views accepted from</dt>
                <dd className="font-mono text-[12.5px]">{a.allowedOrigins.join(', ') || '—'}</dd>
              </div>
              <div>
                <dt className="text-muted">Status</dt>
                <dd>{a.isActive ? <Pill tone="good">Active</Pill> : <Pill>Inactive</Pill>}</dd>
              </div>
            </dl>
            {admin.role === 'owner' && (
              <div className="mt-4 border-t border-line pt-3">
                <p className="mb-2 text-[12.5px] text-muted">New ingestion credentials for CampusHub's API. The old ones stop working immediately: update CampusHub's environment right after.</p>
                <Button onClick={() => confirm('Rotate the ingestion secret now? CampusHub stops reporting until you update it.') && rotate.mutate(a.slug)} loading={rotate.isPending}>
                  <RotateCcw /> Rotate ingestion secret
                </Button>
              </div>
            )}
          </Card>
        ))
      ) : (
        <Card title="No application registered">
          <Empty>
            Register CampusHub on the server: <Mono>npm run app:register -w @sentinel/backend -- --slug campushub …</Mono>
          </Empty>
        </Card>
      )}
      <Card title="Data and privacy">
        <dl className="grid gap-2 text-[13px]">
          <div>
            <dt className="text-muted">Location data</dt>
            <dd>
              {q.data.geoip ? `DB-IP Lite, ${q.data.geoip.edition} edition (${q.data.geoip.month})` : 'Not loaded: locations show as unknown'} · IP geolocation by{' '}
              <a href="https://db-ip.com" className="underline" target="_blank" rel="noreferrer noopener">
                DB-IP
              </a>{' '}
              (CC BY 4.0)
            </dd>
          </div>
          <div>
            <dt className="text-muted">Retention</dt>
            <dd>Page views and visits 395 days · security events 90 days (evidence of open alerts and incidents is kept) · audit log 2 years</dd>
          </div>
          <div>
            <dt className="text-muted">Visitor privacy</dt>
            <dd>Networks only (/24, /48), no names, emails or what anyone types; Do-Not-Track and GPC honoured.</dd>
          </div>
        </dl>
      </Card>
      <Modal open={!!secret} onClose={() => setSecret(null)} title="New ingestion credentials">
        {secret && (
          <div className="grid gap-3 text-[13px]">
            <p>Put these in CampusHub's API environment now. They are shown only once.</p>
            <pre className="overflow-auto rounded-[8px] bg-surface-2 p-3 font-mono text-[12.5px]">{`SENTINEL_INGEST_KEY_ID=${secret.ingestKeyId}\nSENTINEL_INGEST_SECRET=${secret.ingestSecret}`}</pre>
            <Button
              onClick={() => void navigator.clipboard?.writeText(`SENTINEL_INGEST_KEY_ID=${secret.ingestKeyId}\nSENTINEL_INGEST_SECRET=${secret.ingestSecret}`).then(() => toast.success('Copied.'))}
            >
              <Copy /> Copy
            </Button>
          </div>
        )}
      </Modal>
    </div>
  );
}

export function SettingsPage() {
  const admin = useAdmin();
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') ?? 'account';
  const tabs = [
    { value: 'account', label: 'Account' },
    ...(admin.role === 'owner' ? [{ value: 'developers', label: 'Developers' }] : []),
    { value: 'rules', label: 'Detection rules' },
    { value: 'application', label: 'Application' },
  ];
  return (
    <>
      <PageHeader title="Settings" subtitle="Your account, the team, detection and the monitored application." actions={<Segmented label="Settings section" value={tab} onChange={(v) => setParams({ tab: v }, { replace: true })} options={tabs} />} />
      {tab === 'account' && <Account />}
      {tab === 'developers' && admin.role === 'owner' && <Developers />}
      {tab === 'rules' && <Rules />}
      {tab === 'application' && <Application />}
    </>
  );
}
