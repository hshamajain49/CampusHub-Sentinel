// Incidents: case files that group alerts with an owner, a status, a classification and append-only notes.
// "Unauthorised access verified" and "Compromise confirmed" are owner-only and a person's judgement, never automatic.
import * as React from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Plus } from 'lucide-react';
import { toast } from 'sonner';
import { useAdmin } from '@/auth/session';
import { api, errorText, list, patch, post, qs } from '@/lib/api';
import { ago, dateTimeFull } from '@/lib/format';
import type { Incident } from '@/lib/types';
import { NewIncidentDialog } from './threats';
import { Button, Card, Empty, ErrorNote, Field, inputCls, PageHeader, Pagination, Pill, rowLink, Segmented, SeverityBadge, SimulatedBadge, Spinner, StatusBadge, Table, td } from '@/components/ui';

export const CLASSIFICATIONS: { value: Incident['classification']; label: string; help: string; ownerOnly?: boolean }[] = [
  { value: 'suspicious', label: 'Suspicious activity', help: 'Something matched a rule. Nothing shows it succeeded.' },
  { value: 'policy_violation', label: 'Security policy violation', help: 'The activity broke a rule of how CampusHub may be used.' },
  { value: 'unauthorized_access_verified', label: 'Unauthorised access verified', help: 'Someone verifiably reached data or functions they must not.', ownerOnly: true },
  { value: 'compromise_confirmed', label: 'Compromise confirmed', help: 'An account, server or data store is confirmed compromised.', ownerOnly: true },
];
const classLabel = (c: Incident['classification']) => CLASSIFICATIONS.find((x) => x.value === c)?.label ?? c;
const classTone = (c: Incident['classification']) => (c === 'compromise_confirmed' || c === 'unauthorized_access_verified' ? 'critical' : c === 'policy_violation' ? 'warning' : 'neutral');

export function IncidentsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const status = params.get('status') ?? 'open';
  const page = Number(params.get('page') ?? 1);
  const [creating, setCreating] = React.useState(false);
  const q = useQuery({
    queryKey: ['security', 'incidents', status, page],
    queryFn: () => list<Incident>(`/api/security/incidents${qs({ status: status === 'open' ? 'new,investigating' : status === 'all' ? undefined : status, page })}`),
  });
  return (
    <>
      <PageHeader
        title="Incidents"
        subtitle="Investigations: who's on it, what's known, and how it ended."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            <Plus /> New incident
          </Button>
        }
      />
      <Card
        action={
          <Segmented
            label="Incident status"
            value={status}
            onChange={(v) => setParams({ status: v }, { replace: true })}
            options={[
              { value: 'open', label: 'Open' },
              { value: 'resolved', label: 'Resolved' },
              { value: 'false_positive', label: 'False positive' },
              { value: 'all', label: 'All' },
            ]}
          />
        }
        title="Cases"
      >
        {q.isPending ? (
          <Spinner />
        ) : q.data?.data.length ? (
          <>
            <Table head={['Reference', 'Title', 'Severity', 'Status', 'Classification', 'Owner', 'Alerts', 'Opened']}>
              {q.data.data.map((i) => (
                <tr key={i.id} className={rowLink} onClick={() => navigate(`/incidents/${i.id}`)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && navigate(`/incidents/${i.id}`)}>
                  <td className={`${td} font-mono text-[12.5px]`}>{i.reference}</td>
                  <td className={td}>{i.title}</td>
                  <td className={td}>
                    <SeverityBadge severity={i.severity} />
                  </td>
                  <td className={td}>
                    <StatusBadge status={i.status} />
                  </td>
                  <td className={td}>
                    <Pill tone={classTone(i.classification)}>{classLabel(i.classification)}</Pill>
                  </td>
                  <td className={`${td} text-ink-2`}>{i.owner?.displayName ?? '—'}</td>
                  <td className={`${td} tabular`}>{i.alertCount}</td>
                  <td className={`${td} whitespace-nowrap text-[12px] text-ink-2`}>{ago(i.openedAt)}</td>
                </tr>
              ))}
            </Table>
            <Pagination page={q.data.meta.page} totalPages={q.data.meta.totalPages} total={q.data.meta.total} onPage={(p) => setParams({ status, page: String(p) }, { replace: true })} />
          </>
        ) : (
          <Empty>No incidents here.</Empty>
        )}
      </Card>
      <NewIncidentDialog open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

export function IncidentPage() {
  const { id } = useParams();
  const admin = useAdmin();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['security', 'incident', id], queryFn: () => api<Incident>(`/api/security/incidents/${id}`) });
  const admins = useQuery({
    queryKey: ['admins'],
    queryFn: () => api<{ id: string; displayName: string; isActive: boolean }[]>('/api/admins'),
    enabled: admin.role === 'owner',
  });
  const [note, setNote] = React.useState('');
  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => patch<Incident>(`/api/security/incidents/${id}`, body),
    onSuccess: (inc) => {
      qc.setQueryData(['security', 'incident', id], inc);
      void qc.invalidateQueries({ queryKey: ['security'] });
      toast.success('Incident updated.');
    },
    onError: (e) => toast.error(errorText(e)),
  });
  const addNote = useMutation({
    mutationFn: () => post<Incident>(`/api/security/incidents/${id}/notes`, { body: note }),
    onSuccess: (inc) => {
      qc.setQueryData(['security', 'incident', id], inc);
      setNote('');
    },
    onError: (e) => toast.error(errorText(e)),
  });
  if (q.error) return <ErrorNote error={q.error} />;
  if (!q.data) return <Spinner />;
  const i = q.data;
  const owners = admin.role === 'owner' ? (admins.data ?? []).filter((a) => a.isActive) : [];

  return (
    <>
      <Link to="/incidents" className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="size-3.5" /> Incidents
      </Link>
      <PageHeader
        title={`${i.reference} · ${i.title}`}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={i.severity} /> <StatusBadge status={i.status} /> <Pill tone={classTone(i.classification)}>{classLabel(i.classification)}</Pill>
            <span>
              opened {dateTimeFull(i.openedAt)} by {i.createdBy}
            </span>
          </span>
        }
      />
      <div className="grid gap-3 xl:grid-cols-[2fr_1fr]">
        <div className="grid content-start gap-3">
          {i.summary && (
            <Card title="Summary">
              <p className="whitespace-pre-wrap text-[13.5px]">{i.summary}</p>
            </Card>
          )}
          <Card title="Notes" subtitle="Append-only: notes can't be edited or deleted">
            {i.notes?.length ? (
              <ol className="mb-3 grid gap-3">
                {i.notes.map((n) => (
                  <li key={n.id} className="rounded-[10px] border border-line bg-surface-2/60 px-3 py-2">
                    <div className="mb-1 text-[12px] text-muted">
                      {n.author.displayName} · {dateTimeFull(n.createdAt)}
                    </div>
                    <p className="whitespace-pre-wrap text-[13px]">{n.body}</p>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="mb-3 text-[12.5px] text-muted">No notes yet. Record what you checked and what you found.</p>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                addNote.mutate();
              }}
              className="grid gap-2"
            >
              <textarea aria-label="New note" className={`${inputCls} h-24 py-2`} value={note} onChange={(e) => setNote(e.target.value)} maxLength={5000} placeholder="Add a note" />
              <div>
                <Button type="submit" loading={addNote.isPending} disabled={!note.trim()}>
                  Add note
                </Button>
              </div>
            </form>
          </Card>
          <Card title="Linked alerts">
            {i.alerts?.length ? (
              <Table head={['Severity', 'Alert', 'Status', 'Occurrences', 'Last seen']}>
                {i.alerts.map((a) => (
                  <tr key={a.id}>
                    <td className={td}>
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className={td}>
                      <Link className="text-primary hover:underline" to={`/alerts/${a.id}`}>
                        {a.title}
                      </Link>{' '}
                      {a.simulated && <SimulatedBadge />}
                    </td>
                    <td className={td}>
                      <StatusBadge status={a.status} />
                    </td>
                    <td className={`${td} tabular`}>{a.occurrences}</td>
                    <td className={`${td} text-[12px] text-ink-2`}>{ago(a.lastSeenAt)}</td>
                  </tr>
                ))}
              </Table>
            ) : (
              <Empty>No alerts linked. Open one from an alert's page.</Empty>
            )}
          </Card>
        </div>
        <Card title="Case" className="content-start">
          <div className="grid gap-3">
            <Field label="Status">
              <select className={inputCls} value={i.status} onChange={(e) => update.mutate({ status: e.target.value })}>
                <option value="new">New</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False positive</option>
              </select>
            </Field>
            <Field label="Severity">
              <select className={inputCls} value={i.severity} onChange={(e) => update.mutate({ severity: e.target.value })}>
                {['low', 'medium', 'high', 'critical'].map((s) => (
                  <option key={s} value={s}>
                    {s[0]!.toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Classification" hint={CLASSIFICATIONS.find((c) => c.value === i.classification)?.help}>
              <select className={inputCls} value={i.classification} onChange={(e) => update.mutate({ classification: e.target.value })}>
                {CLASSIFICATIONS.map((c) => (
                  <option key={c.value} value={c.value} disabled={c.ownerOnly && admin.role !== 'owner'}>
                    {c.label}
                    {c.ownerOnly && admin.role !== 'owner' ? ' (owners only)' : ''}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Owner">
              {admin.role === 'owner' ? (
                <select className={inputCls} value={i.owner?.id ?? ''} onChange={(e) => update.mutate({ ownerId: e.target.value || null })}>
                  <option value="">Nobody</option>
                  {owners.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.displayName}
                    </option>
                  ))}
                </select>
              ) : (
                <div className="flex items-center gap-2 text-[13px]">
                  {i.owner?.displayName ?? 'Nobody'}
                  {i.owner?.id !== admin.id && (
                    <Button size="sm" onClick={() => update.mutate({ ownerId: admin.id })}>
                      Take it
                    </Button>
                  )}
                </div>
              )}
            </Field>
            {i.resolvedAt && <p className="text-[12px] text-muted">Closed {dateTimeFull(i.resolvedAt)}</p>}
          </div>
        </Card>
      </div>
    </>
  );
}
