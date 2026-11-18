// Security Threats: the state of detection (counts by severity, open alerts, incidents, suspicious IPs), the
// timeline, the most targeted endpoints, and the alert queue with triage.
import * as React from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Siren } from 'lucide-react';
import { toast } from 'sonner';
import { api, errorText, list, patch, post, qs } from '@/lib/api';
import { ago, dateTimeFull, num } from '@/lib/format';
import type { Alert, SecurityOverview, Severity } from '@/lib/types';
import { BarList, SeverityTimeline } from '@/components/charts';
import { rangeParams, RangePicker, useRange } from '@/components/filters';
import {
  Button,
  Card,
  Empty,
  ErrorNote,
  Field,
  inputCls,
  Modal,
  Mono,
  PageHeader,
  Pagination,
  rowLink,
  Segmented,
  SeverityBadge,
  SeverityDot,
  SimulatedBadge,
  Spinner,
  Stat,
  StatusBadge,
  Table,
  td,
} from '@/components/ui';

export function ThreatsPage() {
  const navigate = useNavigate();
  const [range, setRange] = useRange('7d');
  const [params, setParams] = useSearchParams();
  const status = params.get('status') ?? 'active';
  const page = Number(params.get('page') ?? 1);
  const o = useQuery({ queryKey: ['security', 'overview', range], queryFn: () => api<SecurityOverview>(`/api/security/overview${qs(rangeParams(range))}`) });
  const t = useQuery({ queryKey: ['security', 'timeseries', range], queryFn: () => api<{ granularity: 'hour' | 'day'; points: any[] }>(`/api/security/timeseries${qs(rangeParams(range))}`) });
  const statusParam = { active: 'open,acknowledged', resolved: 'resolved', false_positive: 'false_positive', all: undefined }[status];
  const alerts = useQuery({ queryKey: ['security', 'alerts', status, page], queryFn: () => list<Alert>(`/api/security/alerts${qs({ status: statusParam, page, pageSize: 20 })}`) });
  const setQ = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    next.set(k, v);
    if (k !== 'page') next.delete('page');
    setParams(next, { replace: true });
  };

  if (o.error) return <ErrorNote error={o.error} />;
  const d = o.data;
  return (
    <>
      <PageHeader title="Security Threats" subtitle="What detection found, and what still needs a look." actions={<RangePicker value={range} onChange={setRange} />} />
      {!d ? (
        <Spinner />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
            <Stat label="Security events" value={num(d.events.total)} sub={d.events.simulated ? `${num(d.events.simulated)} simulated` : 'in range'} />
            <Stat label="Critical" value={num(d.events.bySeverity.critical)} tone={d.events.bySeverity.critical ? 'critical' : undefined} sub="events" />
            <Stat label="High" value={num(d.events.bySeverity.high)} tone={d.events.bySeverity.high ? 'critical' : undefined} sub="events" />
            <Stat label="Medium" value={num(d.events.bySeverity.medium)} tone={d.events.bySeverity.medium ? 'warning' : undefined} sub="events" />
            <Stat label="Low / info" value={num(d.events.bySeverity.low + d.events.bySeverity.info)} sub="events" />
            <Stat label="Active alerts" value={num(d.alerts.active)} tone={d.alerts.openBySeverity.critical ? 'critical' : d.alerts.active ? 'warning' : undefined} sub={`${num(d.alerts.openedInRange)} opened in range`} />
            <Stat label="Resolved incidents" value={num(d.incidents.resolved)} sub={`${num(d.incidents.open)} open`} />
            <Stat label="Suspicious IPs" value={num(d.suspiciousIps)} sub={`${num(d.activeBlocks)} blocked now`} />
          </div>
          {d.incidents.confirmed > 0 && (
            <div className="mt-3 rounded-[12px] border border-critical/50 bg-critical/10 px-4 py-3 text-[13px] text-critical-text" role="alert">
              {d.incidents.confirmed} incident{d.incidents.confirmed === 1 ? ' is' : 's are'} classified as verified unauthorised access or a confirmed compromise.{' '}
              <Link to="/incidents" className="font-semibold underline">
                Review incidents
              </Link>
            </div>
          )}
          <div className="mt-3 grid gap-3 xl:grid-cols-[2fr_1fr]">
            <Card title="Security events over time" subtitle={t.data ? `Per ${t.data.granularity}` : undefined}>
              {t.data ? <SeverityTimeline points={t.data.points} granularity={t.data.granularity} /> : <Spinner />}
            </Card>
            <Card title="Most targeted endpoints" subtitle="Events above info, with distinct IPs">
              <BarList
                valueLabel="events"
                onSelect={(k) => navigate(`/events${qs({ ...rangeParams(range), route: k })}`)}
                rows={d.topEndpoints.map((e) => ({
                  key: e.endpoint,
                  label: (
                    <span className="inline-flex items-center gap-1.5">
                      <SeverityDot severity={e.worstSeverity} />
                      <span className="font-mono text-[12px]">{e.endpoint}</span>
                    </span>
                  ),
                  sub: `${e.ips} IP${e.ips === 1 ? '' : 's'}`,
                  value: e.events,
                  title: `${e.endpoint}: ${e.events} events from ${e.ips} IPs; worst severity ${e.worstSeverity}`,
                }))}
              />
            </Card>
          </div>
        </>
      )}

      <Card
        className="mt-3"
        title="Alerts"
        action={
          <Segmented
            label="Alert status"
            value={status}
            onChange={(v) => setQ('status', v)}
            options={[
              { value: 'active', label: 'Active' },
              { value: 'resolved', label: 'Resolved' },
              { value: 'false_positive', label: 'False positive' },
              { value: 'all', label: 'All' },
            ]}
          />
        }
      >
        {alerts.isPending ? (
          <Spinner />
        ) : alerts.data?.data.length ? (
          <>
            <Table head={['Severity', 'Alert', 'Status', 'Occurrences', 'First seen', 'Last seen']}>
              {alerts.data.data.map((a) => (
                <tr key={a.id} className={rowLink} onClick={() => navigate(`/alerts/${a.id}`)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && navigate(`/alerts/${a.id}`)}>
                  <td className={td}>
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className={td}>
                    <div className="flex flex-wrap items-center gap-1.5 text-ink">
                      {a.title} {a.simulated && <SimulatedBadge />}
                    </div>
                    <div className="mt-0.5 line-clamp-1 text-[12px] text-muted">{a.detectionReason}</div>
                  </td>
                  <td className={td}>
                    <StatusBadge status={a.status} />
                    {a.incident && <div className="mt-1 text-[11.5px] text-muted">{a.incident.reference}</div>}
                  </td>
                  <td className={`${td} tabular`}>{num(a.occurrences)}</td>
                  <td className={`${td} whitespace-nowrap text-[12px] text-ink-2`}>{ago(a.firstSeenAt)}</td>
                  <td className={`${td} whitespace-nowrap text-[12px] text-ink-2`}>{ago(a.lastSeenAt)}</td>
                </tr>
              ))}
            </Table>
            <Pagination page={alerts.data.meta.page} totalPages={alerts.data.meta.totalPages} total={alerts.data.meta.total} onPage={(p) => setQ('page', String(p))} />
          </>
        ) : (
          <Empty>{status === 'active' ? 'No active alerts.' : 'Nothing here.'}</Empty>
        )}
      </Card>
    </>
  );
}

const CLASSIFICATION_TEXT = {
  suspicious: 'Suspicious activity: a detection rule matched. Not proof of an attack succeeding.',
  policy_violation: 'Security policy violation: the activity broke a rule of how CampusHub may be used.',
};

export function AlertPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['security', 'alert', id], queryFn: () => api<Alert>(`/api/security/alerts/${id}`) });
  const [note, setNote] = React.useState('');
  const [incidentOpen, setIncidentOpen] = React.useState(false);
  const setStatus = useMutation({
    mutationFn: (status: Alert['status']) => patch<Alert>(`/api/security/alerts/${id}`, { status, ...(note.trim() ? { note: note.trim() } : {}) }),
    onSuccess: (a) => {
      qc.setQueryData(['security', 'alert', id], a);
      void qc.invalidateQueries({ queryKey: ['security'] });
      void qc.invalidateQueries({ queryKey: ['health'] });
      setNote('');
      toast.success(`Alert marked ${a.status.replace('_', ' ')}.`);
    },
    onError: (e) => toast.error(errorText(e)),
  });
  if (q.error) return <ErrorNote error={q.error} />;
  if (!q.data) return <Spinner />;
  const a = q.data;
  const closed = a.status === 'resolved' || a.status === 'false_positive';
  return (
    <>
      <Link to="/threats" className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="size-3.5" /> Security Threats
      </Link>
      <PageHeader
        title={a.title}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={a.severity} /> <StatusBadge status={a.status} /> {a.simulated && <SimulatedBadge />}
            <span>Rule: {a.rule.name ?? a.rule.key}</span>
          </span>
        }
      />
      <div className="grid gap-3 xl:grid-cols-[2fr_1fr]">
        <div className="grid gap-3">
          <Card title="Why this alert">
            <p className="text-[13.5px] text-ink">{a.detectionReason}</p>
            <p className="mt-2 text-[12.5px] text-muted">{CLASSIFICATION_TEXT[a.classification]}</p>
            <dl className="mt-3 grid grid-cols-2 gap-3 text-[13px] sm:grid-cols-4">
              <div>
                <dt className="text-[11.5px] uppercase text-muted">Group</dt>
                <dd>
                  <Mono>{a.groupKey}</Mono>
                </dd>
              </div>
              <div>
                <dt className="text-[11.5px] uppercase text-muted">Occurrences</dt>
                <dd className="tabular">{num(a.occurrences)}</dd>
              </div>
              <div>
                <dt className="text-[11.5px] uppercase text-muted">First seen</dt>
                <dd>{dateTimeFull(a.firstSeenAt)}</dd>
              </div>
              <div>
                <dt className="text-[11.5px] uppercase text-muted">Last seen</dt>
                <dd>{dateTimeFull(a.lastSeenAt)}</dd>
              </div>
            </dl>
          </Card>
          <Card title="Evidence" subtitle="Up to 50 of the events behind this alert">
            {a.sampleEvents?.length ? (
              <Table head={['Time', 'Event', 'Source', 'Request']}>
                {a.sampleEvents.map((e) => (
                  <tr key={e.id} className={rowLink} onClick={() => navigate(`/events?event=${e.id}`)}>
                    <td className={`${td} whitespace-nowrap text-[12px]`}>{dateTimeFull(e.occurredAt)}</td>
                    <td className={td}>
                      <div className="flex items-center gap-1.5">
                        <SeverityDot severity={e.severity as Severity} />
                        <Mono>{e.category}</Mono>
                      </div>
                      <div className="text-[12px] text-muted">{e.description}</div>
                    </td>
                    <td className={td}>
                      {e.sourceIp ? (
                        <Link to={`/ips/${e.sourceIp}`} onClick={(ev) => ev.stopPropagation()} className="font-mono text-[12.5px] text-primary hover:underline">
                          {e.sourceIp}
                        </Link>
                      ) : (
                        '—'
                      )}
                      {e.userRef && <div className="text-[12px] text-muted">user {e.userRef}</div>}
                    </td>
                    <td className={`${td} font-mono text-[12px]`}>
                      {e.method} {e.route} {e.statusCode ? `→ ${e.statusCode}` : ''}
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              <Empty>No sample events (rules on traffic counters have none).</Empty>
            )}
          </Card>
        </div>
        <div className="grid content-start gap-3">
          <Card title="Triage">
            <Field label="Note (optional, saved in the audit log)">
              <textarea className={`${inputCls} h-20 py-2`} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} placeholder="What you checked, what you found" />
            </Field>
            <div className="mt-3 flex flex-wrap gap-2">
              {!closed && a.status !== 'acknowledged' && (
                <Button onClick={() => setStatus.mutate('acknowledged')} loading={setStatus.isPending}>
                  Investigating
                </Button>
              )}
              {!closed && (
                <>
                  <Button variant="primary" onClick={() => setStatus.mutate('resolved')} loading={setStatus.isPending}>
                    Resolve
                  </Button>
                  <Button onClick={() => setStatus.mutate('false_positive')} loading={setStatus.isPending} title="Quietens this rule for this group for its cooldown">
                    False positive
                  </Button>
                </>
              )}
              {closed && (
                <Button onClick={() => setStatus.mutate('open')} loading={setStatus.isPending}>
                  Reopen
                </Button>
              )}
            </div>
            {a.resolvedBy && (
              <p className="mt-3 text-[12px] text-muted">
                Closed by {a.resolvedBy} · {dateTimeFull(a.resolvedAt)}
              </p>
            )}
            {a.lastNotifiedAt && <p className="mt-1 text-[12px] text-muted">Emailed {ago(a.lastNotifiedAt)}</p>}
          </Card>
          <Card title="Incident">
            {a.incident ? (
              <Link to={`/incidents/${a.incident.id}`} className="font-semibold text-primary hover:underline">
                {a.incident.reference}
              </Link>
            ) : (
              <>
                <p className="mb-3 text-[12.5px] text-muted">Open an incident to investigate this with notes, an owner and a classification.</p>
                <Button onClick={() => setIncidentOpen(true)}>
                  <Siren /> Open incident
                </Button>
              </>
            )}
          </Card>
        </div>
      </div>
      <NewIncidentDialog open={incidentOpen} onClose={() => setIncidentOpen(false)} alert={a} />
    </>
  );
}

export function NewIncidentDialog({ open, onClose, alert }: { open: boolean; onClose: () => void; alert?: Alert }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [title, setTitle] = React.useState(alert?.title ?? '');
  const [severity, setSeverity] = React.useState<string>(alert?.severity ?? 'medium');
  const [summary, setSummary] = React.useState('');
  React.useEffect(() => {
    if (open) {
      setTitle(alert?.title ?? '');
      setSeverity(alert?.severity ?? 'medium');
      setSummary('');
    }
  }, [open, alert]);
  const create = useMutation({
    mutationFn: () => post<{ id: string; reference: string }>('/api/security/incidents', { title, severity, summary: summary || undefined, alertIds: alert ? [alert.id] : [] }),
    onSuccess: (inc) => {
      void qc.invalidateQueries({ queryKey: ['security'] });
      toast.success(`${inc.reference} opened.`);
      onClose();
      navigate(`/incidents/${inc.id}`);
    },
    onError: (e) => toast.error(errorText(e)),
  });
  return (
    <Modal open={open} onClose={onClose} title="Open an incident">
      <form
        className="grid gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
      >
        <Field label="Title">
          <input className={inputCls} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} required />
        </Field>
        <Field label="Severity">
          <select className={inputCls} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {['low', 'medium', 'high', 'critical'].map((s) => (
              <option key={s} value={s}>
                {s[0]!.toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Summary (optional)">
          <textarea className={`${inputCls} h-24 py-2`} value={summary} onChange={(e) => setSummary(e.target.value)} maxLength={5000} />
        </Field>
        <p className="text-[12px] text-muted">It starts as "suspicious". Only an owner can classify it as verified unauthorised access or a confirmed compromise.</p>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={title.trim().length < 3}>
            Open incident
          </Button>
        </div>
      </form>
    </Modal>
  );
}
