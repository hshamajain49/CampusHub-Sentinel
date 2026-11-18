// Security Events: the raw event log with filters. Details were redacted by Sentinel on arrival (no credentials).
import * as React from 'react';
import { Link, useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { Search } from 'lucide-react';
import { api, list, qs } from '@/lib/api';
import { dateTimeFull } from '@/lib/format';
import type { SecEvent, SecurityOverview } from '@/lib/types';
import { rangeParams, RangePicker, useRange } from '@/components/filters';
import { Button, Card, Empty, inputCls, Modal, Mono, PageHeader, Pagination, rowLink, Select, SeverityBadge, SimulatedBadge, Spinner, StatusBadge, Table, td } from '@/components/ui';

function EventDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const q = useQuery({ queryKey: ['security', 'event', id], queryFn: () => api<SecEvent>(`/api/security/events/${id}`), enabled: !!id });
  const e = q.data;
  return (
    <Modal open={!!id} onClose={onClose} title="Security event" wide>
      {!e ? (
        <Spinner />
      ) : (
        <div className="grid gap-4 text-[13px]">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={e.severity} />
            <Mono>{e.category}</Mono>
            {e.simulated && <SimulatedBadge />}
          </div>
          <p className="text-ink">{e.description}</p>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3">
            {[
              ['Event id', <Mono key="id">{e.id}</Mono>],
              ['Occurred', dateTimeFull(e.occurredAt)],
              ['Received', dateTimeFull(e.receivedAt)],
              ['Source IP', e.sourceIp ? <Link key="ip" className="font-mono text-primary hover:underline" to={`/ips/${e.sourceIp}`}>{e.sourceIp}</Link> : '—'],
              ['Account', e.userRef ? <Mono key="u">{e.userRef}</Mono> : '—'],
              ['Role', e.actorRole ?? '—'],
              ['Request', <Mono key="r">{[e.method, e.route ?? e.path].filter(Boolean).join(' ') || '—'}</Mono>],
              ['Status', e.statusCode ?? '—'],
            ].map(([k, v]) => (
              <div key={String(k)} className="min-w-0">
                <dt className="text-[11.5px] uppercase tracking-[0.4px] text-muted">{k}</dt>
                <dd className="truncate">{v}</dd>
              </div>
            ))}
          </dl>
          <div>
            <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-[0.4px] text-muted">Details</h3>
            <pre className="max-h-[220px] overflow-auto rounded-[10px] border border-line bg-surface-2 p-3 font-mono text-[12px] text-ink-2">{JSON.stringify(e.details ?? {}, null, 2)}</pre>
          </div>
          {!!e.alerts?.length && (
            <div>
              <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-[0.4px] text-muted">Part of alerts</h3>
              <ul className="grid gap-1">
                {e.alerts.map((a) => (
                  <li key={a.id} className="flex items-center gap-2">
                    <SeverityBadge severity={a.severity} /> <StatusBadge status={a.status} />
                    <Link to={`/alerts/${a.id}`} className="text-primary hover:underline">
                      {a.title}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

export function EventsPage() {
  const [range, setRange] = useRange('7d');
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? '';
  const set = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!('page' in patch)) next.delete('page');
    setParams(next, { replace: true });
  };
  const [ipDraft, setIpDraft] = React.useState(get('ip'));
  const [userDraft, setUserDraft] = React.useState(get('userRef'));
  const [routeDraft, setRouteDraft] = React.useState(get('route'));
  const filters = {
    severity: get('severity') || undefined,
    category: get('category') || undefined,
    ip: get('ip') || undefined,
    userRef: get('userRef') || undefined,
    route: get('route') || undefined,
    simulated: get('simulated') || undefined,
    page: Number(get('page') || 1),
  };
  const cats = useQuery({ queryKey: ['security', 'overview', range], queryFn: () => api<SecurityOverview>(`/api/security/overview${qs(rangeParams(range))}`) });
  const q = useQuery({
    queryKey: ['security', 'events', range, filters],
    queryFn: () => list<SecEvent>(`/api/security/events${qs({ ...rangeParams(range), ...filters, pageSize: 50 })}`),
  });

  return (
    <>
      <PageHeader title="Security Events" subtitle="Everything CampusHub reported, newest first." actions={<RangePicker value={range} onChange={setRange} />} />
      <Card>
        <form
          className="mb-3 flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            set({ ip: ipDraft.trim(), userRef: userDraft.trim(), route: routeDraft.trim() });
          }}
        >
          <Select
            label="Severity"
            value={get('severity')}
            onChange={(v) => set({ severity: v })}
            options={[
              { value: '', label: 'All severities' },
              { value: 'critical,high', label: 'High and critical' },
              { value: 'medium', label: 'Medium' },
              { value: 'low', label: 'Low' },
              { value: 'info', label: 'Info' },
            ]}
          />
          <Select
            label="Category"
            value={get('category')}
            onChange={(v) => set({ category: v })}
            options={[{ value: '', label: 'All categories' }, ...(cats.data?.topCategories ?? []).map((c) => ({ value: c.category, label: `${c.category} (${c.events})` }))]}
          />
          <Select
            label="Simulated"
            value={get('simulated')}
            onChange={(v) => set({ simulated: v })}
            options={[
              { value: '', label: 'Real and simulated' },
              { value: 'false', label: 'Real only' },
              { value: 'true', label: 'Simulated only' },
            ]}
          />
          <input aria-label="IP or CIDR" placeholder="IP or CIDR" className={`${inputCls} w-[160px] font-mono`} value={ipDraft} onChange={(e) => setIpDraft(e.target.value)} />
          <input aria-label="Account id" placeholder="Account id" className={`${inputCls} w-[150px]`} value={userDraft} onChange={(e) => setUserDraft(e.target.value)} />
          <input aria-label="Route starts with" placeholder="Route starts with" className={`${inputCls} w-[200px] font-mono`} value={routeDraft} onChange={(e) => setRouteDraft(e.target.value)} />
          <Button type="submit">
            <Search /> Filter
          </Button>
        </form>
        {q.isPending ? (
          <Spinner />
        ) : q.error ? (
          <Empty>{(q.error as Error).message}</Empty>
        ) : q.data?.data.length ? (
          <>
            <Table head={['Time', 'Severity', 'Event', 'Source', 'Request']}>
              {q.data.data.map((e) => (
                <tr key={e.id} className={rowLink} onClick={() => set({ event: e.id, page: get('page') })} tabIndex={0} onKeyDown={(k) => k.key === 'Enter' && set({ event: e.id, page: get('page') })}>
                  <td className={`${td} whitespace-nowrap text-[12px] text-ink-2`}>{dateTimeFull(e.occurredAt)}</td>
                  <td className={td}>
                    <SeverityBadge severity={e.severity} />
                  </td>
                  <td className={td}>
                    <div className="flex items-center gap-1.5">
                      <Mono>{e.category}</Mono>
                      {e.simulated && <SimulatedBadge />}
                    </div>
                    <div className="line-clamp-1 text-[12px] text-muted">{e.description}</div>
                  </td>
                  <td className={td}>
                    <Mono>{e.sourceIp ?? '—'}</Mono>
                    {e.userRef && <div className="text-[12px] text-muted">{e.userRef}</div>}
                  </td>
                  <td className={`${td} font-mono text-[12px]`}>
                    {e.method} {e.route ?? e.path} {e.statusCode ? `→ ${e.statusCode}` : ''}
                  </td>
                </tr>
              ))}
            </Table>
            <Pagination page={q.data.meta.page} totalPages={q.data.meta.totalPages} total={q.data.meta.total} onPage={(p) => set({ page: String(p) })} />
          </>
        ) : (
          <Empty>No events match.</Empty>
        )}
      </Card>
      <EventDialog id={params.get('event')} onClose={() => set({ event: '', page: get('page') })} />
    </>
  );
}
