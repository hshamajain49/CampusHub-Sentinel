// Live Visitors: who is on CampusHub now, and every visit in the chosen range. IPs are shown as networks only (the
// API never stores or returns a full visitor address); nothing here identifies a person.
import * as React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, Users } from 'lucide-react';
import { api, list, qs } from '@/lib/api';
import { ago, countryName, dateTime, dateTimeFull, duration, flag, titleCase } from '@/lib/format';
import { useLive } from '@/lib/live';
import type { VisitSession } from '@/lib/types';
import { rangeParams, RangePicker, useRange } from '@/components/filters';
import { Card, Empty, Modal, Mono, PageHeader, Pagination, Pill, rowLink, SimulatedBadge, Spinner, Stat, Table, td } from '@/components/ui';

function location(v: VisitSession) {
  const l = v.location;
  const place = [l.city, l.region].filter(Boolean).join(', ');
  return `${flag(l.country)} ${place ? `${place}, ` : ''}${countryName(l.country)}`.trim();
}

function SessionRow({ v, onOpen }: { v: VisitSession; onOpen: () => void }) {
  return (
    <tr className={rowLink} onClick={onOpen} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && onOpen()}>
      <td className={td}>
        <div className="flex items-center gap-2">
          <span aria-hidden className={`size-2 rounded-full ${v.online ? 'live-dot bg-good' : 'bg-surface-3'}`} />
          <Mono>{v.visitor.id}</Mono>
          {v.visitor.isNew ? <Pill tone="primary">New</Pill> : <Pill>Returning</Pill>}
          {v.simulated && <SimulatedBadge />}
        </div>
      </td>
      <td className={td}>{location(v)}</td>
      <td className={td}>
        <div className="text-ink">{titleCase(v.device)}</div>
        <div className="text-[12px] text-muted">
          {v.browser ?? 'Unknown'} · {v.os ?? 'Unknown'}
          {v.viewport ? ` · ${v.viewport.toUpperCase()}` : ''}
        </div>
      </td>
      <td className={td}>
        <div className="font-mono text-[12px] text-ink">{v.entryPath}</div>
        {v.exitPath !== v.entryPath && <div className="font-mono text-[12px] text-muted">→ {v.exitPath}</div>}
      </td>
      <td className={`${td} tabular`}>{v.pageViews}</td>
      <td className={`${td} tabular`}>{duration(v.durationSeconds)}</td>
      <td className={td}>
        {v.referrer.host ?? titleCase(v.referrer.source)}
        {v.referrer.host && <div className="text-[12px] text-muted">{titleCase(v.referrer.source)}</div>}
      </td>
      <td className={`${td} whitespace-nowrap text-[12px] text-ink-2`}>{ago(v.lastActivityAt)}</td>
    </tr>
  );
}

const HEAD = ['Visitor', 'Location', 'Device', 'Pages (entry → exit)', 'Views', 'Duration', 'Source', 'Last activity'];

export function SessionDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const q = useQuery({ queryKey: ['analytics', 'session', id], queryFn: () => api<VisitSession>(`/api/analytics/sessions/${id}`), enabled: !!id });
  const v = q.data;
  return (
    <Modal open={!!id} onClose={onClose} title="Visit details" wide>
      {!v ? (
        <Spinner />
      ) : (
        <div className="grid gap-4 text-[13px]">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3">
            {[
              ['Visitor', <Mono key="v">{v.visitor.id}</Mono>],
              ['Visitor type', v.visitor.isNew ? 'New' : 'Returning'],
              ['First visit', dateTimeFull(v.visitor.firstSeenAt)],
              ['Session started', dateTimeFull(v.startedAt)],
              ['Last activity', dateTimeFull(v.lastActivityAt)],
              ['Duration', duration(v.durationSeconds)],
              ['Location', location(v)],
              ['Network', v.ip ? <Mono key="ip">{v.ip}</Mono> : '—'],
              ['Device', `${titleCase(v.device)} · ${v.viewport?.toUpperCase() ?? '—'}`],
              ['Browser', v.browser ?? 'Unknown'],
              ['Operating system', v.os ?? 'Unknown'],
              ['Source', v.referrer.host ? `${v.referrer.host} (${v.referrer.source})` : titleCase(v.referrer.source)],
              ...(v.utm ? [['Campaign', [v.utm.source, v.utm.medium, v.utm.campaign].filter(Boolean).join(' · ')]] : []),
              ...(v.userRef ? [['CampusHub account', <Mono key="u">{v.userRef}</Mono>]] : []),
            ].map(([k, val]) => (
              <div key={String(k)} className="min-w-0">
                <dt className="text-[11.5px] uppercase tracking-[0.4px] text-muted">{k}</dt>
                <dd className="truncate text-ink">{val}</dd>
              </div>
            ))}
          </dl>
          <div>
            <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-[0.4px] text-muted">Pages ({v.pages?.length ?? 0})</h3>
            <ol className="max-h-[260px] overflow-auto rounded-[10px] border border-line">
              {v.pages?.map((p, i) => (
                <li key={i} className="flex justify-between gap-3 border-b border-line/60 px-3 py-1.5 last:border-0">
                  <span className="font-mono text-[12.5px]">{p.path}</span>
                  <span className="tabular text-[12px] text-muted">{dateTime(p.at)}</span>
                </li>
              ))}
            </ol>
          </div>
          <p className="text-[12px] text-muted">
            Sentinel keeps the network (/24 or /48), not the full address, and no names or emails. Record ids in paths are shown as :id.
          </p>
        </div>
      )}
    </Modal>
  );
}

export function VisitorsPage() {
  const { summary } = useLive();
  const live = summary ? Object.values(summary.apps)[0] : undefined;
  const [range, setRange] = useRange('today');
  const [page, setPage] = React.useState(1);
  const [open, setOpen] = React.useState<string | null>(null);
  const online = useQuery({ queryKey: ['analytics', 'sessions', 'live'], queryFn: () => list<VisitSession>('/api/analytics/sessions?live=true&pageSize=50') });
  const all = useQuery({
    queryKey: ['analytics', 'sessions', range, page],
    queryFn: () => list<VisitSession>(`/api/analytics/sessions${qs({ ...rangeParams(range), page, pageSize: 25 })}`),
  });
  React.useEffect(() => setPage(1), [range.range, range.from, range.to]);

  return (
    <>
      <PageHeader title="Live Visitors" subtitle="Who is on CampusHub right now, and each visit in the range." />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Online now" icon={<Activity className="size-3.5" />} value={live?.online ?? online.data?.data.length ?? '—'} sub="active in the last 2 minutes" tone={live?.online ? 'good' : undefined} />
        <Stat label="Page views, last 5 min" value={live?.pageViews5m ?? '—'} sub={live?.lastPath ? `latest: ${live.lastPath}` : undefined} />
        <Stat label="Visits in range" icon={<Users className="size-3.5" />} value={all.data?.meta.total ?? '—'} />
        <Stat label="New visitors online" value={online.data?.data.filter((v) => v.visitor.isNew).length ?? '—'} sub="first visit in this session" />
      </div>

      <Card className="mt-3" title="Online now" subtitle="Updates live">
        {online.isPending ? (
          <Spinner />
        ) : online.data?.data.length ? (
          <Table head={HEAD}>
            {online.data.data.map((v) => (
              <SessionRow key={v.id} v={v} onOpen={() => setOpen(v.id)} />
            ))}
          </Table>
        ) : (
          <Empty>Nobody is on CampusHub right now.</Empty>
        )}
      </Card>

      <Card className="mt-3" title="All visits" action={<RangePicker value={range} onChange={setRange} />}>
        {all.isPending ? (
          <Spinner />
        ) : all.data?.data.length ? (
          <>
            <Table head={HEAD}>
              {all.data.data.map((v) => (
                <SessionRow key={v.id} v={v} onOpen={() => setOpen(v.id)} />
              ))}
            </Table>
            <Pagination page={all.data.meta.page} totalPages={all.data.meta.totalPages} total={all.data.meta.total} onPage={setPage} />
          </>
        ) : (
          <Empty>No visits in this range.</Empty>
        )}
      </Card>
      <SessionDialog id={open} onClose={() => setOpen(null)} />
    </>
  );
}
