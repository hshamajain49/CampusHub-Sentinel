// Overview: today at a glance. Every number comes from the API; the health status is computed server-side.
import { Link, useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { Activity, AlertOctagon, Globe2, Monitor, Radar, ShieldAlert, Users } from 'lucide-react';
import { api, list } from '@/lib/api';
import { ago, countryName, flag, num, titleCase } from '@/lib/format';
import type { Alert, BreakdownRow, Overview, SecurityOverview, TimePoint, VisitSession } from '@/lib/types';
import { useLive } from '@/lib/live';
import { BarList, SeverityTimeline, TimeSeriesChart } from '@/components/charts';
import { Card, Empty, ErrorNote, HealthBadge, PageHeader, rowLink, SeverityBadge, SimulatedBadge, Spinner, Stat, StatusBadge } from '@/components/ui';

export function OverviewPage() {
  const navigate = useNavigate();
  const { summary } = useLive();
  const live = summary ? Object.values(summary.apps)[0] : undefined;
  const a = useQuery({ queryKey: ['analytics', 'overview', 'today'], queryFn: () => api<Overview>('/api/analytics/overview?range=today') });
  const s = useQuery({ queryKey: ['security', 'overview', 'today'], queryFn: () => api<SecurityOverview>('/api/security/overview?range=today') });
  const traffic = useQuery({
    queryKey: ['analytics', 'timeseries', 'today'],
    queryFn: () => api<{ granularity: 'hour' | 'day'; points: TimePoint[] }>('/api/analytics/timeseries?range=today'),
  });
  const timeline = useQuery({ queryKey: ['security', 'timeseries', 'today'], queryFn: () => api<{ granularity: 'hour' | 'day'; points: any[] }>('/api/security/timeseries?range=today') });
  const countries = useQuery({ queryKey: ['analytics', 'breakdown', 'country', '7d'], queryFn: () => api<{ rows: BreakdownRow[] }>('/api/analytics/breakdown?range=7d&dimension=country&limit=8') });
  const devices = useQuery({ queryKey: ['analytics', 'breakdown', 'device', '7d'], queryFn: () => api<{ rows: BreakdownRow[] }>('/api/analytics/breakdown?range=7d&dimension=device&limit=5') });
  const alerts = useQuery({ queryKey: ['security', 'alerts', 'open-top'], queryFn: () => list<Alert>('/api/security/alerts?status=open,acknowledged&pageSize=6') });
  const sessions = useQuery({ queryKey: ['analytics', 'sessions', 'latest'], queryFn: () => list<VisitSession>('/api/analytics/sessions?range=today&pageSize=6') });

  if (a.error || s.error) return <ErrorNote error={a.error ?? s.error} />;
  if (!a.data || !s.data) return <Spinner />;
  const critical = s.data.alerts.openBySeverity.critical;

  return (
    <>
      <PageHeader title="Overview" subtitle="Today on CampusHub: visitors and security, updated live." />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Visitors today" icon={<Users className="size-3.5" />} value={num(a.data.visitorsToday)} sub={`${num(a.data.pageViews)} page views`} />
        <Stat label="Online now" icon={<Activity className="size-3.5" />} value={num(live?.online ?? a.data.online)} sub={`${num(live?.pageViews5m ?? 0)} views in 5 min`} />
        <Stat label="API requests today" icon={<Radar className="size-3.5" />} value={num(s.data.requests)} sub={s.data.health.lastIngestAt ? `data ${ago(s.data.health.lastIngestAt)}` : 'no data received yet'} />
        <Stat label="Threats detected" icon={<ShieldAlert className="size-3.5" />} value={num(s.data.alerts.openedInRange)} sub={`${num(s.data.alerts.active)} alerts open`} tone={s.data.alerts.active ? 'warning' : undefined} />
        <Stat label="Critical alerts" icon={<AlertOctagon className="size-3.5" />} value={num(critical)} sub={`${num(s.data.alerts.openBySeverity.high)} high`} tone={critical ? 'critical' : undefined} />
        <div className="card min-w-0 p-4">
          <div className="text-[12px] font-medium text-muted">System health</div>
          <div className="mt-2 text-[20px] leading-8">
            <HealthBadge status={s.data.health.status} reasons={s.data.health.reasons} />
          </div>
          <div className="mt-0.5 line-clamp-2 text-[12px] text-muted">
            {s.data.health.reasons[0] ??
              (s.data.alerts.active > 0 ? 'Open alerts are all simulated test traffic, so they don’t count' : 'All monitored signals are normal')}
          </div>
        </div>
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <Card title="Page views today" subtitle="Per hour (report timezone)">
          {traffic.data ? <TimeSeriesChart points={traffic.data.points} granularity={traffic.data.granularity} dataKey="pageViews" label="Page views" /> : <Spinner />}
        </Card>
        <Card title="Security events today" subtitle="Per hour, by severity">
          {timeline.data ? <SeverityTimeline points={timeline.data.points} granularity={timeline.data.granularity} /> : <Spinner />}
        </Card>
      </div>

      <div className="mt-3 grid gap-3 lg:grid-cols-3">
        <Card title="Visitor geography" subtitle="Sessions by country, last 7 days" action={<Link to="/traffic" className="text-[12px] text-primary hover:underline">Traffic</Link>}>
          <BarList
            valueLabel="sessions"
            rows={(countries.data?.rows ?? []).map((r) => ({ key: r.key, label: `${flag(r.key)} ${countryName(r.key)}`.trim(), value: r.sessions }))}
          />
        </Card>
        <Card title="Devices" subtitle="Sessions, last 7 days">
          <BarList valueLabel="sessions" rows={(devices.data?.rows ?? []).map((r) => ({ key: r.key, label: titleCase(r.key), value: r.sessions }))} />
        </Card>
        <Card title="Recent threats" subtitle="Open alerts, most serious first" action={<Link to="/threats" className="text-[12px] text-primary hover:underline">All</Link>}>
          {alerts.data?.data.length ? (
            <ul className="-mx-2 grid">
              {alerts.data.data.map((al) => (
                <li key={al.id}>
                  <button className={`${rowLink} grid w-full gap-1 rounded-[8px] px-2 py-2 text-left`} onClick={() => navigate(`/alerts/${al.id}`)}>
                    <span className="flex items-center gap-2">
                      <SeverityBadge severity={al.severity} />
                      <StatusBadge status={al.status} />
                      {al.simulated && <SimulatedBadge />}
                      <span className="ml-auto text-[11.5px] text-muted">{ago(al.lastSeenAt)}</span>
                    </span>
                    <span className="truncate text-[13px] text-ink">{al.title}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty icon={<ShieldAlert className="size-5 text-good-text" />}>No open alerts.</Empty>
          )}
        </Card>
      </div>

      <Card className="mt-3" title="Latest visitor activity" action={<Link to="/visitors" className="text-[12px] text-primary hover:underline">Live visitors</Link>}>
        {sessions.data?.data.length ? (
          <ul className="grid gap-1">
            {sessions.data.data.map((v) => (
              <li key={v.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-[8px] px-1 py-1.5 text-[13px]">
                <span aria-hidden className={`size-2 rounded-full ${v.online ? 'live-dot bg-good' : 'bg-surface-3'}`} />
                <span className="w-[150px] truncate text-ink">{`${flag(v.location.country)} ${countryName(v.location.country)}`}</span>
                <span className="flex items-center gap-1 text-ink-2">
                  <Monitor className="size-3.5" aria-hidden /> {titleCase(v.device)} · {v.browser ?? 'Unknown'}
                </span>
                <span className="font-mono text-[12px] text-ink-2">{v.exitPath}</span>
                <span className="ml-auto text-[12px] text-muted">
                  {v.pageViews} page{v.pageViews === 1 ? '' : 's'} · {ago(v.lastActivityAt)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <Empty icon={<Globe2 className="size-5" />}>No visits today yet. Page views appear here once CampusHub's tracker is switched on.</Empty>
        )}
      </Card>
    </>
  );
}
