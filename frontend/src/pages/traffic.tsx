// Traffic Analytics: visitors over time, hour of day, and where visits come from (device, browser, OS, place,
// pages, sources). Each time chart shows one measure; switch the measure rather than stacking axes.
import * as React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import { countryName, duration, flag, num, pct, titleCase } from '@/lib/format';
import type { BreakdownRow, Overview, TimePoint } from '@/lib/types';
import { BarList, ColumnChart, SplitBar, TimeSeriesChart } from '@/components/charts';
import { rangeParams, RangePicker, useRange, type RangeState } from '@/components/filters';
import { Card, ErrorNote, PageHeader, Segmented, Spinner, Stat } from '@/components/ui';

function useBreakdown(range: RangeState, dimension: string, limit = 10) {
  return useQuery({
    queryKey: ['analytics', 'breakdown', dimension, range, limit],
    queryFn: () => api<{ rows: BreakdownRow[] }>(`/api/analytics/breakdown${qs({ ...rangeParams(range), dimension, limit })}`),
  });
}

function Breakdown({ title, range, dimension, label, value = 'sessions', limit }: { title: string; range: RangeState; dimension: string; label: (k: string) => string; value?: 'sessions' | 'pageViews'; limit?: number }) {
  const q = useBreakdown(range, dimension, limit);
  return (
    <Card title={title} subtitle={value === 'pageViews' ? 'Page views' : 'Sessions'}>
      {q.data ? <BarList valueLabel={value === 'pageViews' ? 'page views' : 'sessions'} rows={q.data.rows.map((r) => ({ key: r.key, label: label(r.key), value: (value === 'pageViews' ? r.pageViews : r.sessions) ?? 0 }))} /> : <Spinner />}
    </Card>
  );
}

const pathLabel = (k: string) => k;
const country = (k: string) => `${flag(k)} ${countryName(k)}`.trim();

export function TrafficPage() {
  const [range, setRange] = useRange('7d');
  const [metric, setMetric] = React.useState<'visitors' | 'sessions' | 'pageViews'>('visitors');
  const p = rangeParams(range);
  const o = useQuery({ queryKey: ['analytics', 'overview', range], queryFn: () => api<Overview>(`/api/analytics/overview${qs(p)}`) });
  const ts = useQuery({ queryKey: ['analytics', 'timeseries', range], queryFn: () => api<{ granularity: 'hour' | 'day'; points: TimePoint[] }>(`/api/analytics/timeseries${qs(p)}`) });
  const hours = useQuery({ queryKey: ['analytics', 'hours', range], queryFn: () => api<{ hours: { hour: number; sessions: number }[]; timezone: string }>(`/api/analytics/hours${qs(p)}`) });
  const metricLabel = { visitors: 'Visitors', sessions: 'Sessions', pageViews: 'Page views' }[metric];

  if (o.error) return <ErrorNote error={o.error} />;
  return (
    <>
      <PageHeader title="Traffic Analytics" subtitle="Visitors, visits and where they come from." actions={<RangePicker value={range} onChange={setRange} />} />
      {!o.data ? (
        <Spinner />
      ) : (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
          <Stat label="Unique visitors" value={num(o.data.visitors)} />
          <Stat label="New visitors" value={num(o.data.newVisitors)} />
          <Stat label="Returning" value={num(o.data.returningVisitors)} />
          <Stat label="Sessions" value={num(o.data.sessions)} />
          <Stat label="Page views" value={num(o.data.pageViews)} sub={o.data.sessions ? `${(o.data.pageViews / o.data.sessions).toFixed(1)} per session` : undefined} />
          <Stat label="Avg. session" value={duration(o.data.avgSessionSeconds)} />
          <Stat label="Bounce rate" value={pct(o.data.bounceRate)} sub="one page only" />
        </div>
      )}

      {o.data && (
        <div className="mt-3 grid grid-cols-3 gap-3">
          <Stat label="Visitors today" value={num(o.data.visitorsToday)} />
          <Stat label="This week" value={num(o.data.visitorsThisWeek)} sub="last 7 days" />
          <Stat label="This month" value={num(o.data.visitorsThisMonth)} sub={`last 30 days · ${num(o.data.allTime.visitors)} all time`} />
        </div>
      )}

      <div className="mt-3 grid gap-3 xl:grid-cols-[2fr_1fr]">
        <Card
          title={`${metricLabel} over time`}
          subtitle={ts.data ? `Per ${ts.data.granularity} (report timezone)` : undefined}
          action={
            <Segmented
              label="Measure"
              value={metric}
              onChange={setMetric}
              options={[
                { value: 'visitors', label: 'Visitors' },
                { value: 'sessions', label: 'Sessions' },
                { value: 'pageViews', label: 'Page views' },
              ]}
            />
          }
        >
          {ts.data ? <TimeSeriesChart points={ts.data.points} granularity={ts.data.granularity} dataKey={metric} label={metricLabel} height={260} /> : <Spinner />}
        </Card>
        <div className="grid gap-3">
          <Card title="New vs returning visitors">
            {o.data && (
              <SplitBar
                parts={[
                  { label: 'New', value: o.data.newVisitors, color: 'var(--series-1)' },
                  { label: 'Returning', value: o.data.returningVisitors, color: 'var(--series-2)' },
                ]}
              />
            )}
          </Card>
          <Card title="Hour of day" subtitle={hours.data ? `Sessions started (${hours.data.timezone})` : undefined}>
            {hours.data ? <ColumnChart label="Sessions" data={hours.data.hours.map((h) => ({ x: String(h.hour).padStart(2, '0'), value: h.sessions }))} height={170} /> : <Spinner />}
          </Card>
        </div>
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <Breakdown title="Most visited pages" range={range} dimension="page" label={pathLabel} value="pageViews" limit={12} />
        <Breakdown title="Traffic sources" range={range} dimension="source" label={titleCase} />
        <Breakdown title="Referring sites" range={range} dimension="referrer" label={(k) => (k === 'unknown' ? 'None (direct)' : k)} />
        <Breakdown title="Countries" range={range} dimension="country" label={country} />
        <Breakdown title="Cities" range={range} dimension="city" label={(k) => (k === 'unknown' ? 'Unknown (country-level data only)' : k)} />
        <Breakdown title="Devices" range={range} dimension="device" label={titleCase} />
        <Breakdown title="Browsers" range={range} dimension="browser" label={(k) => (k === 'unknown' ? 'Unknown' : k)} />
        <Breakdown title="Operating systems" range={range} dimension="os" label={(k) => (k === 'unknown' ? 'Unknown' : k)} />
        <Breakdown
          title="Screen sizes"
          range={range}
          dimension="viewport"
          label={(k) => ({ xs: 'Phone (< 640 px)', sm: 'Large phone (640–767)', md: 'Tablet (768–1023)', lg: 'Laptop (1024–1279)', xl: 'Desktop (≥ 1280)' })[k] ?? 'Unknown'}
        />
        <Breakdown title="Entry pages" range={range} dimension="entry" label={pathLabel} />
      </div>
      <p className="mt-4 text-[12px] text-muted">
        Locations: IP geolocation by{' '}
        <a href="https://db-ip.com" className="underline" target="_blank" rel="noreferrer noopener">
          DB-IP
        </a>{' '}
        (CC BY 4.0), looked up on Sentinel's server; no visitor address is sent to anyone else.
      </p>
    </>
  );
}
