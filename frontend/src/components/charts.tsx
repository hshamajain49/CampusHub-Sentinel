// Charts (dataviz method): one series per time chart (never two y-axes), thin marks, recessive grid, hover tooltip on
// every plot, a table view for the time charts, legends for multi-series, text in text colours (never series colours).
import * as React from 'react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { bucketLabel, num, short } from '@/lib/format';
import { cn } from './ui';

const AXIS = { stroke: 'var(--axis)', tick: { fill: 'var(--muted)', fontSize: 11 }, tickLine: false };

function TooltipBox({ title, rows }: { title: string; rows: { label: string; value: string; color?: string }[] }) {
  return (
    <div className="rounded-[8px] border border-line-strong bg-surface-3 px-3 py-2 text-[12px] shadow-lg">
      <div className="mb-1 font-semibold text-ink">{title}</div>
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-2 text-ink-2">
          {r.color && <span aria-hidden className="inline-block size-2 rounded-full" style={{ background: r.color }} />}
          <span>{r.label}</span>
          <span className="tabular ml-auto pl-4 font-semibold text-ink">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

function TableView({ head, rows }: { head: string[]; rows: (string | number)[][] }) {
  return (
    <details className="mt-2 text-[12px] text-muted">
      <summary className="cursor-pointer select-none hover:text-ink">Show as table</summary>
      <div className="mt-2 max-h-[240px] overflow-auto rounded-[8px] border border-line">
        <table className="w-full text-left">
          <thead className="sticky top-0 bg-surface-2">
            <tr>
              {head.map((h) => (
                <th key={h} className="px-2 py-1 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-t border-line/60 text-ink-2">
                {r.map((c, j) => (
                  <td key={j} className="tabular px-2 py-1">
                    {typeof c === 'number' ? num(c) : c}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

/** One measure over time: a 2 px line over a 10 % wash. */
export function TimeSeriesChart<P extends { bucket: string }>({
  points,
  granularity,
  dataKey,
  label,
  height = 220,
}: {
  points: P[];
  granularity: 'hour' | 'day';
  dataKey: keyof P & string;
  label: string;
  height?: number;
}) {
  const data = points.map((p) => ({ ...p, x: bucketLabel(p.bucket, granularity) }));
  return (
    <div>
      <div style={{ height }} role="img" aria-label={`${label} over time`}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="x" {...AXIS} minTickGap={24} />
            <YAxis {...AXIS} axisLine={false} allowDecimals={false} tickFormatter={short} width={48} />
            <Tooltip
              cursor={{ stroke: 'var(--axis)' }}
              content={({ active, payload }) =>
                active && payload?.[0] ? (
                  <TooltipBox title={String(payload[0].payload.bucket).replace('T', ' ')} rows={[{ label, value: num(Number(payload[0].value)), color: 'var(--series-1)' }]} />
                ) : null
              }
            />
            <Area
              type="monotone"
              dataKey={dataKey as string}
              stroke="var(--series-1)"
              strokeWidth={2}
              fill="var(--series-1)"
              fillOpacity={0.1}
              dot={false}
              activeDot={{ r: 4, stroke: 'var(--surface)', strokeWidth: 2 }}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <TableView head={['Time', label]} rows={points.map((p) => [String(p.bucket).replace('T', ' '), Number(p[dataKey])])} />
    </div>
  );
}

/** Columns (e.g. hour of day): ≤ 24 px, 4 px rounded tops, value in the tooltip. */
export function ColumnChart({ data, label, height = 200 }: { data: { x: string; value: number }[]; label: string; height?: number }) {
  return (
    <div style={{ height }} role="img" aria-label={label}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis dataKey="x" {...AXIS} interval={2} />
          <YAxis {...AXIS} axisLine={false} allowDecimals={false} tickFormatter={short} width={48} />
          <Tooltip
            cursor={{ fill: 'rgba(255,255,255,0.04)' }}
            content={({ active, payload }) =>
              active && payload?.[0] ? <TooltipBox title={String(payload[0].payload.x)} rows={[{ label, value: num(Number(payload[0].value)), color: 'var(--series-1)' }]} /> : null
            }
          />
          <Bar dataKey="value" fill="var(--series-1)" maxBarSize={24} radius={[4, 4, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

const SEV_SERIES = [
  { key: 'low', label: 'Low / info', color: 'var(--sev-low)' },
  { key: 'medium', label: 'Medium', color: 'var(--sev-medium)' },
  { key: 'high', label: 'High / critical', color: 'var(--sev-high)' },
] as const;

/** Security events per bucket, stacked by severity (validated trio, 2 px surface gaps, legend always shown). */
export function SeverityTimeline({ points, granularity, height = 220 }: { points: { bucket: string; low: number; medium: number; high: number; alerts: number }[]; granularity: 'hour' | 'day'; height?: number }) {
  const data = points.map((p) => ({ ...p, x: bucketLabel(p.bucket, granularity) }));
  return (
    <div>
      <Legend items={SEV_SERIES.map((s) => ({ label: s.label, color: s.color }))} />
      <div style={{ height }} role="img" aria-label="Security events over time by severity">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="x" {...AXIS} minTickGap={20} />
            <YAxis {...AXIS} axisLine={false} allowDecimals={false} tickFormatter={short} width={48} />
            <Tooltip
              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const p = payload[0]!.payload;
                return (
                  <TooltipBox
                    title={String(p.bucket).replace('T', ' ')}
                    rows={[
                      ...[...SEV_SERIES].reverse().map((s) => ({ label: s.label, value: num(p[s.key]), color: s.color })),
                      { label: 'Alerts opened', value: num(p.alerts) },
                    ]}
                  />
                );
              }}
            />
            {SEV_SERIES.map((s, i) => (
              <Bar
                key={s.key}
                dataKey={s.key}
                stackId="sev"
                fill={s.color}
                stroke="var(--surface)"
                strokeWidth={2}
                maxBarSize={24}
                radius={i === SEV_SERIES.length - 1 ? [4, 4, 0, 0] : 0}
                isAnimationActive={false}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <TableView
        head={['Time', 'Low / info', 'Medium', 'High / critical', 'Alerts opened']}
        rows={points.map((p) => [p.bucket.replace('T', ' '), p.low, p.medium, p.high, p.alerts])}
      />
    </div>
  );
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <ul className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-ink-2">
      {items.map((i) => (
        <li key={i.label} className="inline-flex items-center gap-1.5">
          <span aria-hidden className="inline-block h-2.5 w-2.5 rounded-[3px]" style={{ background: i.color }} />
          {i.label}
        </li>
      ))}
    </ul>
  );
}

/**
 * Ranked horizontal bars as plain HTML: the label and value are text (readable, selectable, translatable), the bar is
 * the only colour. Used for devices, browsers, countries, pages, sources, endpoints.
 */
export function BarList({
  rows,
  empty = 'No data in this range.',
  valueLabel,
  onSelect,
}: {
  rows: { key: string; label: React.ReactNode; value: number; sub?: React.ReactNode; title?: string }[];
  empty?: string;
  valueLabel: string;
  onSelect?: (key: string) => void;
}) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  const total = rows.reduce((n, r) => n + r.value, 0);
  if (!rows.length) return <p className="py-6 text-center text-[13px] text-muted">{empty}</p>;
  return (
    <ul className="grid gap-1.5" aria-label={valueLabel}>
      {rows.map((r) => (
        <li key={r.key}>
          <button
            type="button"
            disabled={!onSelect}
            onClick={() => onSelect?.(r.key)}
            title={r.title ?? `${typeof r.label === 'string' ? r.label : r.key}: ${num(r.value)} ${valueLabel} (${total ? ((r.value / total) * 100).toFixed(1) : 0}%)`}
            className={cn('group relative grid w-full grid-cols-[1fr_auto] items-center gap-3 rounded-[6px] px-2 py-1.5 text-left', onSelect && 'hover:bg-surface-2')}
          >
            <span aria-hidden className="absolute inset-y-1 left-0 rounded-r-[4px] bg-[var(--series-1)] opacity-25 group-hover:opacity-35" style={{ width: `${(r.value / max) * 100}%` }} />
            <span className="relative min-w-0 truncate text-[13px] text-ink">
              {r.label}
              {r.sub && <span className="ml-2 text-[12px] text-muted">{r.sub}</span>}
            </span>
            <span className="tabular relative text-[13px] font-semibold text-ink">{num(r.value)}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

/** A part-to-whole bar for two or three parts, legend with values underneath (e.g. new vs returning). */
export function SplitBar({ parts }: { parts: { label: string; value: number; color: string }[] }) {
  const total = parts.reduce((n, p) => n + p.value, 0);
  return (
    <div>
      <div className="flex h-3 w-full gap-[2px] overflow-hidden rounded-[4px] bg-surface-3" role="img" aria-label={parts.map((p) => `${p.label} ${p.value}`).join(', ')}>
        {total > 0 &&
          parts.map((p) =>
            p.value > 0 ? <span key={p.label} title={`${p.label}: ${num(p.value)}`} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} /> : null,
          )}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-[12.5px] text-ink-2">
        {parts.map((p) => (
          <li key={p.label} className="inline-flex items-center gap-1.5">
            <span aria-hidden className="inline-block size-2.5 rounded-[3px]" style={{ background: p.color }} />
            {p.label}
            <span className="tabular font-semibold text-ink">{num(p.value)}</span>
            <span className="tabular text-muted">{total ? `${((p.value / total) * 100).toFixed(0)}%` : '—'}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
