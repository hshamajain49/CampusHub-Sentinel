// Date range filter (Today / 7 / 30 / 90 days / Custom), kept in the URL so a view can be shared and reloaded.
import { useSearchParams } from 'react-router';
import { inputCls, Segmented } from './ui';

export type RangeKey = 'today' | '7d' | '30d' | '90d' | 'custom';
export interface RangeState {
  range: RangeKey;
  from?: string;
  to?: string;
}

export function useRange(defaultRange: RangeKey = '7d'): [RangeState, (r: RangeState) => void] {
  const [params, setParams] = useSearchParams();
  const range = (params.get('range') as RangeKey) || defaultRange;
  const state: RangeState = { range, from: params.get('from') ?? undefined, to: params.get('to') ?? undefined };
  const set = (r: RangeState) => {
    const next = new URLSearchParams(params);
    next.set('range', r.range);
    for (const k of ['from', 'to'] as const) {
      if (r.range === 'custom' && r[k]) next.set(k, r[k]!);
      else next.delete(k);
    }
    next.delete('page');
    setParams(next, { replace: true });
  };
  return [state, set];
}

/** Query-string fragment for the API (custom ranges only once both dates are set). */
export function rangeParams(r: RangeState): Record<string, string | undefined> {
  if (r.range === 'custom') return r.from && r.to ? { range: 'custom', from: r.from, to: r.to } : { range: '7d' };
  return { range: r.range };
}

export function RangePicker({ value, onChange }: { value: RangeState; onChange: (r: RangeState) => void }) {
  const today = new Date().toISOString().slice(0, 10);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Segmented
        label="Date range"
        value={value.range}
        onChange={(range) => onChange(range === 'custom' ? { range, from: value.from ?? today, to: value.to ?? today } : { range })}
        options={[
          { value: 'today', label: 'Today' },
          { value: '7d', label: '7 days' },
          { value: '30d', label: '30 days' },
          { value: '90d', label: '90 days' },
          { value: 'custom', label: 'Custom' },
        ]}
      />
      {value.range === 'custom' && (
        <div className="flex items-center gap-1.5">
          <input aria-label="From" type="date" max={value.to ?? today} className={`${inputCls} w-[150px]`} value={value.from ?? ''} onChange={(e) => onChange({ ...value, from: e.target.value })} />
          <span className="text-muted">–</span>
          <input aria-label="To" type="date" min={value.from} max={today} className={`${inputCls} w-[150px]`} value={value.to ?? ''} onChange={(e) => onChange({ ...value, to: e.target.value })} />
        </div>
      )}
    </div>
  );
}
