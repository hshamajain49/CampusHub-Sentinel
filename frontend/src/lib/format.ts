// Display helpers. Times are shown in the viewer's local time; buckets from the API are already in REPORT_TIMEZONE.
const nf = new Intl.NumberFormat('en');
const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });
let regions: Intl.DisplayNames | null = null;
try {
  regions = new Intl.DisplayNames(['en'], { type: 'region' });
} catch {
  regions = null;
}

export const num = (n: number | null | undefined) => (n === null || n === undefined ? '—' : nf.format(n));
/** Full under 10,000, compact above (axis ticks and tiles). */
export const short = (n: number) => (Math.abs(n) < 10_000 ? nf.format(n) : compact.format(n));
export const pct = (n: number | null | undefined, digits = 1) => (n === null || n === undefined ? '—' : `${n.toFixed(digits)}%`);

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—';
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`;
}

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—';
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 10) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

const dtf = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
const dtfFull = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
export const dateTime = (iso: string | null | undefined) => (iso ? dtf.format(new Date(iso)) : '—');
export const dateTimeFull = (iso: string | null | undefined) => (iso ? dtfFull.format(new Date(iso)) : '—');

/** "2026-11-17T14:00" bucket label → "14:00" (hourly) or "17 Nov" (daily). */
export function bucketLabel(bucket: string, granularity: 'hour' | 'day'): string {
  const [date, time] = bucket.split('T');
  if (granularity === 'hour') return time ?? bucket;
  const [, m, d] = (date ?? '').split('-');
  const month = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][Number(m) - 1] ?? '';
  return `${Number(d)} ${month}`;
}

export function countryName(code: string | null | undefined): string {
  if (!code || code === 'unknown') return 'Unknown';
  try {
    return regions?.of(code) ?? code;
  } catch {
    return code;
  }
}

/** Regional-indicator flag; decorative only (the name is always shown too). */
export function flag(code: string | null | undefined): string {
  if (!code || !/^[A-Z]{2}$/.test(code)) return '';
  return String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

export const titleCase = (s: string | null | undefined) => (s ? s.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase()) : '—');
