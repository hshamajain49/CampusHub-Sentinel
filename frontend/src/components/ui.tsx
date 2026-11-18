// Small UI kit for the dashboard. Status and severity always pair colour with an icon and a word (never colour alone).
import * as React from 'react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { AlertOctagon, AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Info, Loader2, ShieldAlert, X } from 'lucide-react';
import type { Severity } from '@/lib/types';

export const cn = (...v: ClassValue[]) => twMerge(clsx(v));

export function Card({ title, action, children, className, subtitle }: { title?: React.ReactNode; subtitle?: React.ReactNode; action?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn('card flex min-w-0 flex-col p-4', className)}>
      {(title || action) && (
        <header className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && <h2 className="text-[13px] font-semibold text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-[12px] text-muted">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; size?: 'sm' | 'md'; loading?: boolean };
export function Button({ variant = 'secondary', size = 'md', loading, className, children, disabled, ...p }: ButtonProps) {
  return (
    <button
      {...p}
      disabled={disabled || loading}
      className={cn(
        'inline-flex shrink-0 items-center justify-center gap-1.5 rounded-[8px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 [&_svg]:size-4',
        size === 'sm' ? 'h-8 px-2.5 text-[12.5px]' : 'h-9 px-3.5 text-[13px]',
        variant === 'primary' && 'bg-primary text-white hover:bg-primary-hover',
        variant === 'secondary' && 'border border-line-strong bg-surface-2 text-ink hover:bg-surface-3',
        variant === 'ghost' && 'text-ink-2 hover:bg-surface-2 hover:text-ink',
        variant === 'danger' && 'bg-critical text-white hover:brightness-110',
        className,
      )}
    >
      {loading && <Loader2 className="animate-spin" />}
      {children}
    </button>
  );
}

export const inputCls =
  'h-9 w-full rounded-[8px] border border-line-strong bg-surface-2 px-3 text-[13px] text-ink placeholder:text-muted focus:border-primary focus:outline-none';

/**
 * Label above a single control; the hint and error are linked with aria-describedby, so the control's accessible
 * name is just the label (not the label plus its help text).
 */
export function Field({ label, error, hint, children }: { label: string; error?: string | null; hint?: string; children: React.ReactElement<any> }) {
  const id = React.useId();
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const describedBy = [hint && !error ? hintId : null, error ? errId : null].filter(Boolean).join(' ') || undefined;
  const control = React.cloneElement(children, { id: children.props.id ?? id, 'aria-describedby': describedBy, 'aria-invalid': error ? true : undefined });
  return (
    <div className="grid gap-1.5">
      <label htmlFor={children.props.id ?? id} className="text-[12.5px] font-medium text-ink-2">
        {label}
      </label>
      {control}
      {hint && !error && (
        <span id={hintId} className="text-[12px] text-muted">
          {hint}
        </span>
      )}
      {error && (
        <span id={errId} className="text-[12px] text-critical-text" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

export function Select({ value, onChange, options, className, label }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; className?: string; label: string }) {
  return (
    <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)} className={cn(inputCls, 'w-auto pr-8', className)}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-[8px] border border-line-strong bg-surface-2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn('h-7 rounded-[6px] px-2.5 text-[12.5px] font-medium', value === o.value ? 'bg-surface-3 text-ink' : 'text-muted hover:text-ink')}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

const SEV: Record<Severity, { label: string; dot: string; text: string; Icon: typeof Info }> = {
  info: { label: 'Info', dot: 'bg-muted', text: 'text-ink-2', Icon: Info },
  low: { label: 'Low', dot: 'bg-[var(--sev-low)]', text: 'text-ink-2', Icon: Info },
  medium: { label: 'Medium', dot: 'bg-[var(--sev-medium)]', text: 'text-warning-text', Icon: AlertTriangle },
  high: { label: 'High', dot: 'bg-[var(--sev-high)]', text: 'text-critical-text', Icon: ShieldAlert },
  critical: { label: 'Critical', dot: 'bg-[var(--sev-critical)]', text: 'text-critical-text', Icon: AlertOctagon },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEV[severity] ?? SEV.info;
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11.5px] font-semibold',
        severity === 'critical' ? 'border-critical bg-critical/20 text-critical-text' : 'border-line-strong bg-surface-2',
        severity !== 'critical' && s.text,
      )}
    >
      <s.Icon className="size-3.5" aria-hidden />
      {s.label}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  return <span aria-hidden className={cn('inline-block size-2 shrink-0 rounded-full', SEV[severity]?.dot)} />;
}

const STATUS: Record<string, { label: string; cls: string }> = {
  open: { label: 'Open', cls: 'text-critical-text border-critical/50' },
  acknowledged: { label: 'Investigating', cls: 'text-warning-text border-warning/40' },
  resolved: { label: 'Resolved', cls: 'text-good-text border-good/40' },
  false_positive: { label: 'False positive', cls: 'text-ink-2 border-line-strong' },
  new: { label: 'New', cls: 'text-critical-text border-critical/50' },
  investigating: { label: 'Investigating', cls: 'text-warning-text border-warning/40' },
};
export function StatusBadge({ status }: { status: string }) {
  const s = STATUS[status] ?? { label: status, cls: 'text-ink-2 border-line-strong' };
  return <span className={cn('inline-flex rounded-full border px-2 py-0.5 text-[11.5px] font-semibold', s.cls)}>{s.label}</span>;
}

export function Pill({ children, tone = 'neutral', title }: { children: React.ReactNode; tone?: 'neutral' | 'good' | 'warning' | 'critical' | 'primary'; title?: string }) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11.5px] font-medium',
        tone === 'neutral' && 'bg-surface-3 text-ink-2',
        tone === 'good' && 'bg-good/15 text-good-text',
        tone === 'warning' && 'bg-warning/15 text-warning-text',
        tone === 'critical' && 'bg-critical/20 text-critical-text',
        tone === 'primary' && 'bg-primary-soft text-[#8fbaf0]',
      )}
    >
      {children}
    </span>
  );
}

export function SimulatedBadge() {
  return (
    <Pill tone="primary" title="Raised by test traffic (simulated: true), not a real event">
      Simulated
    </Pill>
  );
}

/** A KPI tile: label, the number, an optional small line under it. */
export function Stat({ label, value, sub, tone, icon }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: 'good' | 'warning' | 'critical'; icon?: React.ReactNode }) {
  return (
    <div className="card min-w-0 p-4">
      <div className="flex items-center gap-1.5 text-[12px] font-medium text-muted">
        {icon}
        {label}
      </div>
      <div
        className={cn(
          'tabular mt-1.5 truncate text-[26px] font-semibold leading-8 tracking-[-0.3px]',
          tone === 'critical' ? 'text-critical-text' : tone === 'warning' ? 'text-warning-text' : tone === 'good' ? 'text-good-text' : 'text-ink',
        )}
      >
        {value}
      </div>
      {sub && <div className="mt-0.5 truncate text-[12px] text-muted">{sub}</div>}
    </div>
  );
}

export function HealthBadge({ status, reasons }: { status: 'healthy' | 'warning' | 'critical'; reasons?: string[] }) {
  const map = {
    healthy: { label: 'Healthy', Icon: CheckCircle2, cls: 'text-good-text', dot: 'bg-good' },
    warning: { label: 'Warning', Icon: AlertTriangle, cls: 'text-warning-text', dot: 'bg-warning' },
    critical: { label: 'Critical', Icon: AlertOctagon, cls: 'text-critical-text', dot: 'bg-critical' },
  }[status];
  return (
    <span className={cn('inline-flex items-center gap-1.5 font-semibold', map.cls)} title={reasons?.join('\n') || 'All monitored signals are normal'}>
      <map.Icon className="size-4" aria-hidden />
      {map.label}
    </span>
  );
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 p-8 text-[13px] text-muted" role="status">
      <Loader2 className="size-4 animate-spin" /> {label}…
    </div>
  );
}

export function Empty({ children, icon }: { children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center text-[13px] text-muted">
      {icon}
      {children}
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  return (
    <div className="rounded-[10px] border border-critical/40 bg-critical/10 px-3 py-2 text-[13px] text-critical-text" role="alert">
      {error instanceof Error ? error.message : 'Something went wrong.'}
    </div>
  );
}

/** Plain table with sticky header; rows clickable when onRow is given. */
export function Table({ head, children, className }: { head: React.ReactNode[]; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('-mx-4 overflow-x-auto', className)}>
      <table className="w-full min-w-[640px] border-collapse text-left text-[13px]">
        <thead>
          <tr className="border-b border-line text-[11.5px] uppercase tracking-[0.4px] text-muted">
            {head.map((h, i) => (
              <th key={i} className="whitespace-nowrap px-4 py-2 font-medium first:pl-4">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="[&>tr]:border-b [&>tr]:border-line/60 [&>tr:last-child]:border-0">{children}</tbody>
      </table>
    </div>
  );
}
export const td = 'px-4 py-2.5 align-top';
export const rowLink = 'cursor-pointer hover:bg-surface-2/70';

export function Pagination({ page, totalPages, total, onPage }: { page: number; totalPages: number; total: number; onPage: (p: number) => void }) {
  if (totalPages <= 1) return <div className="pt-3 text-[12px] text-muted">{total} total</div>;
  return (
    <div className="flex items-center justify-between pt-3 text-[12px] text-muted">
      <span className="tabular">
        Page {page} of {totalPages} · {total} total
      </span>
      <div className="flex gap-1">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
          <ChevronLeft />
        </Button>
        <Button size="sm" variant="ghost" disabled={page >= totalPages} onClick={() => onPage(page + 1)} aria-label="Next page">
          <ChevronRight />
        </Button>
      </div>
    </div>
  );
}

export function Modal({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: string; children: React.ReactNode; wide?: boolean }) {
  const ref = React.useRef<HTMLDialogElement>(null);
  const titleId = React.useId();
  React.useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      onCancel={onClose}
      className={cn('m-auto w-[calc(100%-32px)] rounded-[14px] border border-line-strong bg-surface p-0 text-ink backdrop:bg-black/60', wide ? 'max-w-[720px]' : 'max-w-[440px]')}
    >
      {open && (
        <div className="p-5">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 id={titleId} className="text-[15px] font-semibold">
              {title}
            </h2>
            <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close">
              <X />
            </Button>
          </div>
          {children}
        </div>
      )}
    </dialog>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-[20px] font-semibold tracking-[-0.2px]">{title}</h1>
        {subtitle && <p className="mt-0.5 text-[13px] text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[12.5px]">{children}</span>;
}
