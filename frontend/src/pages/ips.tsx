// Suspicious IPs: addresses ranked by a decaying risk score, with temporary blocks and the never-block allowlist.
// Blocking and allowlist changes are for owners and ask for a fresh password + code.
import * as React from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Ban, ShieldCheck, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { useAdmin } from '@/auth/session';
import { useReauth } from '@/auth/reauth';
import { api, ApiError, del, errorText, list, post, qs } from '@/lib/api';
import { ago, dateTime, dateTimeFull, num } from '@/lib/format';
import type { Block, Severity, SuspiciousIp } from '@/lib/types';
import { Button, Card, Empty, Field, inputCls, Modal, Mono, PageHeader, Pagination, Pill, rowLink, Segmented, SeverityBadge, SeverityDot, Spinner, StatusBadge, Table, td } from '@/components/ui';

const RISK_TONE = { low: 'neutral', medium: 'warning', high: 'critical', critical: 'critical' } as const;

function RiskPill({ score, level }: { score: number; level: SuspiciousIp['riskLevel'] }) {
  return (
    <Pill tone={RISK_TONE[level]} title="Weighted by severity; halves every day without activity. It ranks addresses; it is not proof.">
      <span className="tabular font-semibold">{score.toFixed(1)}</span> {level}
    </Pill>
  );
}

function BlockDialog({ open, onClose, initialCidr }: { open: boolean; onClose: () => void; initialCidr?: string }) {
  const qc = useQueryClient();
  const withReauth = useReauth();
  const [cidr, setCidr] = React.useState(initialCidr ?? '');
  const [minutes, setMinutes] = React.useState('60');
  const [reason, setReason] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (open) {
      setCidr(initialCidr ?? '');
      setReason('');
      setError(null);
    }
  }, [open, initialCidr]);
  const m = useMutation({
    mutationFn: () => withReauth(() => post<Block>('/api/security/blocks', { cidr, minutes: Number(minutes), reason })),
    onSuccess: (b) => {
      void qc.invalidateQueries({ queryKey: ['security'] });
      toast.success(`${b.cidr} blocked until ${dateTime(b.expiresAt)}.`);
      onClose();
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === 'REAUTH_CANCELLED') return;
      setError(errorText(e));
    },
  });
  return (
    <Modal open={open} onClose={onClose} title="Block temporarily">
      <form
        className="grid gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
      >
        <Field label="IP address or range" hint="At most an IPv4 /16 or IPv6 /48. Allowlisted addresses can't be blocked." error={error}>
          <input className={`${inputCls} font-mono`} value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="203.0.113.9 or 203.0.113.0/24" required />
        </Field>
        <Field label="For">
          <select className={inputCls} value={minutes} onChange={(e) => setMinutes(e.target.value)}>
            {[
              ['15', '15 minutes'],
              ['60', '1 hour'],
              ['360', '6 hours'],
              ['1440', '24 hours'],
              ['10080', '7 days'],
            ].map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Reason (recorded in the audit log)">
          <input className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} required />
        </Field>
        <p className="text-[12px] text-muted">CampusHub refuses requests from the range until the block expires or is lifted. Sentinel never blocks permanently.</p>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="danger" loading={m.isPending} disabled={!cidr.trim() || reason.trim().length < 3}>
            <Ban /> Block
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function BlocksAndAllowlist() {
  const admin = useAdmin();
  const qc = useQueryClient();
  const withReauth = useReauth();
  const owner = admin.role === 'owner';
  const blocks = useQuery({ queryKey: ['security', 'blocks'], queryFn: () => api<Block[]>('/api/security/blocks?active=true') });
  const allow = useQuery({ queryKey: ['security', 'allowlist'], queryFn: () => api<{ id: string; cidr: string; note: string; createdBy: string; createdAt: string }[]>('/api/security/allowlist') });
  const [cidr, setCidr] = React.useState('');
  const [note, setNote] = React.useState('');
  const refresh = () => void qc.invalidateQueries({ queryKey: ['security'] });
  const fail = (e: unknown) => !(e instanceof ApiError && e.code === 'REAUTH_CANCELLED') && toast.error(errorText(e));
  const lift = useMutation({ mutationFn: (id: string) => post(`/api/security/blocks/${id}/lift`), onSuccess: () => (refresh(), toast.success('Block lifted.')), onError: fail });
  const add = useMutation({
    mutationFn: () => withReauth(() => post<{ liftedBlocks: number }>('/api/security/allowlist', { cidr, note })),
    onSuccess: (r) => {
      refresh();
      setCidr('');
      setNote('');
      toast.success(r.liftedBlocks ? `Added; ${r.liftedBlocks} block(s) lifted.` : 'Added to the allowlist.');
    },
    onError: fail,
  });
  const remove = useMutation({ mutationFn: (id: string) => withReauth(() => del(`/api/security/allowlist/${id}`)), onSuccess: () => (refresh(), toast.success('Removed.')), onError: fail });

  return (
    <div className="mt-3 grid gap-3 lg:grid-cols-2">
      <Card title="Active blocks" subtitle="Enforced by CampusHub until they expire">
        {blocks.data?.length ? (
          <ul className="grid gap-2">
            {blocks.data.map((b) => (
              <li key={b.id} className="flex flex-wrap items-center gap-2 rounded-[10px] border border-line px-3 py-2 text-[13px]">
                <Mono>{b.cidr}</Mono>
                <Pill>{b.source === 'rule' ? `auto · ${b.ruleKey}` : 'manual'}</Pill>
                <span className="text-[12px] text-muted">until {dateTime(b.expiresAt)}</span>
                <span className="w-full truncate text-[12px] text-ink-2">{b.reason}</span>
                {owner && (
                  <Button size="sm" variant="ghost" className="ml-auto" onClick={() => lift.mutate(b.id)} loading={lift.isPending && lift.variables === b.id}>
                    Lift
                  </Button>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <Empty>No active blocks.</Empty>
        )}
      </Card>
      <Card title="Allowlist" subtitle="Never blocked, by hand or by a rule (your offices, the campus gateway)">
        {allow.data?.length ? (
          <ul className="mb-3 grid gap-1.5">
            {allow.data.map((w) => (
              <li key={w.id} className="flex items-center gap-2 text-[13px]">
                <ShieldCheck className="size-4 text-good-text" aria-hidden />
                <Mono>{w.cidr}</Mono>
                <span className="truncate text-ink-2">{w.note}</span>
                {owner && (
                  <Button size="sm" variant="ghost" className="ml-auto" aria-label={`Remove ${w.cidr}`} onClick={() => remove.mutate(w.id)}>
                    <Trash2 />
                  </Button>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mb-3 text-[12.5px] text-muted">Empty. Add the networks you work from so a mistaken block can never lock you out.</p>
        )}
        {owner && (
          <form
            className="flex flex-wrap gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              add.mutate();
            }}
          >
            <input aria-label="IP or range to allow" className={`${inputCls} w-[180px] font-mono`} placeholder="IP or CIDR" value={cidr} onChange={(e) => setCidr(e.target.value)} />
            <input aria-label="Note" className={`${inputCls} min-w-[140px] flex-1`} placeholder="Whose network?" value={note} onChange={(e) => setNote(e.target.value)} />
            <Button type="submit" loading={add.isPending} disabled={!cidr.trim() || note.trim().length < 2}>
              Add
            </Button>
          </form>
        )}
      </Card>
    </div>
  );
}

export function IpsPage() {
  const navigate = useNavigate();
  const admin = useAdmin();
  const [minScore, setMinScore] = React.useState('5');
  const [page, setPage] = React.useState(1);
  const [blockOpen, setBlockOpen] = React.useState(false);
  const q = useQuery({ queryKey: ['security', 'ips', minScore, page], queryFn: () => list<SuspiciousIp>(`/api/security/ips${qs({ minScore, page, pageSize: 25 })}`) });
  return (
    <>
      <PageHeader
        title="Suspicious IPs"
        subtitle="Addresses ranked by recent suspicious activity. A high score is a reason to look, not proof."
        actions={
          admin.role === 'owner' && (
            <Button variant="danger" onClick={() => setBlockOpen(true)}>
              <Ban /> Block an address
            </Button>
          )
        }
      />
      <Card
        action={
          <Segmented
            label="Minimum risk"
            value={minScore}
            onChange={(v) => (setMinScore(v), setPage(1))}
            options={[
              { value: '0', label: 'All' },
              { value: '5', label: 'Score ≥ 5' },
              { value: '10', label: '≥ 10' },
              { value: '30', label: '≥ 30' },
            ]}
          />
        }
        title="Ranked by risk"
      >
        {q.isPending ? (
          <Spinner />
        ) : q.data?.data.length ? (
          <>
            <Table head={['IP address', 'Risk', 'Events', 'Open alerts', 'First detected', 'Last detected', 'Reasons', 'State']}>
              {q.data.data.map((ip) => (
                <tr key={ip.ip} className={rowLink} onClick={() => navigate(`/ips/${ip.ip}`)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && navigate(`/ips/${ip.ip}`)}>
                  <td className={td}>
                    <Mono>{ip.ip}</Mono>
                  </td>
                  <td className={td}>
                    <RiskPill score={ip.riskScore} level={ip.riskLevel} />
                  </td>
                  <td className={`${td} tabular`}>{num(ip.eventCount)}</td>
                  <td className={`${td} tabular`}>{ip.openAlerts || '—'}</td>
                  <td className={`${td} whitespace-nowrap text-[12px] text-ink-2`}>{dateTime(ip.firstDetectedAt)}</td>
                  <td className={`${td} whitespace-nowrap text-[12px] text-ink-2`}>{ago(ip.lastDetectedAt)}</td>
                  <td className={`${td} max-w-[260px] text-[12px] text-ink-2`}>
                    <span className="line-clamp-2">{ip.reasons.join(', ')}</span>
                  </td>
                  <td className={td}>{ip.blocked ? <Pill tone="critical">Blocked</Pill> : ip.allowlisted ? <Pill tone="good">Allowlisted</Pill> : '—'}</td>
                </tr>
              ))}
            </Table>
            <Pagination page={q.data.meta.page} totalPages={q.data.meta.totalPages} total={q.data.meta.total} onPage={setPage} />
          </>
        ) : (
          <Empty>No addresses above this score.</Empty>
        )}
      </Card>
      <BlocksAndAllowlist />
      <BlockDialog open={blockOpen} onClose={() => setBlockOpen(false)} />
    </>
  );
}

interface IpDetail {
  ip: string;
  riskScore: number;
  riskLevel: SuspiciousIp['riskLevel'];
  eventCount: number;
  firstDetectedAt: string | null;
  lastDetectedAt: string | null;
  reasons: string[];
  events: { id: string; occurredAt: string; category: string; severity: Severity; userRef: string | null; method: string | null; route: string | null; statusCode: number | null; description: string }[];
  alerts: { id: string; ruleKey: string; severity: Severity; title: string; status: string; occurrences: number; lastSeenAt: string }[];
  blocks: Block[];
}

export function IpPage() {
  const { ip } = useParams();
  const admin = useAdmin();
  const navigate = useNavigate();
  const [blockOpen, setBlockOpen] = React.useState(false);
  const q = useQuery({ queryKey: ['security', 'ip', ip], queryFn: () => api<IpDetail>(`/api/security/ips/${ip}`) });
  if (!q.data) return q.error ? <Empty>{(q.error as Error).message}</Empty> : <Spinner />;
  const d = q.data;
  const active = d.blocks.find((b) => b.active);
  return (
    <>
      <Link to="/ips" className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-muted hover:text-ink">
        <ArrowLeft className="size-3.5" /> Suspicious IPs
      </Link>
      <PageHeader
        title={d.ip}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <RiskPill score={d.riskScore} level={d.riskLevel} /> {num(d.eventCount)} events · first {dateTime(d.firstDetectedAt)} · last {ago(d.lastDetectedAt)}
            {active && <Pill tone="critical">Blocked until {dateTime(active.expiresAt)}</Pill>}
          </span>
        }
        actions={
          admin.role === 'owner' &&
          !active && (
            <Button variant="danger" onClick={() => setBlockOpen(true)}>
              <Ban /> Block
            </Button>
          )
        }
      />
      <div className="grid gap-3 xl:grid-cols-[2fr_1fr]">
        <Card title="Recent events" subtitle="Latest 100">
          {d.events.length ? (
            <Table head={['Time', 'Event', 'Request']}>
              {d.events.map((e) => (
                <tr key={e.id} className={rowLink} onClick={() => navigate(`/events?event=${e.id}`)}>
                  <td className={`${td} whitespace-nowrap text-[12px]`}>{dateTimeFull(e.occurredAt)}</td>
                  <td className={td}>
                    <span className="flex items-center gap-1.5">
                      <SeverityDot severity={e.severity} /> <Mono>{e.category}</Mono>
                    </span>
                    <span className="text-[12px] text-muted">{e.description}</span>
                  </td>
                  <td className={`${td} font-mono text-[12px]`}>
                    {e.method} {e.route} {e.statusCode ? `→ ${e.statusCode}` : ''}
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            <Empty>No events from this address.</Empty>
          )}
        </Card>
        <div className="grid content-start gap-3">
          <Card title="Why it's listed">
            <ul className="flex flex-wrap gap-1.5">
              {d.reasons.map((r) => (
                <Pill key={r}>{r}</Pill>
              ))}
            </ul>
          </Card>
          <Card title="Alerts">
            {d.alerts.length ? (
              <ul className="grid gap-2">
                {d.alerts.map((a) => (
                  <li key={a.id}>
                    <Link to={`/alerts/${a.id}`} className="grid gap-1 rounded-[8px] px-1 py-1 hover:bg-surface-2">
                      <span className="flex items-center gap-2">
                        <SeverityBadge severity={a.severity} /> <StatusBadge status={a.status} />
                      </span>
                      <span className="text-[13px]">{a.title}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>None.</Empty>
            )}
          </Card>
          <Card title="Block history">
            {d.blocks.length ? (
              <ul className="grid gap-1.5 text-[12.5px]">
                {d.blocks.map((b) => (
                  <li key={b.id}>
                    <Mono>{b.cidr}</Mono> · {b.source} · {dateTime(b.createdAt)} → {b.liftedAt ? `lifted ${dateTime(b.liftedAt)}` : dateTime(b.expiresAt)}
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>Never blocked.</Empty>
            )}
          </Card>
        </div>
      </div>
      <BlockDialog open={blockOpen} onClose={() => setBlockOpen(false)} initialCidr={d.ip} />
    </>
  );
}
