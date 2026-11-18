// Security Audit Reports: who did what in Sentinel (every sign-in, step, change and triage), and the CampusHub
// security scan reports. The audit log is append-only in the database; nobody can edit or delete an entry here.
import * as React from 'react';
import { useQuery } from '@tanstack/react-query';
import { list, qs } from '@/lib/api';
import { dateTimeFull } from '@/lib/format';
import { Card, Empty, Mono, PageHeader, Pagination, Pill, Segmented, Select, Spinner, Table, td } from '@/components/ui';
import { ScanReports } from './scan-reports';

interface AuditEntry {
  id: number;
  occurredAt: string;
  admin: { id: string | null; email: string } | null;
  action: string;
  outcome: 'success' | 'failure';
  target: { type: string; id: string } | null;
  ip: string | null;
  userAgent: string | null;
  details: Record<string, unknown>;
}

const ACTIONS = [
  'auth.login',
  'auth.logout',
  'auth.mfa_verify',
  'auth.mfa_enable',
  'auth.password_change',
  'auth.reauth',
  'admin.created',
  'admin.deactivated',
  'admin.mfa_reset',
  'alert.status_changed',
  'incident.created',
  'incident.updated',
  'incident.note_added',
  'block.created',
  'block.lifted',
  'allowlist.added',
  'allowlist.removed',
  'rule.updated',
  'app.secret_rotated',
  'preferences.updated',
];

export function AuditPage() {
  const [outcome, setOutcome] = React.useState<'all' | 'success' | 'failure'>('all');
  const [action, setAction] = React.useState('');
  const [page, setPage] = React.useState(1);
  const q = useQuery({
    queryKey: ['audit', outcome, action, page],
    queryFn: () => list<AuditEntry>(`/api/audit-logs${qs({ outcome: outcome === 'all' ? undefined : outcome, action: action || undefined, page, pageSize: 50 })}`),
  });
  return (
    <>
      <PageHeader title="Security Audit Reports" subtitle="Who did what in Sentinel, and CampusHub's security scan results." />
      <ScanReports />
      <Card
        className="mt-3"
        title="Dashboard audit log"
        subtitle="Append-only in the database: entries can't be changed or deleted, by anyone"
        action={
          <div className="flex flex-wrap gap-2">
            <Select label="Action" value={action} onChange={(v) => (setAction(v), setPage(1))} options={[{ value: '', label: 'All actions' }, ...ACTIONS.map((a) => ({ value: a, label: a }))]} />
            <Segmented
              label="Outcome"
              value={outcome}
              onChange={(v) => (setOutcome(v), setPage(1))}
              options={[
                { value: 'all', label: 'All' },
                { value: 'success', label: 'Succeeded' },
                { value: 'failure', label: 'Failed' },
              ]}
            />
          </div>
        }
      >
        {q.isPending ? (
          <Spinner />
        ) : q.data?.data.length ? (
          <>
            <Table head={['Time', 'Who', 'Action', 'Outcome', 'Target', 'From', 'Details']}>
              {q.data.data.map((e) => (
                <tr key={e.id}>
                  <td className={`${td} whitespace-nowrap text-[12px]`}>{dateTimeFull(e.occurredAt)}</td>
                  <td className={`${td} max-w-[200px] truncate`}>{e.admin?.email ?? <span className="text-muted">unknown account</span>}</td>
                  <td className={td}>
                    <Mono>{e.action}</Mono>
                  </td>
                  <td className={td}>{e.outcome === 'success' ? <Pill tone="good">Success</Pill> : <Pill tone="critical">Failed</Pill>}</td>
                  <td className={`${td} text-[12px] text-ink-2`}>{e.target ? `${e.target.type} ${e.target.id.slice(0, 8)}` : '—'}</td>
                  <td className={td}>
                    <Mono>{e.ip ?? '—'}</Mono>
                  </td>
                  <td className={`${td} max-w-[280px] text-[12px] text-ink-2`}>
                    <span className="line-clamp-2 font-mono">{Object.keys(e.details).length ? JSON.stringify(e.details) : '—'}</span>
                  </td>
                </tr>
              ))}
            </Table>
            <Pagination page={q.data.meta.page} totalPages={q.data.meta.totalPages} total={q.data.meta.total} onPage={setPage} />
          </>
        ) : (
          <Empty>No entries.</Empty>
        )}
      </Card>
    </>
  );
}
