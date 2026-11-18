// Security scan reports uploaded by CampusHub's tooling (npm run security:audit -- --upload). Read-only here:
// reports are append-only in the database.
import * as React from 'react';
import { useQuery } from '@tanstack/react-query';
import { FileSearch } from 'lucide-react';
import { api, list, qs } from '@/lib/api';
import { dateTimeFull } from '@/lib/format';
import { Card, Empty, ErrorNote, Modal, Mono, Pagination, Pill, Segmented, Spinner, Table, rowLink, td } from '@/components/ui';

type Status = 'pass' | 'fail' | 'warn' | 'info' | 'skip';
interface Summary {
  pass: number;
  fail: number;
  warn: number;
  info: number;
  skip: number;
}
interface Check {
  id: string;
  title: string;
  status: Status;
  severity?: string;
  location?: string;
  detail?: string;
}
interface ReportRow {
  id: string;
  receivedAt: string;
  finishedAt: string;
  source: string;
  environment: string;
  gitCommit: string | null;
  summary: Summary;
  sections: { name: string; kind: string; summary: Summary; checks?: Check[] }[];
}

const TONE: Record<Status, 'critical' | 'warning' | 'good' | 'neutral'> = { fail: 'critical', warn: 'warning', pass: 'good', info: 'neutral', skip: 'neutral' };
const LABEL: Record<Status, string> = { fail: 'Fail', warn: 'Warn', pass: 'Pass', info: 'Info', skip: 'Skipped' };

function Counts({ s }: { s: Summary }) {
  return (
    <span className="flex flex-wrap gap-1">
      {s.fail > 0 && <Pill tone="critical">{s.fail} fail</Pill>}
      {s.warn > 0 && <Pill tone="warning">{s.warn} warn</Pill>}
      <Pill tone="good">{s.pass} pass</Pill>
      {s.skip > 0 && <Pill>{s.skip} skipped</Pill>}
    </span>
  );
}

function ReportDetail({ id, onClose }: { id: string | null; onClose: () => void }) {
  const [show, setShow] = React.useState<'problems' | 'all'>('problems');
  const q = useQuery({ queryKey: ['scan-report', id], queryFn: () => api<ReportRow>(`/api/security/reports/${id}`), enabled: !!id });
  const r = q.data;
  return (
    <Modal open={!!id} onClose={onClose} title="Scan report" wide>
      {q.isPending ? (
        <Spinner />
      ) : q.error ? (
        <ErrorNote error={q.error} />
      ) : r ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[12.5px] text-ink-2">
            <span>
              {dateTimeFull(r.receivedAt)} · <Pill tone={r.environment === 'production' ? 'primary' : 'neutral'}>{r.environment}</Pill>
              {r.gitCommit && (
                <>
                  {' '}
                  · commit <Mono>{r.gitCommit}</Mono>
                </>
              )}
            </span>
            <Segmented
              label="Show"
              value={show}
              onChange={setShow}
              options={[
                { value: 'problems', label: 'Problems' },
                { value: 'all', label: 'All checks' },
              ]}
            />
          </div>
          <p className="text-[12px] text-muted">
            Automated checks only: a clean report is not proof that CampusHub is secure. Active-probe results come from simulated attacks on a local or staging environment.
          </p>
          {r.sections.map((s) => {
            const checks = (s.checks ?? []).filter((c) => show === 'all' || c.status === 'fail' || c.status === 'warn');
            return (
              <section key={s.name}>
                <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-[13.5px] font-semibold">
                    {s.name} <span className="font-normal text-muted">· {s.kind}</span>
                  </h3>
                  <Counts s={s.summary} />
                </div>
                {checks.length ? (
                  <Table head={['Result', 'Check', 'Where / detail']}>
                    {checks.map((c, i) => (
                      <tr key={`${c.id}-${i}`}>
                        <td className={td}>
                          <Pill tone={TONE[c.status]}>{LABEL[c.status]}</Pill>
                        </td>
                        <td className={`${td} text-[12.5px]`}>
                          {c.title}
                          <div className="text-[11px] text-muted">
                            <Mono>{c.id}</Mono>
                          </div>
                        </td>
                        <td className={`${td} max-w-[320px] text-[12px] text-ink-2`}>
                          {c.location && (
                            <div>
                              <Mono>{c.location}</Mono>
                            </div>
                          )}
                          <span className="break-words">{c.detail ?? ''}</span>
                        </td>
                      </tr>
                    ))}
                  </Table>
                ) : (
                  <p className="rounded-lg bg-surface-2 px-3 py-2 text-[12.5px] text-ink-2">{show === 'problems' ? 'No failures or warnings.' : 'No checks.'}</p>
                )}
              </section>
            );
          })}
        </div>
      ) : null}
    </Modal>
  );
}

export function ScanReports() {
  const [page, setPage] = React.useState(1);
  const [open, setOpen] = React.useState<string | null>(null);
  const q = useQuery({ queryKey: ['scan-reports', page], queryFn: () => list<ReportRow>(`/api/security/reports${qs({ page, pageSize: 10 })}`) });
  return (
    <Card title="Security scan reports" subtitle="Dependency audit, secret scan, static analysis, header checks and the active probe, uploaded by CampusHub's tooling">
      {q.isPending ? (
        <Spinner />
      ) : q.error ? (
        <ErrorNote error={q.error} />
      ) : q.data?.data.length ? (
        <>
          <Table head={['Received', 'Environment', 'Result', 'Sections']}>
            {q.data.data.map((r) => (
              <tr
                key={r.id}
                className={rowLink}
                tabIndex={0}
                onClick={() => setOpen(r.id)}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setOpen(r.id))}
                aria-label={`Open the scan report from ${dateTimeFull(r.receivedAt)}`}
              >
                <td className={`${td} whitespace-nowrap text-[12px]`}>
                  {dateTimeFull(r.receivedAt)}
                  {r.gitCommit && (
                    <div className="text-[11px] text-muted">
                      commit <Mono>{r.gitCommit}</Mono>
                    </div>
                  )}
                </td>
                <td className={td}>
                  <Pill tone={r.environment === 'production' ? 'primary' : 'neutral'}>{r.environment}</Pill>
                </td>
                <td className={td}>
                  <Counts s={r.summary} />
                </td>
                <td className={`${td} text-[12px] text-ink-2`}>{r.sections.map((s) => s.name).join(' · ')}</td>
              </tr>
            ))}
          </Table>
          <Pagination page={q.data.meta.page} totalPages={q.data.meta.totalPages} total={q.data.meta.total} onPage={setPage} />
        </>
      ) : (
        <Empty icon={<FileSearch className="size-5" />}>
          No scan reports yet. In the CampusHub repository run <Mono>npm run security:audit -- --upload</Mono> with the ingestion settings in the environment.
        </Empty>
      )}
      <ReportDetail id={open} onClose={() => setOpen(null)} />
    </Card>
  );
}
