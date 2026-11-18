// Live updates over Server-Sent Events (/api/stream). The server pushes a small summary at most every 2 s while
// something changes and an "alert" event the moment an alert opens or escalates. Pages refresh their queries on
// change (throttled), so nothing polls the database on a timer.
import * as React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import type { LiveSummary } from './types';

interface LiveCtx {
  connected: boolean;
  summary: LiveSummary | null;
}
const Ctx = React.createContext<LiveCtx>({ connected: false, summary: null });
export const useLive = () => React.useContext(Ctx);

export function LiveProvider({ children, onAlertClick }: { children: React.ReactNode; onAlertClick: (id: string) => void }) {
  const qc = useQueryClient();
  const [connected, setConnected] = React.useState(false);
  const [summary, setSummary] = React.useState<LiveSummary | null>(null);
  const clickRef = React.useRef(onAlertClick);
  clickRef.current = onAlertClick;

  React.useEffect(() => {
    let lastRefresh = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // Refetch what's on screen at most every 5 s, however busy the stream is.
    const refresh = () => {
      const wait = Math.max(0, 5_000 - (Date.now() - lastRefresh));
      if (timer) return;
      timer = setTimeout(() => {
        timer = undefined;
        lastRefresh = Date.now();
        void qc.invalidateQueries({ predicate: (q) => ['analytics', 'security', 'health'].includes(String(q.queryKey[0])) });
      }, wait);
    };
    const es = new EventSource('/api/stream');
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false); // EventSource reconnects on its own (retry: 5000)
    es.addEventListener('analytics', (e) => {
      setSummary(JSON.parse((e as MessageEvent).data));
      refresh();
    });
    es.addEventListener('alert', (e) => {
      const a = JSON.parse((e as MessageEvent).data) as { id: string; severity: string; title: string; created: boolean; simulated: boolean };
      refresh();
      if (a.severity !== 'high' && a.severity !== 'critical') return;
      const text = `${a.created ? 'New' : 'Escalated'} ${a.severity} alert${a.simulated ? ' (simulated)' : ''}`;
      const show = a.severity === 'critical' ? toast.error : toast.warning;
      show(text, { description: a.title, duration: a.severity === 'critical' ? Infinity : 12_000, action: { label: 'View', onClick: () => clickRef.current(a.id) } });
    });
    es.addEventListener('session-ended', () => {
      es.close();
      void qc.invalidateQueries({ queryKey: ['session'] });
    });
    return () => {
      if (timer) clearTimeout(timer);
      es.close();
    };
  }, [qc]);

  return <Ctx.Provider value={{ connected, summary }}>{children}</Ctx.Provider>;
}
