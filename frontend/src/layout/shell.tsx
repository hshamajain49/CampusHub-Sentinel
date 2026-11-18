// App shell: navigation, the health indicator (derived by the API from open alerts and ingestion freshness), the
// live-connection indicator, and the signed-in developer. Guards every page: no active session → sign-in.
import * as React from 'react';
import { NavLink, Navigate, Outlet, useLocation, useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  BarChart3,
  FileClock,
  Gauge,
  Globe2,
  ListTree,
  LogOut,
  Menu,
  Settings,
  ShieldAlert,
  Siren,
  X,
} from 'lucide-react';
import { useSession } from '@/auth/session';
import { api } from '@/lib/api';
import { LiveProvider, useLive } from '@/lib/live';
import type { Health } from '@/lib/types';
import { Button, cn, HealthBadge, Spinner } from '@/components/ui';

const NAV = [
  { to: '/', label: 'Overview', icon: Gauge, end: true },
  { to: '/visitors', label: 'Live Visitors', icon: Activity },
  { to: '/traffic', label: 'Traffic Analytics', icon: BarChart3 },
  { to: '/threats', label: 'Security Threats', icon: ShieldAlert },
  { to: '/events', label: 'Security Events', icon: ListTree },
  { to: '/ips', label: 'Suspicious IPs', icon: Globe2 },
  { to: '/incidents', label: 'Incidents', icon: Siren },
  { to: '/audit', label: 'Audit Reports', icon: FileClock },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export function useHealth() {
  return useQuery({ queryKey: ['health'], queryFn: () => api<Health>('/api/security/status'), refetchInterval: 60_000 });
}

function Nav({ onNavigate }: { onNavigate?: () => void }) {
  const { summary } = useLive();
  const open = summary ? Object.values(summary.apps)[0]?.openAlerts : undefined;
  const urgent = (open?.critical ?? 0) + (open?.high ?? 0);
  return (
    <nav aria-label="Main" className="grid gap-0.5">
      {NAV.map((n) => (
        <NavLink
          key={n.to}
          to={n.to}
          end={n.end}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'flex items-center gap-2.5 rounded-[8px] px-3 py-2 text-[13px] font-medium',
              isActive ? 'bg-surface-3 text-ink' : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
            )
          }
        >
          <n.icon className="size-4 shrink-0" aria-hidden />
          <span className="flex-1">{n.label}</span>
          {n.to === '/threats' && urgent > 0 && (
            <span className="tabular rounded-full bg-critical px-1.5 text-[11px] font-semibold text-white" aria-label={`${urgent} open high or critical alerts`}>
              {urgent}
            </span>
          )}
        </NavLink>
      ))}
    </nav>
  );
}

function TopBar({ onMenu }: { onMenu: () => void }) {
  const { session, signOut } = useSession();
  const { connected, summary } = useLive();
  const health = useHealth();
  const online = summary ? Object.values(summary.apps)[0]?.online : undefined;
  return (
    <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-page/90 px-4 backdrop-blur md:px-6">
      <Button variant="ghost" size="sm" className="md:hidden" onClick={onMenu} aria-label="Open navigation">
        <Menu />
      </Button>
      <div className="flex min-w-0 items-center gap-2 text-[13px]">
        <span className="text-muted">System</span>
        {health.data ? <HealthBadge status={health.data.status} reasons={health.data.reasons} /> : <span className="text-muted">…</span>}
      </div>
      <div className="ml-auto flex items-center gap-3 text-[12.5px]">
        {online !== undefined && (
          <span className="tabular hidden text-ink-2 sm:inline">
            <span className="font-semibold text-ink">{online}</span> online
          </span>
        )}
        <span className="flex items-center gap-1.5 text-ink-2" title={connected ? 'Live updates connected' : 'Live updates reconnecting'}>
          <span aria-hidden className={cn('size-2 rounded-full', connected ? 'live-dot bg-good' : 'bg-muted')} />
          <span className="hidden sm:inline">{connected ? 'Live' : 'Reconnecting'}</span>
        </span>
        <span className="hidden max-w-[200px] truncate text-ink-2 lg:inline" title={session?.admin.email}>
          {session?.admin.displayName} · {session?.admin.role}
        </span>
        <Button variant="ghost" size="sm" onClick={() => void signOut()} aria-label="Sign out" title="Sign out">
          <LogOut />
        </Button>
      </div>
    </header>
  );
}

export function Shell() {
  const { session, loading } = useSession();
  const navigate = useNavigate();
  const loc = useLocation();
  const [menu, setMenu] = React.useState(false);
  React.useEffect(() => setMenu(false), [loc.pathname]);
  if (loading) return <Spinner label="Checking your session" />;
  if (!session) return <Navigate to="/login" replace />;
  if (session.state !== 'active') return <Navigate to="/sign-in/step" replace />;

  return (
    <LiveProvider onAlertClick={(id) => navigate(`/alerts/${id}`)}>
      <div className="flex min-h-screen">
        <aside className="sticky top-0 hidden h-screen w-[232px] shrink-0 flex-col border-r border-line bg-surface/40 p-3 md:flex">
          <div className="mb-4 flex items-center gap-2 px-2 pt-1 text-[14px] font-semibold">
            <img src="/favicon.svg" alt="" className="size-7" />
            Sentinel
          </div>
          <Nav />
          <p className="mt-auto px-2 text-[11px] leading-4 text-muted">
            IP geolocation by{' '}
            <a className="underline hover:text-ink" href="https://db-ip.com" target="_blank" rel="noreferrer noopener">
              DB-IP
            </a>{' '}
            (CC BY 4.0)
          </p>
        </aside>
        {menu && (
          <div className="fixed inset-0 z-40 md:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
            <button className="absolute inset-0 bg-black/60" aria-label="Close navigation" onClick={() => setMenu(false)} />
            <div className="absolute inset-y-0 left-0 w-[260px] border-r border-line bg-surface p-3">
              <div className="mb-4 flex items-center justify-between px-2">
                <span className="text-[14px] font-semibold">Sentinel</span>
                <Button variant="ghost" size="sm" onClick={() => setMenu(false)} aria-label="Close navigation">
                  <X />
                </Button>
              </div>
              <Nav onNavigate={() => setMenu(false)} />
            </div>
          </div>
        )}
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar onMenu={() => setMenu(true)} />
          <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-5 md:px-6">
            <Outlet />
          </main>
        </div>
      </div>
    </LiveProvider>
  );
}
