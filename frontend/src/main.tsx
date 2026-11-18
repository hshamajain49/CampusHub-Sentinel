import * as React from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, Link, RouterProvider } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { ApiError } from '@/lib/api';
import { SessionProvider } from '@/auth/session';
import { ReauthProvider } from '@/auth/reauth';
import { LoginPage, StepPage } from '@/auth/sign-in';
import { Shell } from '@/layout/shell';
import { OverviewPage } from '@/pages/overview';
import { VisitorsPage } from '@/pages/visitors';
import { TrafficPage } from '@/pages/traffic';
import { AlertPage, ThreatsPage } from '@/pages/threats';
import { EventsPage } from '@/pages/events';
import { IpPage, IpsPage } from '@/pages/ips';
import { IncidentPage, IncidentsPage } from '@/pages/incidents';
import { AuditPage } from '@/pages/audit';
import { SettingsPage } from '@/pages/settings';
import './styles.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 20_000,
      refetchOnWindowFocus: true,
      // Client errors (401/403/404/422) won't fix themselves; retry only network and server errors.
      retry: (n, e) => !(e instanceof ApiError && e.status >= 400 && e.status < 500) && n < 2,
    },
  },
});

function NotFound() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-[20px] font-semibold">Page not found</h1>
      <Link to="/" className="mt-2 inline-block text-primary hover:underline">
        Back to the overview
      </Link>
    </div>
  );
}

const router = createBrowserRouter([
  { path: '/login', element: <LoginPage /> },
  { path: '/sign-in/step', element: <StepPage /> },
  {
    element: <Shell />,
    children: [
      { path: '/', element: <OverviewPage /> },
      { path: '/visitors', element: <VisitorsPage /> },
      { path: '/traffic', element: <TrafficPage /> },
      { path: '/threats', element: <ThreatsPage /> },
      { path: '/alerts/:id', element: <AlertPage /> },
      { path: '/events', element: <EventsPage /> },
      { path: '/ips', element: <IpsPage /> },
      { path: '/ips/:ip', element: <IpPage /> },
      { path: '/incidents', element: <IncidentsPage /> },
      { path: '/incidents/:id', element: <IncidentPage /> },
      { path: '/audit', element: <AuditPage /> },
      { path: '/settings', element: <SettingsPage /> },
      { path: '*', element: <NotFound /> },
    ],
  },
]);

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <SessionProvider>
        <ReauthProvider>
          <RouterProvider router={router} />
        </ReauthProvider>
      </SessionProvider>
      <Toaster theme="dark" position="top-right" richColors closeButton />
    </QueryClientProvider>
  </React.StrictMode>,
);
