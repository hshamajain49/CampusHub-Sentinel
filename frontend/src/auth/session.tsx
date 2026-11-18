// The signed-in developer. The session itself is an HttpOnly cookie; this only mirrors GET /api/auth/session.
// Any API answer of UNAUTHENTICATED (expired, signed out elsewhere, deactivated) drops to the sign-in page.
import * as React from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, onApiError, post } from '@/lib/api';
import type { SessionView } from '@/lib/types';

interface SessionCtx {
  session: SessionView | null;
  loading: boolean;
  refresh: () => Promise<SessionView | null>;
  signOut: () => Promise<void>;
}

const Ctx = React.createContext<SessionCtx | null>(null);

export function useSession(): SessionCtx {
  const c = React.useContext(Ctx);
  if (!c) throw new Error('useSession outside SessionProvider');
  return c;
}

/** For pages under the guard: the session is always active there. */
export function useAdmin() {
  const { session } = useSession();
  if (!session) throw new Error('useAdmin requires a session');
  return session.admin;
}

async function fetchSession(): Promise<SessionView | null> {
  try {
    return await api<SessionView>('/api/auth/session');
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['session'], queryFn: fetchSession, staleTime: 30_000, refetchInterval: 60_000, retry: false });

  React.useEffect(
    () =>
      onApiError((err) => {
        if (err.code === 'UNAUTHENTICATED') {
          qc.setQueryData(['session'], null);
          qc.removeQueries({ predicate: (query) => query.queryKey[0] !== 'session' });
        }
        if (err.code === 'STEP_REQUIRED') void qc.invalidateQueries({ queryKey: ['session'] });
      }),
    [qc],
  );

  const value = React.useMemo<SessionCtx>(
    () => ({
      session: q.data ?? null,
      loading: q.isPending,
      refresh: async () => (await q.refetch()).data ?? null,
      signOut: async () => {
        await post('/api/auth/logout').catch(() => undefined);
        qc.setQueryData(['session'], null);
        qc.removeQueries({ predicate: (query) => query.queryKey[0] !== 'session' });
      },
    }),
    [q, qc],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
