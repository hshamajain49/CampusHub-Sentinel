// Same-origin API calls. The session is an HttpOnly cookie the browser sends by itself; state-changing requests carry
// the CSRF header the API requires. Errors become ApiError with the server's code (the UI branches on codes only).
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details: any = null,
  ) {
    super(message);
    this.name = 'ApiError';
  }
  get fieldErrors(): Record<string, string[]> {
    return this.details?.fieldErrors ?? {};
  }
}

type Listener = (err: ApiError) => void;
const listeners = new Set<Listener>();
/** The session provider listens for UNAUTHENTICATED / STEP_REQUIRED anywhere in the app. */
export function onApiError(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function qs(params: Record<string, unknown>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) continue;
    p.set(k, Array.isArray(v) ? v.join(',') : String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

export async function api<T = any>(path: string, init: { method?: string; body?: unknown; raw?: boolean } = {}): Promise<T> {
  const method = init.method ?? 'GET';
  const headers: Record<string, string> = { accept: 'application/json' };
  if (method !== 'GET') headers['x-requested-with'] = 'sentinel';
  if (init.body !== undefined) headers['content-type'] = 'application/json';
  let res: Response;
  try {
    res = await fetch(path, { method, headers, body: init.body === undefined ? undefined : JSON.stringify(init.body), credentials: 'same-origin' });
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', 'Sentinel is unreachable. Check your connection.');
  }
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const e = body?.error;
    const err = new ApiError(res.status, e?.code ?? 'INTERNAL_ERROR', e?.message ?? 'Something went wrong.', e?.details ?? null);
    for (const l of listeners) l(err);
    throw err;
  }
  return (init.raw ? body : (body?.data ?? body)) as T;
}

export const post = <T = any>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body: body ?? {} });
export const patch = <T = any>(path: string, body: unknown) => api<T>(path, { method: 'PATCH', body });
export const put = <T = any>(path: string, body: unknown) => api<T>(path, { method: 'PUT', body });
export const del = <T = any>(path: string) => api<T>(path, { method: 'DELETE' });
export const list = <T = any>(path: string) => api<{ data: T[]; meta: { page: number; pageSize: number; total: number; totalPages: number } }>(path, { raw: true });

export const errorText = (e: unknown) => (e instanceof ApiError ? e.message : 'Something went wrong.');
