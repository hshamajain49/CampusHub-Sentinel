import { afterEach, describe, expect, it, vi } from 'vitest';
import { ago, bucketLabel, countryName, duration, flag, num, short } from './format';
import { api, ApiError, onApiError, post, qs } from './api';

describe('format', () => {
  it('numbers: full under 10,000, compact above', () => {
    expect(num(1234)).toBe('1,234');
    expect(short(9999)).toBe('9,999');
    expect(short(12_500)).toBe('12.5K');
    expect(num(null)).toBe('—');
  });
  it('durations and relative times', () => {
    expect(duration(42)).toBe('42s');
    expect(duration(125)).toBe('2m 05s');
    expect(duration(3720)).toBe('1h 02m');
    const now = Date.parse('2026-11-18T12:00:00Z');
    expect(ago('2026-11-18T11:59:55Z', now)).toBe('just now');
    expect(ago('2026-11-18T11:30:00Z', now)).toBe('30 min ago');
  });
  it('bucket labels, countries and flags', () => {
    expect(bucketLabel('2026-11-18T14:00', 'hour')).toBe('14:00');
    expect(bucketLabel('2026-11-08T00:00', 'day')).toBe('8 Nov');
    expect(countryName('IN')).toBe('India');
    expect(countryName('unknown')).toBe('Unknown');
    expect(flag('IN')).toBe('🇮🇳');
    expect(flag('xx1')).toBe('');
  });
});

describe('api client', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('builds query strings without empty values', () => {
    expect(qs({ range: '7d', status: ['open', 'acknowledged'], empty: '', none: undefined, list: [] })).toBe('?range=7d&status=open%2Cacknowledged');
    expect(qs({})).toBe('');
  });

  it('sends the CSRF header on state-changing requests only, same-origin credentials', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ data: { ok: true } }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await api('/api/x');
    await post('/api/y', { a: 1 });
    const [getCall, postCall] = fetchMock.mock.calls as unknown as [string, RequestInit][];
    expect((getCall![1].headers as Record<string, string>)['x-requested-with']).toBeUndefined();
    expect((postCall![1].headers as Record<string, string>)['x-requested-with']).toBe('sentinel');
    expect(postCall![1].credentials).toBe('same-origin');
  });

  it('turns error bodies into ApiError and tells listeners (session handling)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'UNAUTHENTICATED', message: 'Please sign in.' } }), { status: 401 })));
    const seen: string[] = [];
    const off = onApiError((e) => seen.push(e.code));
    await expect(api('/api/z')).rejects.toBeInstanceOf(ApiError);
    off();
    expect(seen).toEqual(['UNAUTHENTICATED']);
  });

  it('reports an unreachable server as NETWORK_ERROR', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('Failed to fetch'))));
    await expect(api('/api/z')).rejects.toMatchObject({ code: 'NETWORK_ERROR' });
  });
});
