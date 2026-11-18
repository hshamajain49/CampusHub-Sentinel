// Sensitive actions (blocks, allowlist, rules, developers, secret rotation) need a password + authenticator code from
// the last few minutes. `withReauth(fn)` runs fn; if the API answers REAUTH_REQUIRED it asks once, then retries.
import * as React from 'react';
import { KeyRound } from 'lucide-react';
import { ApiError, errorText, post } from '@/lib/api';
import { Button, Field, inputCls, Modal } from '@/components/ui';

type Pending = { resolve: () => void; reject: (e: unknown) => void };
const Ctx = React.createContext<(<T>(fn: () => Promise<T>) => Promise<T>) | null>(null);

export function useReauth() {
  const c = React.useContext(Ctx);
  if (!c) throw new Error('useReauth outside ReauthProvider');
  return c;
}

export function ReauthProvider({ children }: { children: React.ReactNode }) {
  const [pending, setPending] = React.useState<Pending | null>(null);
  const [password, setPassword] = React.useState('');
  const [code, setCode] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);

  const ask = React.useCallback(
    () =>
      new Promise<void>((resolve, reject) => {
        setPassword('');
        setCode('');
        setError(null);
        setPending({ resolve, reject });
      }),
    [],
  );

  const withReauth = React.useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn();
      } catch (e) {
        if (!(e instanceof ApiError) || e.code !== 'REAUTH_REQUIRED') throw e;
        await ask();
        return fn();
      }
    },
    [ask],
  );

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post('/api/auth/reauth', { password, code: code.replace(/\s+/g, '') });
      pending?.resolve();
      setPending(null);
    } catch (err) {
      setError(errorText(err));
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => {
    pending?.reject(new ApiError(403, 'REAUTH_CANCELLED', 'Cancelled.'));
    setPending(null);
  };

  return (
    <Ctx.Provider value={withReauth}>
      {children}
      <Modal open={!!pending} onClose={cancel} title="Confirm it's you">
        <form onSubmit={submit} className="grid gap-3">
          <p className="text-[13px] text-ink-2">This changes what Sentinel enforces or who can use it. Enter your password and a current authenticator code.</p>
          <Field label="Password">
            <input className={inputCls} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          </Field>
          <Field label="Authenticator code" error={error}>
            <input className={`${inputCls} font-mono tracking-[0.2em]`} inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} />
          </Field>
          <div className="mt-1 flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={cancel}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={busy} disabled={!password || code.replace(/\s+/g, '').length !== 6}>
              <KeyRound /> Confirm
            </Button>
          </div>
        </form>
      </Modal>
    </Ctx.Provider>
  );
}
