// Sign-in: email + password, then whichever steps the server says are open (authenticator code, new password,
// authenticator setup). The server decides the order; this page renders the current step from the session state.
import * as React from 'react';
import { Navigate, useNavigate } from 'react-router';
import { Copy, Download, KeyRound, LogIn, ShieldCheck, Smartphone } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorText, post } from '@/lib/api';
import { Button, Field, inputCls, Spinner } from '@/components/ui';
import { useSession } from './session';

function Frame({ title, subtitle, icon, children }: { title: string; subtitle?: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-[400px]">
        <div className="mb-5 flex items-center gap-2.5 text-[14px] font-semibold text-ink-2">
          <img src="/favicon.svg" alt="" className="size-7" /> CampusHub Sentinel
        </div>
        <div className="card p-6">
          <div className="mb-4 grid size-11 place-items-center rounded-[12px] bg-primary-soft text-primary [&_svg]:size-5">{icon}</div>
          <h1 className="text-[19px] font-semibold">{title}</h1>
          {subtitle && <p className="mt-1 text-[13px] text-ink-2">{subtitle}</p>}
          <div className="mt-5">{children}</div>
        </div>
        <p className="mt-4 text-center text-[12px] text-muted">For the CampusHub development team only. Every sign-in is recorded.</p>
      </div>
    </div>
  );
}

export function LoginPage() {
  const { session, loading, refresh } = useSession();
  const navigate = useNavigate();
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  if (loading) return <Spinner />;
  if (session) return <Navigate to={session.state === 'active' ? '/' : '/sign-in/step'} replace />;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await post('/api/auth/login', { email, password });
      await refresh();
      navigate('/sign-in/step', { replace: true });
    } catch (err) {
      setError(errorText(err));
      setPassword('');
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="Sign in" subtitle="Security and analytics monitoring for CampusHub." icon={<LogIn />}>
      <form onSubmit={submit} className="grid gap-4" noValidate>
        <Field label="Email">
          <input className={inputCls} type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required />
        </Field>
        <Field label="Password" error={error}>
          <input className={inputCls} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </Field>
        <Button type="submit" variant="primary" loading={busy} disabled={!email || !password}>
          Continue
        </Button>
      </form>
    </Frame>
  );
}

/** Renders the open sign-in step; when the session becomes active, goes to the dashboard. */
export function StepPage() {
  const { session, loading } = useSession();
  const [codes, setCodes] = React.useState<string[] | null>(null);
  if (loading) return <Spinner />;
  if (!session) return <Navigate to="/login" replace />;
  if (codes) return <RecoveryCodes codes={codes} />;
  if (session.state === 'active') return <Navigate to="/" replace />;
  if (session.state === 'mfa_verify') return <VerifyStep />;
  if (session.state === 'password_change') return <PasswordStep />;
  return <EnrolStep onCodes={setCodes} />;
}

function SignOutLink() {
  const { signOut } = useSession();
  return (
    <button type="button" onClick={() => void signOut()} className="mt-3 w-full text-center text-[12.5px] text-muted hover:text-ink">
      Sign out
    </button>
  );
}

function VerifyStep() {
  const { refresh } = useSession();
  const [recovery, setRecovery] = React.useState(false);
  const [code, setCode] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ usedRecoveryCode: boolean; recoveryCodesLeft: number }>('/api/auth/mfa/verify', { code: code.replace(/\s+/g, '') });
      if (r.usedRecoveryCode) toast.warning(`Recovery code used: ${r.recoveryCodesLeft} left.`);
      await refresh();
    } catch (err) {
      setError(errorText(err));
      setCode('');
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="Two-step verification" subtitle={recovery ? 'Enter one of your recovery codes. Each works once.' : 'Enter the 6-digit code from your authenticator app.'} icon={<ShieldCheck />}>
      <form onSubmit={submit} className="grid gap-4">
        <Field label={recovery ? 'Recovery code' : 'Code'} error={error}>
          <input
            className={`${inputCls} font-mono text-[16px] tracking-[0.25em]`}
            inputMode={recovery ? 'text' : 'numeric'}
            autoComplete="one-time-code"
            maxLength={recovery ? 11 : 7}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            autoFocus
          />
        </Field>
        <Button type="submit" variant="primary" loading={busy} disabled={!code}>
          Verify
        </Button>
        <button type="button" className="text-[12.5px] text-primary hover:underline" onClick={() => (setRecovery((v) => !v), setCode(''), setError(null))}>
          {recovery ? 'Use the authenticator app' : 'Lost your phone? Use a recovery code'}
        </button>
      </form>
      <SignOutLink />
    </Frame>
  );
}

function PasswordStep() {
  const { refresh } = useSession();
  const [current, setCurrent] = React.useState('');
  const [next, setNext] = React.useState('');
  const [confirm, setConfirm] = React.useState('');
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const [busy, setBusy] = React.useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (next !== confirm) return setErrors({ confirm: 'The passwords do not match.' });
    setBusy(true);
    setErrors({});
    try {
      await post('/api/auth/password', { currentPassword: current, newPassword: next });
      await refresh();
    } catch (err) {
      const fe = err instanceof ApiError ? err.fieldErrors : {};
      setErrors({ current: fe.currentPassword?.[0] ?? '', next: fe.newPassword?.[0] ?? (fe.currentPassword ? '' : errorText(err)) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame title="Choose a new password" subtitle="Replace the temporary password you were given." icon={<KeyRound />}>
      <form onSubmit={submit} className="grid gap-4">
        <Field label="Temporary password" error={errors.current || null}>
          <input className={inputCls} type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} autoFocus />
        </Field>
        <Field label="New password" hint="At least 12 characters. A passphrase works well." error={errors.next || null}>
          <input className={inputCls} type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Field label="Confirm new password" error={errors.confirm || null}>
          <input className={inputCls} type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </Field>
        <Button type="submit" variant="primary" loading={busy} disabled={!current || !next || !confirm}>
          Update password
        </Button>
      </form>
      <SignOutLink />
    </Frame>
  );
}

function EnrolStep({ onCodes }: { onCodes: (c: string[]) => void }) {
  const { refresh } = useSession();
  const [setup, setSetup] = React.useState<{ secret: string; qrSvg: string } | null>(null);
  const [code, setCode] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      setSetup(await post('/api/auth/mfa/setup'));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  const enable = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post<{ recoveryCodes: string[] }>('/api/auth/mfa/enable', { code: code.replace(/\s+/g, '') });
      onCodes(r.recoveryCodes); // the session is active now; show the codes before leaving
      void refresh();
    } catch (err) {
      setError(errorText(err));
      setCode('');
      if (err instanceof ApiError && err.code === 'SETUP_EXPIRED') setSetup(null);
    } finally {
      setBusy(false);
    }
  };
  if (!setup) {
    return (
      <Frame title="Set up two-step verification" subtitle="Sentinel requires an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password…)." icon={<Smartphone />}>
        {error && <p className="mb-3 text-[12.5px] text-critical-text">{error}</p>}
        <Button variant="primary" className="w-full" onClick={() => void start()} loading={busy}>
          Start
        </Button>
        <SignOutLink />
      </Frame>
    );
  }
  return (
    <Frame title="Scan with your authenticator app" subtitle="Then enter the 6-digit code it shows." icon={<Smartphone />}>
      <div className="grid justify-items-center gap-3">
        {/* An <img> never runs script inside the SVG. */}
        <img src={`data:image/svg+xml;base64,${btoa(setup.qrSvg)}`} alt="QR code for your authenticator app" className="size-44 rounded-[10px] bg-white p-1" />
        <details className="w-full text-[12.5px] text-muted">
          <summary className="cursor-pointer text-primary">Can't scan? Enter the key</summary>
          <div className="mt-2 flex items-center gap-2 rounded-[8px] bg-surface-2 px-3 py-2">
            <code className="min-w-0 flex-1 break-all font-mono text-ink">{setup.secret}</code>
            <Button size="sm" variant="ghost" aria-label="Copy key" onClick={() => void navigator.clipboard?.writeText(setup.secret.replace(/\s+/g, ''))}>
              <Copy />
            </Button>
          </div>
        </details>
      </div>
      <form onSubmit={enable} className="mt-4 grid gap-4">
        <Field label="Code from the app" error={error}>
          <input className={`${inputCls} font-mono text-[16px] tracking-[0.25em]`} inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} />
        </Field>
        <Button type="submit" variant="primary" loading={busy} disabled={code.replace(/\s+/g, '').length !== 6}>
          Turn on two-step verification
        </Button>
      </form>
    </Frame>
  );
}

function RecoveryCodes({ codes }: { codes: string[] }) {
  const navigate = useNavigate();
  const [saved, setSaved] = React.useState(false);
  const text = `CampusHub Sentinel recovery codes (each works once)\n\n${codes.join('\n')}\n`;
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: 'sentinel-recovery-codes.txt' });
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  };
  return (
    <Frame title="Save your recovery codes" subtitle="If you lose your phone, each code signs you in once. They won't be shown again." icon={<KeyRound />}>
      <ul className="grid grid-cols-2 gap-x-4 gap-y-1 rounded-[10px] border border-line bg-surface-2 px-4 py-3 font-mono text-[13.5px]">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <Button onClick={() => void navigator.clipboard?.writeText(text).then(() => toast.success('Copied.'))}>
          <Copy /> Copy
        </Button>
        <Button onClick={download}>
          <Download /> Download
        </Button>
      </div>
      <label className="mt-4 flex items-center gap-2 text-[13px]">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} className="size-4 accent-[var(--primary)]" />
        I've saved these codes somewhere safe.
      </label>
      <Button variant="primary" className="mt-4 w-full" disabled={!saved} onClick={() => navigate('/', { replace: true })}>
        Continue to the dashboard
      </Button>
    </Frame>
  );
}
