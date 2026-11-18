// Developer passwords: argon2id (OWASP Password Storage Cheat Sheet: m=19 MiB, t=2, p=1), at least 12 characters,
// not a common password and not built from the email address. No composition rules (NIST SP 800-63B §5.1.1.2).
import { hash, verify } from '@node-rs/argon2';
import { z } from 'zod';

const ARGON2 = { algorithm: 2 /* Argon2id */, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;
export const MIN_PASSWORD_LENGTH = 12;

export function hashPassword(password: string): Promise<string> {
  return hash(password, ARGON2);
}

/** A hash of a random password: verifying against it when the email is unknown keeps the response time the same. */
let dummy: Promise<string> | undefined;
export async function verifyPassword(stored: string | null | undefined, password: string): Promise<boolean> {
  if (!stored) {
    dummy ??= hashPassword(`dummy-${Math.random()}`);
    await verify(await dummy, password).catch(() => false);
    return false;
  }
  try {
    return await verify(stored, password);
  } catch {
    return false;
  }
}

const COMMON = /^(password|passw0rd|p@ssw0rd|qwerty|letmein|welcome|admin|administrator|sentinel|campushub|changeme|iloveyou|monkey|dragon|football|secret)[\d!@#$%^&*._\-+=?]*$/i;
const COMMON_EXACT = new Set(['123456789012', '1234567890ab', 'qwertyuiop12', 'abcdefghijkl', '1q2w3e4r5t6y', 'aaaaaaaaaaaa']);

export function passwordProblem(password: string, email?: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  if (password.length > 128) return 'Use at most 128 characters.';
  const p = password.toLowerCase();
  if (COMMON.test(p) || COMMON_EXACT.has(p) || /^(.)\1+$/.test(p)) return 'This password is too common. Choose something harder to guess.';
  const local = email?.split('@')[0]?.toLowerCase();
  if (local && local.length >= 4 && p.includes(local)) return "Don't use your email address in your password.";
  return null;
}

export const newPasswordSchema = z.string().min(1).max(128);

/** Strong random password for new accounts (shown once by the CLI or the API). */
export function generatePassword(length = 20): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_';
  const n = alphabet.length;
  const limit = 256 - (256 % n); // rejection sampling: every symbol equally likely
  const bytes = new Uint8Array(length * 2);
  const out: string[] = [];
  while (out.length < length) {
    crypto.getRandomValues(bytes);
    for (const b of bytes) if (b < limit && out.length < length) out.push(alphabet[b % n]!);
  }
  return out.join('');
}
