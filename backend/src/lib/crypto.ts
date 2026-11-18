// One root secret (DATA_ENCRYPTION_KEY) → independent keys per purpose (HKDF), so a key used for one job can never
// decrypt or forge another's data. Encryption is AES-256-GCM with the purpose as additional authenticated data.
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { config } from '../config/env.js';

export type Purpose = 'totp-secret' | 'ingest-secret' | 'keyed-hash' | 'ip-hash';

const keys = new Map<Purpose, Buffer>();
function keyFor(purpose: Purpose): Buffer {
  let k = keys.get(purpose);
  if (!k) {
    k = Buffer.from(hkdfSync('sha256', Buffer.from(config.DATA_ENCRYPTION_KEY, 'base64'), 'campushub-sentinel', `${purpose}-v1`, 32));
    keys.set(purpose, k);
  }
  return k;
}

export function encrypt(plain: string, purpose: Purpose): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyFor(purpose), iv);
  cipher.setAAD(Buffer.from(purpose));
  const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), ct.toString('base64url'), cipher.getAuthTag().toString('base64url')].join('.');
}

export function decrypt(stored: string, purpose: Purpose): string {
  const [v, iv, ct, tag] = stored.split('.');
  if (v !== 'v1' || !iv || !ct || !tag) throw new Error('unknown ciphertext format');
  const decipher = createDecipheriv('aes-256-gcm', keyFor(purpose), Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(purpose));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
}

/** Keyed hash (HMAC-SHA256, base64url): stable for lookups, useless without the server key. */
export function keyedHash(value: string, purpose: 'keyed-hash' | 'ip-hash' = 'keyed-hash'): string {
  return createHmac('sha256', keyFor(purpose)).update(value).digest('base64url');
}

/** Opaque random token (session cookies, site keys). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  if (x.length !== y.length) {
    timingSafeEqual(y, y);
    return false;
  }
  return timingSafeEqual(x, y);
}
