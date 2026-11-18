// Session guard chain. Every /api route except sign-in declares the session state(s) it accepts; 'active' (every
// sign-in step done) is the default. Authorization is checked here on the server, never only in the dashboard.
import type { RequestHandler } from 'express';
import { config } from '../config/env.js';
import { appError } from '../errors/app-error.js';
import { clearSessionCookie, findSession, type SessionState } from '../modules/auth/sessions.js';
import type { AdminInfo } from '../types/express.js';
import { parseCookies } from './basics.js';

/** Reads the session cookie; a stale or forged cookie is cleared. Never fails the request by itself. */
export const loadSession: RequestHandler = async (req, res, next) => {
  const token = parseCookies(req.get('cookie'))[config.SESSION_COOKIE];
  if (!token) return next();
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    clearSessionCookie(res);
    return next();
  }
  const found = await findSession(token);
  if (!found) {
    clearSessionCookie(res);
    return next();
  }
  req.session = found.session;
  req.admin = found.admin;
  next();
};

export function requireSession(...states: SessionState[]): RequestHandler {
  const allowed = states.length ? states : (['active'] as SessionState[]);
  return (req, _res, next) => {
    if (!req.session || !req.admin) return next(appError('UNAUTHENTICATED'));
    if (!allowed.includes(req.session.state)) return next(appError('STEP_REQUIRED', undefined, { next: req.session.state }));
    next();
  };
}

export function requireRole(...roles: AdminInfo['role'][]): RequestHandler {
  return (req, _res, next) => {
    if (!req.admin || !roles.includes(req.admin.role)) return next(appError('FORBIDDEN'));
    next();
  };
}

/** Sensitive actions: the password and an authenticator code must have been confirmed in the last REAUTH_MINUTES. */
export const requireRecentReauth: RequestHandler = (req, _res, next) => {
  const at = req.session?.reauthAt;
  if (!at || Date.now() - new Date(at).getTime() > config.REAUTH_MINUTES * 60_000) return next(appError('REAUTH_REQUIRED'));
  next();
};
