// Error catalogue: the dashboard chooses behaviour by code, never by message text.
export const ERRORS = {
  VALIDATION_ERROR: [400, 'Please check the highlighted fields.'],
  UNAUTHENTICATED: [401, 'Please sign in.'],
  /** Signed in, but a sign-in step (new password, authenticator) comes first; details.next says which. */
  STEP_REQUIRED: [403, 'Finish signing in first.'],
  FORBIDDEN: [403, "You don't have access to this."],
  CSRF_REJECTED: [403, 'This request was refused (cross-site request protection).'],
  REAUTH_REQUIRED: [403, 'Confirm your password and code to continue.'],
  NOT_FOUND: [404, 'Not found.'],
  CONFLICT: [409, 'This conflicts with the current state.'],
  INVALID_CREDENTIALS: [401, 'Incorrect email or password.'],
  INVALID_CODE: [422, "That code didn't work. Check your authenticator app and try again."],
  INVALID_CURRENT_PASSWORD: [422, 'Your current password is incorrect.'],
  WEAK_PASSWORD: [400, "This password doesn't meet the rules."],
  SETUP_EXPIRED: [409, 'This setup has expired. Start again.'],
  LAST_OWNER: [409, "There must always be at least one active owner."],
  SIGN_IN_LOCKED: [429, 'Too many failed attempts. Try again later.'],
  RATE_LIMITED: [429, 'Too many requests. Please wait a moment and try again.'],
  INTERNAL_ERROR: [500, 'Something went wrong. Please try again.'],
  SERVICE_UNAVAILABLE: [503, 'Service temporarily unavailable.'],
} as const;

export type ErrorCode = keyof typeof ERRORS;

export class AppError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly details: unknown = null,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export function appError(code: ErrorCode, message?: string, details: unknown = null): AppError {
  const [status, fallback] = ERRORS[code];
  return new AppError(status, code, message ?? fallback, details);
}
