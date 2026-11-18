export interface SessionInfo {
  id: string;
  state: 'password_change' | 'mfa_enroll' | 'mfa_verify' | 'active';
  createdAt: Date;
  expiresAt: Date;
  mfaVerifiedAt: Date | null;
  reauthAt: Date | null;
}

export interface AdminInfo {
  id: string;
  email: string;
  displayName: string;
  role: 'owner' | 'analyst';
  mustChangePassword: boolean;
  totpEnabled: boolean;
}

declare global {
  namespace Express {
    interface Request {
      id: string;
      valid: { params: any; query: any; body: any };
      session?: SessionInfo;
      admin?: AdminInfo;
      /** Set by requireSignature on /ingest/v1 (server-to-server). */
      ingestApp?: { id: string; slug: string };
      rawBody?: Buffer;
    }
  }
}

export {};
