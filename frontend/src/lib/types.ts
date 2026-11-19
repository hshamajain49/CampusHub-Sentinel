// Response shapes of the Sentinel API (backend/src/modules/*). Kept to what the dashboard reads.
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type SessionState = 'password_change' | 'mfa_enroll' | 'mfa_verify' | 'active';
export type Role = 'owner' | 'analyst';

export interface SessionView {
  state: SessionState;
  admin: { id: string; email: string; displayName: string; role: Role };
  expiresAt: string;
  reauthUntil: string | null;
  /** Authenticator codes are asked for (server MFA_MODE=required). */
  mfaRequired: boolean;
}

export interface Overview {
  range: { from: string; to: string; timezone: string };
  visitors: number;
  newVisitors: number;
  returningVisitors: number;
  sessions: number;
  pageViews: number;
  avgSessionSeconds: number;
  bounceRate: number;
  online: number;
  visitorsToday: number;
  visitorsThisWeek: number;
  visitorsThisMonth: number;
  allTime: { visitors: number; pageViews: number };
}

export interface TimePoint {
  bucket: string;
  visitors: number;
  sessions: number;
  pageViews: number;
}

export interface BreakdownRow {
  key: string;
  sessions: number;
  visitors?: number;
  pageViews?: number;
}

export interface VisitSession {
  id: string;
  visitor: { id: string; firstSeenAt: string; isNew: boolean };
  startedAt: string;
  lastActivityAt: string;
  durationSeconds: number;
  pageViews: number;
  entryPath: string;
  exitPath: string;
  referrer: { host: string | null; source: string };
  utm: { source: string | null; medium: string | null; campaign: string | null } | null;
  device: string;
  browser: string | null;
  os: string | null;
  viewport: string | null;
  location: { country: string | null; region: string | null; city: string | null };
  ip: string | null;
  userRef: string | null;
  simulated: boolean;
  online: boolean;
  pages?: { path: string; at: string }[];
}

export interface Health {
  status: 'healthy' | 'warning' | 'critical';
  reasons: string[];
  lastIngestAt: string | null;
}

export interface SecEvent {
  id: string;
  occurredAt: string;
  receivedAt?: string;
  category: string;
  severity: Severity;
  sourceIp: string | null;
  userRef: string | null;
  actorRole?: string | null;
  method: string | null;
  route: string | null;
  path?: string | null;
  statusCode: number | null;
  description: string;
  details?: Record<string, unknown>;
  simulated: boolean;
  alerts?: { id: string; title: string; status: string; severity: Severity }[];
}

export interface SecurityOverview {
  range: { from: string; to: string };
  health: Health;
  events: { total: number; simulated: number; bySeverity: Record<Severity, number> };
  alerts: { active: number; openBySeverity: Record<Exclude<Severity, 'info'>, number>; openedInRange: number };
  incidents: { open: number; resolved: number; false_positive: number; confirmed: number };
  suspiciousIps: number;
  activeBlocks: number;
  requests: number;
  topEndpoints: { endpoint: string; events: number; ips: number; worstSeverity: Severity }[];
  topCategories: { category: string; events: number }[];
  recentEvents: SecEvent[];
}

export interface Alert {
  id: string;
  rule: { key: string; name: string | null };
  groupKey: string;
  severity: Exclude<Severity, 'info'>;
  classification: 'suspicious' | 'policy_violation';
  title: string;
  detectionReason: string;
  status: 'open' | 'acknowledged' | 'resolved' | 'false_positive';
  occurrences: number;
  firstSeenAt: string;
  lastSeenAt: string;
  lastNotifiedAt: string | null;
  incident: { id: string; reference: string } | null;
  resolvedAt: string | null;
  resolvedBy: string | null;
  simulated: boolean;
  sampleEvents?: SecEvent[];
}

export interface Incident {
  id: string;
  reference: string;
  title: string;
  summary: string | null;
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
  severity: Exclude<Severity, 'info'>;
  classification: 'suspicious' | 'policy_violation' | 'unauthorized_access_verified' | 'compromise_confirmed';
  owner: { id: string; email: string; displayName: string } | null;
  createdBy: string;
  openedAt: string;
  updatedAt: string;
  resolvedAt: string | null;
  alertCount: number;
  alerts?: { id: string; ruleKey: string; title: string; severity: Severity; status: string; occurrences: number; firstSeenAt: string; lastSeenAt: string; simulated: boolean }[];
  notes?: { id: number; body: string; createdAt: string; author: { email: string; displayName: string } }[];
}

export interface SuspiciousIp {
  ip: string;
  eventCount: number;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  firstDetectedAt: string;
  lastDetectedAt: string;
  reasons: string[];
  blocked: boolean;
  allowlisted: boolean;
  openAlerts: number;
}

export interface Block {
  id: string;
  cidr: string;
  reason: string;
  source: 'manual' | 'rule';
  ruleKey: string | null;
  createdBy: string | null;
  createdAt: string;
  expiresAt: string;
  liftedAt: string | null;
  active: boolean;
}

export interface Rule {
  id: string;
  key: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: Exclude<Severity, 'info'>;
  classification: string;
  categories: string[];
  groupBy: string;
  threshold: number;
  windowSeconds: number;
  cooldownSeconds: number;
  autoBlock: boolean;
  blockSeconds: number;
  params: Record<string, unknown>;
  updatedAt: string;
}

export interface LiveSummary {
  at: string;
  apps: Record<
    string,
    { online: number; pageViews5m: number; lastPath: string | null; openAlerts: Record<'critical' | 'high' | 'medium' | 'low', number>; events5m: number; lastIngestAt: string | null }
  >;
}
