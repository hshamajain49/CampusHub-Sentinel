-- migrate:up
-- =====================================================================
-- CampusHub Sentinel: core schema.
--   administrators   developer accounts (argon2id, mandatory TOTP), sessions, sign-in throttle
--   applications     monitored apps (CampusHub) and their ingestion credentials
--   analytics        visitors, sessions, page views (privacy: random visitor UUID, truncated IP + keyed hash)
--   security         events (immutable), detection rules, alerts, incidents, suspicious IPs, blocks, allowlist
--   audit_logs       every dashboard sign-in and change (append-only, see the next migration)
-- Integrity rules live here as constraints, so a bug in the API can't store an impossible row.
-- =====================================================================

create function public.set_updated_at() returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

-- ───────────────────────────── administrators ─────────────────────────────
create table public.administrator_accounts (
  id                    uuid        primary key default gen_random_uuid(),
  email                 text        not null check (email = lower(btrim(email)) and email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  display_name          text        not null check (length(btrim(display_name)) between 2 and 100),
  role                  text        not null check (role in ('owner', 'analyst')),
  password_hash         text        not null,
  must_change_password  boolean     not null default true,
  -- TOTP: AES-256-GCM encrypted secret; last accepted time step (a code works once); SHA-256 hashes of recovery codes
  totp_secret           text,
  totp_pending_secret   text,
  totp_pending_at       timestamptz,
  totp_enabled_at       timestamptz,
  totp_last_step        bigint      not null default 0,
  recovery_codes        text[]      not null default '{}',
  mfa_failures          integer     not null default 0 check (mfa_failures >= 0),
  mfa_locked_until      timestamptz,
  is_active             boolean     not null default true,
  last_login_at         timestamptz,
  last_login_ip         inet,
  created_by            uuid        references public.administrator_accounts (id),
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now(),
  constraint administrator_enabled_has_secret check (totp_enabled_at is null or totp_secret is not null)
);
create unique index administrator_accounts_email_key on public.administrator_accounts (email);
create trigger administrator_accounts_set_updated_at before update on public.administrator_accounts
  for each row execute function public.set_updated_at();

-- Opaque session tokens: only their SHA-256 is stored. A session moves through the sign-in steps to 'active'.
create table public.administrator_sessions (
  id             uuid        primary key default gen_random_uuid(),
  admin_id       uuid        not null references public.administrator_accounts (id),
  token_hash     text        not null unique,
  state          text        not null check (state in ('password_change', 'mfa_enroll', 'mfa_verify', 'active')),
  created_at     timestamptz not null default now(),
  last_seen_at   timestamptz not null default now(),
  expires_at     timestamptz not null,
  mfa_verified_at timestamptz,                 -- this session passed the authenticator step
  reauth_at      timestamptz,                  -- last step-up (password + code) for sensitive actions
  ip             inet,
  user_agent     text        check (length(user_agent) <= 300),
  revoked_at     timestamptz,
  constraint administrator_sessions_expiry check (expires_at > created_at)
);
create index administrator_sessions_admin_idx on public.administrator_sessions (admin_id, created_at desc);
create index administrator_sessions_expires_idx on public.administrator_sessions (expires_at);

-- Failed sign-ins per account and per IP (keys are HMACs; unknown emails are throttled like real ones).
create table public.login_throttle (
  key                text        primary key,
  failures           integer     not null default 0 check (failures >= 0),
  window_started_at  timestamptz not null default now(),
  locked_until       timestamptz,
  updated_at         timestamptz not null default now()
);
create index login_throttle_updated_idx on public.login_throttle (updated_at);

-- ───────────────────────────── monitored applications ─────────────────────────────
create table public.monitored_applications (
  id                        uuid        primary key default gen_random_uuid(),
  slug                      text        not null unique check (slug ~ '^[a-z][a-z0-9-]{1,40}$'),
  name                      text        not null check (length(btrim(name)) between 2 and 80),
  -- Browser analytics: the public site key and the origins allowed to send page views
  site_key                  text        not null unique,
  allowed_origins           text[]      not null default '{}',
  analytics_consent         text        not null default 'notice' check (analytics_consent in ('notice', 'opt-in')),
  -- Server-to-server ingestion: HMAC key id (sent in the header) and the AES-GCM encrypted secret
  ingest_key_id             text        not null unique,
  ingest_secret             text        not null,
  ingest_secret_rotated_at  timestamptz not null default now(),
  retention_analytics_days  integer     not null default 395 check (retention_analytics_days between 30 and 1095),
  retention_security_days   integer     not null default 90 check (retention_security_days between 30 and 730),
  is_active                 boolean     not null default true,
  last_ingest_at            timestamptz,
  created_at                timestamptz not null default now(),
  updated_at                timestamptz not null default now()
);
create trigger monitored_applications_set_updated_at before update on public.monitored_applications
  for each row execute function public.set_updated_at();

-- ───────────────────────────── analytics ─────────────────────────────
create table public.analytics_visitors (
  id              bigint      generated always as identity primary key,
  app_id          uuid        not null references public.monitored_applications (id),
  visitor_key     uuid        not null,           -- random UUID kept in the visitor's browser; not a fingerprint
  first_seen_at   timestamptz not null default now(),
  last_seen_at    timestamptz not null default now(),
  sessions_count  integer     not null default 0 check (sessions_count >= 0),
  unique (app_id, visitor_key)
);
create index analytics_visitors_first_seen_idx on public.analytics_visitors (app_id, first_seen_at desc);

create table public.analytics_sessions (
  id                uuid        primary key default gen_random_uuid(),
  app_id            uuid        not null references public.monitored_applications (id),
  visitor_id        bigint      not null references public.analytics_visitors (id) on delete cascade,
  started_at        timestamptz not null default now(),
  last_activity_at  timestamptz not null default now(),
  is_new_visitor    boolean     not null,
  entry_path        text        not null check (length(entry_path) <= 300),
  exit_path         text        not null check (length(exit_path) <= 300),
  page_views        integer     not null default 1 check (page_views >= 0),
  referrer_host     text        check (length(referrer_host) <= 253),
  referrer_source   text        not null default 'direct' check (referrer_source in ('direct', 'search', 'social', 'referral', 'campaign', 'internal')),
  utm_source        text        check (length(utm_source) <= 100),
  utm_medium        text        check (length(utm_medium) <= 100),
  utm_campaign      text        check (length(utm_campaign) <= 100),
  device_type       text        not null default 'unknown' check (device_type in ('desktop', 'mobile', 'tablet', 'bot', 'unknown')),
  browser           text        check (length(browser) <= 40),
  browser_version   text        check (length(browser_version) <= 20),
  os                text        check (length(os) <= 40),
  viewport          text        check (viewport in ('xs', 'sm', 'md', 'lg', 'xl')),
  country           char(2),
  region            text        check (length(region) <= 80),
  city              text        check (length(city) <= 80),
  ip_truncated      inet,                          -- IPv4 /24, IPv6 /48
  ip_hash           text,                          -- keyed hash of the full IP (uniqueness only; not reversible)
  user_ref          text        check (length(user_ref) <= 64),  -- reported by the browser; unverified
  simulated         boolean     not null default false,
  constraint analytics_sessions_activity check (last_activity_at >= started_at)
);
create index analytics_sessions_started_idx on public.analytics_sessions (app_id, started_at desc);
create index analytics_sessions_activity_idx on public.analytics_sessions (app_id, last_activity_at desc);
create index analytics_sessions_visitor_idx on public.analytics_sessions (visitor_id, started_at desc);

create table public.analytics_events (
  id           bigint      generated always as identity primary key,
  app_id       uuid        not null references public.monitored_applications (id),
  session_id   uuid        not null references public.analytics_sessions (id) on delete cascade,
  occurred_at  timestamptz not null default now(),
  path         text        not null check (length(path) <= 300)
);
create index analytics_events_time_idx on public.analytics_events (app_id, occurred_at desc);
create index analytics_events_session_idx on public.analytics_events (session_id, occurred_at);
create index analytics_events_path_idx on public.analytics_events (app_id, path, occurred_at desc);

-- Per-minute request counters sent by the monitored API (traffic spikes, "total requests").
create table public.traffic_minutes (
  app_id      uuid        not null references public.monitored_applications (id),
  minute      timestamptz not null check (date_trunc('minute', minute) = minute),
  requests    integer     not null default 0 check (requests >= 0),
  status_2xx  integer     not null default 0 check (status_2xx >= 0),
  status_3xx  integer     not null default 0 check (status_3xx >= 0),
  status_4xx  integer     not null default 0 check (status_4xx >= 0),
  status_5xx  integer     not null default 0 check (status_5xx >= 0),
  primary key (app_id, minute)
);

-- ───────────────────────────── security ─────────────────────────────
-- Immutable once written (next migration). category is "<area>.<what>", e.g. auth.login_failed, authz.denied.
create table public.security_events (
  id                uuid        primary key default gen_random_uuid(),
  app_id            uuid        not null references public.monitored_applications (id),
  event_id          text        not null check (length(event_id) between 8 and 64),  -- the sender's id: duplicates are dropped
  occurred_at       timestamptz not null,
  received_at       timestamptz not null default now(),
  category          text        not null check (category ~ '^[a-z][a-z_]*\.[a-z][a-z_]*$' and length(category) <= 60),
  severity          text        not null check (severity in ('info', 'low', 'medium', 'high', 'critical')),
  source_ip         inet,
  user_ref          text        check (length(user_ref) <= 64),
  actor_role        text        check (length(actor_role) <= 40),
  method            text        check (method in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')),
  route             text        check (length(route) <= 200),   -- route template, e.g. /api/v1/bookings/:bookingId
  path              text        check (length(path) <= 300),
  status_code       integer     check (status_code between 100 and 599),
  description       text        not null check (length(description) between 1 and 500),
  details           jsonb       not null default '{}' check (jsonb_typeof(details) = 'object' and pg_column_size(details) <= 8192),
  simulated         boolean     not null default false,
  unique (app_id, event_id)
);
create index security_events_time_idx on public.security_events (app_id, occurred_at desc);
create index security_events_ip_idx on public.security_events (source_ip, occurred_at desc) where source_ip is not null;
create index security_events_category_idx on public.security_events (category, occurred_at desc);
create index security_events_user_idx on public.security_events (user_ref, occurred_at desc) where user_ref is not null;
create index security_events_severity_idx on public.security_events (severity, occurred_at desc) where severity in ('high', 'critical');

create table public.detection_rules (
  id                uuid        primary key default gen_random_uuid(),
  key               text        not null unique check (key ~ '^[a-z][a-z0-9_]{2,60}$'),
  name              text        not null check (length(name) between 3 and 120),
  description       text        not null,
  enabled           boolean     not null default true,
  severity          text        not null check (severity in ('low', 'medium', 'high', 'critical')),
  -- Rules only ever claim "suspicious" or "policy_violation"; verified access and compromise are set by a person.
  classification    text        not null default 'suspicious' check (classification in ('suspicious', 'policy_violation')),
  categories        text[]      not null check (cardinality(categories) >= 1),
  group_by          text        not null check (group_by in ('source_ip', 'user_ref', 'account', 'source_ip_route', 'app')),
  threshold         integer     not null check (threshold between 1 and 100000),  -- matches when count >= threshold
  window_seconds    integer     not null check (window_seconds between 10 and 86400),
  distinct_field    text        check (distinct_field in ('account', 'source_ip', 'user_ref', 'route')),
  cooldown_seconds  integer     not null default 1800 check (cooldown_seconds between 0 and 86400),
  auto_block        boolean     not null default false,
  block_seconds     integer     not null default 900 check (block_seconds between 60 and 86400),
  params            jsonb       not null default '{}' check (jsonb_typeof(params) = 'object'),
  updated_by        uuid        references public.administrator_accounts (id),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create trigger detection_rules_set_updated_at before update on public.detection_rules
  for each row execute function public.set_updated_at();

create sequence public.incident_reference_seq;

create table public.security_incidents (
  id              uuid        primary key default gen_random_uuid(),
  reference       text        not null unique default 'INC-' || lpad(nextval('public.incident_reference_seq')::text, 4, '0'),
  app_id          uuid        not null references public.monitored_applications (id),
  title           text        not null check (length(btrim(title)) between 3 and 200),
  summary         text        check (length(summary) <= 5000),
  status          text        not null default 'new' check (status in ('new', 'investigating', 'resolved', 'false_positive')),
  severity        text        not null check (severity in ('low', 'medium', 'high', 'critical')),
  classification  text        not null default 'suspicious'
                  check (classification in ('suspicious', 'policy_violation', 'unauthorized_access_verified', 'compromise_confirmed')),
  owner_id        uuid        references public.administrator_accounts (id),
  created_by      uuid        references public.administrator_accounts (id),   -- null: opened by the detection engine
  opened_at       timestamptz not null default now(),
  resolved_at     timestamptz,
  updated_at      timestamptz not null default now(),
  constraint security_incidents_resolved check ((status in ('resolved', 'false_positive')) = (resolved_at is not null))
);
create index security_incidents_status_idx on public.security_incidents (status, opened_at desc);
create trigger security_incidents_set_updated_at before update on public.security_incidents
  for each row execute function public.set_updated_at();

-- Investigation notes: append-only (next migration).
create table public.incident_notes (
  id           bigint      generated always as identity primary key,
  incident_id  uuid        not null references public.security_incidents (id),
  author_id    uuid        not null references public.administrator_accounts (id),
  body         text        not null check (length(btrim(body)) between 1 and 5000),
  created_at   timestamptz not null default now()
);
create index incident_notes_incident_idx on public.incident_notes (incident_id, created_at);

create table public.security_alerts (
  id                uuid        primary key default gen_random_uuid(),
  app_id            uuid        not null references public.monitored_applications (id),
  rule_id           uuid        references public.detection_rules (id),
  rule_key          text        not null,
  group_key         text        not null check (length(group_key) <= 300),
  severity          text        not null check (severity in ('low', 'medium', 'high', 'critical')),
  classification    text        not null check (classification in ('suspicious', 'policy_violation')),
  title             text        not null check (length(title) <= 200),
  detection_reason  text        not null check (length(detection_reason) <= 1000),
  status            text        not null default 'open' check (status in ('open', 'acknowledged', 'resolved', 'false_positive')),
  occurrences       integer     not null default 1 check (occurrences >= 1),
  first_seen_at     timestamptz not null default now(),
  last_seen_at      timestamptz not null default now(),
  last_notified_at  timestamptz,
  incident_id       uuid        references public.security_incidents (id),
  resolved_at       timestamptz,
  resolved_by       uuid        references public.administrator_accounts (id),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  constraint security_alerts_seen check (last_seen_at >= first_seen_at),
  constraint security_alerts_resolved check ((status in ('resolved', 'false_positive')) = (resolved_at is not null))
);
-- One open alert per rule and group: repeats bump occurrences instead of creating duplicates.
create unique index security_alerts_open_key on public.security_alerts (app_id, rule_key, group_key) where status in ('open', 'acknowledged');
create index security_alerts_status_idx on public.security_alerts (status, last_seen_at desc);
create trigger security_alerts_set_updated_at before update on public.security_alerts
  for each row execute function public.set_updated_at();

-- A bounded sample of the events behind each alert (the engine keeps at most 50 per alert).
create table public.alert_events (
  alert_id  uuid not null references public.security_alerts (id) on delete cascade,
  event_id  uuid not null references public.security_events (id) on delete cascade,
  primary key (alert_id, event_id)
);
create index alert_events_event_idx on public.alert_events (event_id);

create table public.suspicious_ips (
  app_id             uuid          not null references public.monitored_applications (id),
  ip                 inet          not null,
  first_detected_at  timestamptz   not null default now(),
  last_detected_at   timestamptz   not null default now(),
  event_count        integer       not null default 0 check (event_count >= 0),
  risk_score         numeric(7, 2) not null default 0 check (risk_score >= 0),
  reasons            text[]        not null default '{}',
  primary key (app_id, ip)
);
create index suspicious_ips_risk_idx on public.suspicious_ips (app_id, risk_score desc);

-- Temporary blocks, enforced by the monitored app (it pulls the active list). At most 7 days per block.
create table public.ip_blocks (
  id          uuid        primary key default gen_random_uuid(),
  app_id      uuid        not null references public.monitored_applications (id),
  cidr        cidr        not null,
  reason      text        not null check (length(btrim(reason)) between 3 and 300),
  source      text        not null check (source in ('manual', 'rule')),
  rule_key    text,
  created_by  uuid        references public.administrator_accounts (id),
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null,
  lifted_at   timestamptz,
  lifted_by   uuid        references public.administrator_accounts (id),
  constraint ip_blocks_window check (expires_at > created_at and expires_at <= created_at + interval '7 days'),
  constraint ip_blocks_who check ((source = 'manual') = (created_by is not null))
);
create index ip_blocks_active_idx on public.ip_blocks (app_id, expires_at) where lifted_at is null;

-- Addresses that are never blocked (developers, the institution's network): protects against locking yourself out.
create table public.ip_allowlist (
  id          uuid        primary key default gen_random_uuid(),
  app_id      uuid        not null references public.monitored_applications (id),
  cidr        cidr        not null,
  note        text        not null check (length(btrim(note)) between 2 and 200),
  created_by  uuid        not null references public.administrator_accounts (id),
  created_at  timestamptz not null default now(),
  unique (app_id, cidr)
);

create table public.notification_preferences (
  admin_id           uuid        primary key references public.administrator_accounts (id),
  email_enabled      boolean     not null default true,
  min_severity       text        not null default 'high' check (min_severity in ('medium', 'high', 'critical')),
  quiet_hours_start  time,
  quiet_hours_end    time,
  updated_at         timestamptz not null default now(),
  constraint notification_quiet_hours check ((quiet_hours_start is null) = (quiet_hours_end is null))
);

create table public.notification_log (
  id          bigint      generated always as identity primary key,
  alert_id    uuid        not null references public.security_alerts (id) on delete cascade,
  admin_id    uuid        not null references public.administrator_accounts (id),
  channel     text        not null check (channel in ('email')),
  status      text        not null check (status in ('sent', 'failed', 'skipped')),
  error       text        check (length(error) <= 500),
  created_at  timestamptz not null default now()
);
create index notification_log_alert_idx on public.notification_log (alert_id, created_at desc);

-- ───────────────────────────── audit ─────────────────────────────
-- Append-only (next migration). admin_email is a snapshot, so entries stay readable whatever happens to the account.
create table public.audit_logs (
  id           bigint      generated always as identity primary key,
  occurred_at  timestamptz not null default now(),
  admin_id     uuid        references public.administrator_accounts (id),
  admin_email  text,
  action       text        not null check (action ~ '^[a-z][a-z_]*\.[a-z][a-z_]*$'),
  outcome      text        not null default 'success' check (outcome in ('success', 'failure')),
  target_type  text        check (length(target_type) <= 40),
  target_id    text        check (length(target_id) <= 100),
  ip           inet,
  user_agent   text        check (length(user_agent) <= 300),
  details      jsonb       not null default '{}' check (jsonb_typeof(details) = 'object' and pg_column_size(details) <= 4096)
);
create index audit_logs_time_idx on public.audit_logs (occurred_at desc);
create index audit_logs_admin_idx on public.audit_logs (admin_id, occurred_at desc);
create index audit_logs_action_idx on public.audit_logs (action, occurred_at desc);

-- ───────────────────────────── default detection rules (editable from Settings) ─────────────────────────────
insert into public.detection_rules
  (key, name, description, severity, categories, group_by, threshold, window_seconds, distinct_field, params) values
  ('brute_force_ip', 'Brute force from one IP',
   'More than 10 failed sign-ins from one IP address within 5 minutes.',
   'high', '{auth.login_failed}', 'source_ip', 11, 300, null, '{}'),
  ('password_spraying', 'Password spraying',
   'One IP address failed to sign in to 5 or more different accounts within 10 minutes.',
   'high', '{auth.login_failed}', 'source_ip', 5, 600, 'account', '{}'),
  ('account_under_attack', 'Account under attack',
   '10 or more failed sign-ins for one account from at least 3 IP addresses within 15 minutes.',
   'high', '{auth.login_failed}', 'account', 10, 900, null, '{"min_distinct_ips": 3}'),
  ('admin_probing', 'Admin area probing',
   '5 or more refused requests to the admin API from one IP address within 10 minutes.',
   'high', '{authz.denied}', 'source_ip', 5, 600, null, '{"route_prefix": "/api/v1/admin"}'),
  ('member_admin_api', 'Member calling Super Admin APIs',
   'A signed-in member was refused on an admin endpoint. Escalates to high at 3 within 10 minutes.',
   'medium', '{authz.denied}', 'user_ref', 1, 600, null, '{"route_prefix": "/api/v1/admin", "escalate_at": 3, "escalate_severity": "high"}'),
  ('object_enumeration', 'Record enumeration (IDOR probing)',
   '20 or more requests for bookings or complaints that do not exist or belong to someone else, by one user within 10 minutes.',
   'high', '{object.not_found}', 'user_ref', 20, 600, null, '{}'),
  ('injection_probing', 'Injection-like input',
   '3 or more requests with SQL-injection or XSS-like input from one IP address within 10 minutes. Observed only; validation is the control.',
   'medium', '{input.suspicious}', 'source_ip', 3, 600, null, '{}'),
  ('rate_limit_abuse', 'Rate-limit abuse',
   '5 or more rate-limited (429) responses for one IP address within 10 minutes.',
   'medium', '{ratelimit.exceeded}', 'source_ip', 5, 600, null, '{}'),
  ('traffic_spike', 'Traffic spike',
   'Requests per minute above 5 times the trailing one-hour median, and above 300.',
   'medium', '{traffic.minute}', 'app', 1, 3600, null, '{"multiplier": 5, "min_rpm": 300}'),
  ('suspicious_uploads', 'Repeated rejected uploads',
   '3 or more rejected files (wrong type, undecodable, too large) from one user within 30 minutes.',
   'medium', '{upload.rejected}', 'user_ref', 3, 1800, null, '{}'),
  ('privilege_change', 'Privilege change',
   'A role change, a new account with elevated rights, or a new Super Admin. Review that it was expected.',
   'high', '{privilege.changed}', 'app', 1, 60, null, '{}'),
  ('config_change', 'Security setting changed',
   'A security-relevant setting changed (registration, allowed email domains). Recorded for review.',
   'low', '{config.changed}', 'app', 1, 60, null, '{}'),
  ('admin_new_ip', 'Super Admin sign-in from a new IP',
   'A Super Admin signed in from an IP address not seen for them in the last 30 days.',
   'medium', '{auth.login_succeeded}', 'user_ref', 1, 60, null, '{"role": "super_admin", "lookback_days": 30}'),
  ('mfa_failures', 'Repeated two-step failures',
   '5 or more wrong two-step verification codes for one account within 15 minutes.',
   'high', '{auth.mfa_failed}', 'user_ref', 5, 900, null, '{}'),
  ('server_health', 'Server errors',
   '10 or more server or database errors within 5 minutes.',
   'high', '{server.error,db.error}', 'app', 10, 300, null, '{}');

-- migrate:down
-- Forward-only: intentionally empty. dbmate requires the marker.
