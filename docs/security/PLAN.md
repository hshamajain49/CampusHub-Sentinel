# CampusHub Sentinel: implementation plan

Sentinel is a separate application for the **CampusHub developers**. It is not part of CampusHub's Super Admin area, and CampusHub accounts cannot sign in to it. It does two jobs:

1. Visitor analytics for the CampusHub website.
2. Security event collection, threat detection, alerting and incident handling.

Findings referenced as F-xx are in [AUDIT.md](AUDIT.md).

## Decisions (2026-11-17)

| Topic | Decision |
|---|---|
| F-01 containment | The owner switches Render's `DATABASE_URL` and `AWS_*` to the production branch. No database change from the assistant; README passwords removed. |
| Code location | A **separate private repository**, `D:\campushub-sentinel` (`backend/`, `frontend/`, `database/`). Only the CampusHub-side integration (event client, analytics snippet, `/security` tooling) lives in this public repo. |
| Hosting | **One Render service**: the Sentinel API serves its own dashboard from the same origin. |
| Analytics consent | **Invisible to visitors**: no banner, pop-up or prompt. A passive privacy notice (a footer link to a short privacy section, as the brief requires) states what is collected. Do-Not-Track and GPC are honoured silently. A random first-party visitor ID is used (no fingerprinting). Page views are not linked to CampusHub accounts by default. `ANALYTICS_CONSENT=notice` is the default; `opt-in` stays available if your institution's privacy obligations require it. |

## Progress

| Phase | Status |
|---|---|
| 1 | Done 2026-11-17: [AUDIT.md](AUDIT.md) |
| 2 | Done 2026-11-17, in the CampusHub repo (not deployed): F-02, F-05, F-07–F-10, F-12 |
| 3 | Backend foundation done 2026-11-17 (this repo). `/security` tooling in the CampusHub repo is still to do. |
| 4 | Done 2026-11-17: `/collect`, sessions, GeoIP, reporting API, live stream (this repo); `lib/analytics.ts`, `/privacy` page and CSP (CampusHub repo, not deployed) |
| 5 | Done 2026-11-18 (this repo): signed ingestion, detection engine (15 rules), alerts, email, incidents, suspicious IPs, blocks and allowlist, security API, live alert push, secret rotation |
| 6 | Done 2026-11-18: the dashboard (`frontend/`), 9 pages plus sign-in steps, SSE live updates, served by the API on one origin |
| 7 | Done 2026-11-18, in the CampusHub repo (not deployed): signed event reporting, traffic counts, blocklist enforcement (F-03); `campushub_app` role and append-only `audit_logs` (F-04); Better Auth limits in Postgres (F-06) |
| 8 | Done 2026-11-19: `security/` tooling (dependencies, secrets incl. history, SAST, passive headers, active probe, Semgrep/ZAP import, upload to Sentinel), authorization-matrix test, local-staging attack run (15/15 rules), production passive check; scan reports in Sentinel; F-17 to F-20 fixed |

### Phase 8 notes and deviations

- **No staging deployment exists,** so the active probe ran against a local copy configured like production (two-step
  verification required, one trusted proxy hop, reporting to a local Sentinel). Production was only checked passively.
- **Public repository:** CI logs and artifacts are public, so `security.yml` prints counts only (`--quiet`) and
  uploads the full report to Sentinel. Reports never enter the CampusHub repository.
- **Semgrep and ZAP** run only in GitHub Actions (Semgrep won't install on the local Python 3.15). Their output is
  imported into the same report format.
- **`traffic_spike` alerts from tests are not marked simulated:** per-minute counts carry no flag.

### Phase 7 notes and deviations

- **Reporting never blocks a request.** Events are queued in memory (at most 1,000; the oldest are dropped first)
  and sent every 2 s while there is something to send. When idle, one heartbeat a minute is enough for the
  10-minute "ingestion stale" check. Failures back off up to 60 s.
- **The blocklist fails open.** If Sentinel can't be reached, CampusHub keeps its last list, and each block still
  ends at its own expiry. CampusHub's own protections (authorisation, rate limits, sign-in back-off, two-step
  verification) never depend on Sentinel.
- **Input inspection is observe-only.** CampusHub uses parameterised SQL and React escaping, so injection-like input
  is reported, not refused, to avoid false positives on real users. Password, token and code fields are never
  inspected, and only pattern and field names leave CampusHub.
- **New Super Admins are watched from the database** every 5 minutes, because they can only be created out of band
  (script or SQL). A new one raises a critical `privilege.changed` event, however it was made.
- **Simulated traffic** (`X-Sentinel-Simulated: 1`) is honoured only outside production.
- **Better Auth's client address.** Better Auth trusts only a single-entry `X-Forwarded-For`. Behind Render, a client
  that sends its own header falls into one shared bucket. The Postgres store re-keys that bucket with the address
  Express resolved, so every client keeps its own limit.
- **Found in Sentinel and fixed:** simulated events could raise risk scores and trigger automatic blocks.

### Phase 6 notes and deviations

- **Visitor geography is a ranked country list, not a map.** A choropleth needs a map library and boundary data, and
  with few countries a ranked list is more exact. A map can be added later if traffic becomes international.
- **Dark theme only** (the brief asked for dark by default). Chart colours were validated against the card surface
  `#111827`. The severity stack uses a darker amber (`#c98500`) because the reserved warning amber failed the
  lightness band.
- **The "Security Audit Reports" page** shows the dashboard audit log now. Its scan-report section stays empty, and
  says so, until the CampusHub scanning tooling (outstanding from Phase 3) produces reports.
- **Bugs found by the browser check and fixed:**
  - the endpoint severity dots were one level too high (1-based `severity_rank` read with a 0-based index);
  - form hint text leaked into the inputs' accessible names;
  - the CLI scripts failed silently when the database was down (empty `AggregateError` message).

### Phase 5 notes and deviations

- **Detection reasons stay current.** An open alert's reason is rewritten with each repeat, so it always states the
  current evidence (count, window, threshold).
- **Cooldown applies only after "false positive".** After "resolved", renewed activity opens a new alert at once. A
  developer said it was over, so its return is news.
- **Escalation is one-way.** Severity can rise (for example `member_admin_api`) but never drops on an open alert.
  Emails go out when an alert opens or escalates.
- **Lifting a block needs no fresh confirmation.** It only loosens enforcement and can be urgent. Creating a block,
  editing the allowlist and changing rules do need one.
- **One active block per network is enforced in code,** under an advisory lock: "active" depends on `now()`, which an
  index can't express.
- **Traffic spikes need 15 minutes of history.** A brand-new app can't trip the spike rule on noise.
- **Not built:** reminder emails for long-open alerts, and webhook or chat channels. Only email exists, through a
  provider interface.

### Phase 4 notes and deviations

- **Location uses the country edition by default.** The city edition takes about 130 MB of RAM, too much for a
  512 MB free instance. Set `GEOIP_EDITION=city` on a paid instance.
- **Rate limits are per visitor, not per IP.** A whole campus can share one public IP, so the per-IP ceiling is a
  loose 5,000 a minute and the real limit is 120 a minute per visitor.
- **Heartbeats stop after 5 minutes without input.** A tab left open on a screen doesn't inflate session length.
  Activity is only timestamped in the browser, never sent.
- **The live stream (SSE) arrived in Phase 4,** because live visitors need it. Phase 5 adds security alerts to the
  same stream.
- **Retention runs in-process**, every 6 hours on the single instance.
- **Pre-existing CampusHub bug fixed:** after signing in, `?redirectTo=` deep links were ignored, because the guard
  went to the home page before the login form's own redirect ran. Found by the analytics browser test.

### Phase 3 deviations from this plan

- **`analytics_events` isn't partitioned yet.** It is a plain table with time indexes, and `sentinel_purge()` deletes
  rows past retention. Monthly partitions are worth adding once volume justifies them.
- **No direct deletes of protected rows.** Old audit logs, security events and incident notes can only be removed by
  `sentinel_purge()`, which runs as the owner with a transaction-local flag; the app role has no `DELETE` on them.
- **Ingestion secrets are stored encrypted in the database** (AES-256-GCM, key derived from `DATA_ENCRYPTION_KEY`).
  Server-side HMAC verification needs the secret itself, so storing only a hash isn't possible.
- **Developer accounts are never deleted, only deactivated,** so every audit entry still resolves to a person.
- **`.npmrc` sets `legacy-peer-deps=true`.** npm 10 crashes resolving vitest's optional peers otherwise.

## 1. Architecture

```
                         ┌──────────────────────────── CampusHub (unchanged hosting) ───────────────────────────┐
 Visitor's browser ──────┤ SPA (Cloudflare Pages) ──API──▶ CampusHub API (Render) ──▶ Neon "campus-hub" project  │
        │                └──────────────────────────────────────────┬──────────────────────────────────────────┘
        │ page views (sendBeacon, ≤ 2 KB,                           │ security events: HMAC-signed batches,
        │ no credentials, write-only)                               │ fire-and-forget, bounded queue
        ▼                                                           ▼
 ┌──────────────────────────────────────── CampusHub Sentinel ─────────────────────────────────────────────┐
 │  /collect (public, origin-checked)   /ingest/v1/* (server-to-server, HMAC)   /api/* (developers only)    │
 │                       Sentinel API (Node 22 + Express 5) ──▶ Neon "campushub-sentinel" project          │
 │  Developer's browser ◀── dashboard (React) ◀── SSE live stream                                           │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**How the separation works:**

- **Separate code:** Sentinel has its own `package.json`, lockfile, migrations and CI job. It shares no code with CampusHub at runtime.
- **Separate data:** a separate Neon **project**. That keeps your two-branch rule for `campus-hub`, and means a leaked CampusHub database credential can't reach Sentinel's data, or the other way round.
- **Separate identity:** developer accounts live only in Sentinel. They are created by a CLI command, never by self-registration. TOTP is mandatory.
- **Failure isolation:** CampusHub never waits on Sentinel.
  - Events are queued in memory: at most 1 000 events, flushed every 2 seconds or every 50 events.
  - Each send has a 3-second timeout, then backs off exponentially. When the queue is full, the oldest events are dropped and the drops are counted.
  - If Sentinel is down, sleeping or misconfigured, CampusHub behaves exactly as it does today. Its own controls (authorisation, rate limits, the F-02 per-account lockout) are enforced inside CampusHub and do not depend on Sentinel.

### Ingestion channels

| Channel | Caller | Authentication | What it may write |
|---|---|---|---|
| `POST /collect` | Visitors' browsers | None possible (it's public). Instead: `Origin` must match the monitored app's allowlist, per-IP rate limit, 2 KB body cap, strict schema, bot user agents dropped | Page views and heartbeats only. It can never create security events. |
| `POST /ingest/v1/events` | CampusHub API | `X-Sentinel-Signature: t=<unix>,v1=HMAC-SHA256(secret, t + "." + body)`. Requests are rejected if older than 5 minutes, and duplicate `eventId`s are dropped (prevents replay). | Security events and per-minute traffic counters |
| `GET /ingest/v1/blocklist` | CampusHub API | Same HMAC | Read-only: currently active temporary blocks |

The ingestion secret lives only in the two servers' environment variables. The browser never holds a Sentinel credential. CampusHub can't read, change or delete anything in Sentinel: its secret only appends events and reads the blocklist.

### Privacy defaults for analytics

- **Visitor ID:** a random UUID kept in `localStorage`, used to tell new visitors from returning ones. It is not a fingerprint: no canvas, font or hardware probing.
- **IP addresses:** analytics rows keep only a truncated IP (IPv4 /24, IPv6 /48) plus a keyed hash used for uniqueness. Security events keep the full IP, because it is needed for blocking and investigation; they are retained for 90 days.
- **Location:** country and city from an offline DB-IP Lite database (CC-BY 4.0) bundled with the API. No IP is sent to a third-party lookup service.
- **Signed-in users:** the CampusHub user ID is attached only when the visitor is signed in and has allowed analytics. It is shown as "reported by the browser", because a browser can't prove it.
- **Browser privacy signals:** Do-Not-Track and Global Privacy Control are honoured.
- **Consent model:** a passive notice with no banner (see Decisions). It is configurable (`ANALYTICS_CONSENT=notice|opt-in`).
- **Retention, configurable:**

  | Data | Kept for |
  |---|---|
  | Raw analytics events | 13 months |
  | Sessions | 13 months |
  | Security events | 90 days |
  | Alerts and incidents | 2 years |
  | Dashboard audit log | 2 years |

## 2. Data model (Sentinel database)

| Table | Purpose |
|---|---|
| `monitored_applications` | CampusHub: allowed origins, the ingestion secret's hash and key ID, the consent mode |
| `analytics_visitors` | Visitor UUID, first and last seen, new or returning |
| `analytics_sessions` | Session: visitor, start and last activity, entry and exit page, referrer source, device, browser, OS, viewport bucket, country and city, truncated IP, page count, duration, bounce flag |
| `analytics_events` | Page views (path template, title-free), timestamps. Partitioned by month for cheap retention. |
| `security_events` | Event ID (from the sender, unique), occurred and received times, category, severity, source IP, user ID, route template, method, status, detection reason, details (JSONB, size-capped) |
| `detection_rules` | Key, enabled, severity, threshold, window, group-by (`ip`, `user`, `ip+route`…), cooldown, auto-block flag, parameters (JSONB) |
| `security_alerts` | One open alert per (rule, group key). Repeats bump `occurrences` and `last_seen` instead of creating new alerts. |
| `security_incidents` | Status (`new`, `investigating`, `resolved`, `false_positive`) and classification (`suspicious`, `policy_violation`, `unauthorized_access_verified`, `compromise_confirmed`), with linked alerts and events, notes and an owner |
| `suspicious_ips` | Rolling risk score (severity-weighted, with decay), first and last detected, reasons, event count |
| `ip_blocks` | Temporary blocks: IP or CIDR, reason, expiry (max 24 h unless extended), created by. A never-block allowlist protects developers and admins. |
| `administrator_accounts` | Developer accounts: argon2id hash, TOTP secret (encrypted at rest), hashed recovery codes, failed-attempt counter and lockout time |
| `administrator_sessions` | Hash of the session token, created, last seen and expiry, IP, user agent |
| `audit_logs` | Every dashboard sign-in (successful or failed), status change, rule change, block, setting change and export. **Append-only**, enforced by a trigger and role grants. |
| `notification_preferences` | Per developer: email on/off, minimum severity, quiet hours |

**Roles:**

- `sentinel_app` can insert into `security_events` and `audit_logs` but never update or delete them.
- Retention deletes run through a `SECURITY DEFINER` function that the app cannot use for anything else.
- Migrations run as the owner, from CI.

## 3. Detection engine (rule-based)

Rules run when an event is ingested. They count matching events in a sliding window, using indexed SQL over `security_events`, so the counts survive restarts. Every threshold lives in `detection_rules` and can be edited from Settings; adding a rule means adding a row plus, if it needs one, a small TypeScript matcher.

| Rule | Default | Severity |
|---|---|---|
| Brute force from one IP | > 10 failed sign-ins in 5 min | High |
| Password spraying | 1 IP fails sign-in for ≥ 5 distinct accounts in 10 min (accounts compared by keyed hash, never by email) | High |
| Account under attack | ≥ 10 failures for one account from ≥ 3 IPs in 15 min | High |
| Admin-area probing | ≥ 5 `403` responses on `/api/v1/admin/*` by one non-admin user or IP in 10 min | High |
| Student → Super Admin API | Any `403` on an admin route from a signed-in member | Medium (1×), High (≥ 3 in 10 min) |
| Object enumeration (IDOR probing) | ≥ 20 `BOOKING_NOT_FOUND` / `COMPLAINT_NOT_FOUND` responses by one user in 10 min | High |
| Injection probing | ≥ 3 requests matching SQLi or XSS signatures from one IP in 10 min. The signature check only observes, never blocks; Zod validation is the actual control. | Medium |
| Rate-limit abuse | ≥ 5 `429`s for one IP in 10 min | Medium |
| Traffic spike | Requests per minute > 5× the trailing 1-hour median, and > 300 | Medium |
| Suspicious uploads | ≥ 3 rejected files (bad signature, undecodable) by one user in 30 min | Medium |
| Unexpected privilege change | A role change, new account or new Super Admin outside the provisioning script | High |
| Sensitive configuration change | Change to settings (registration, allowed domains) | Low (informational, always recorded) |
| Super Admin activity at unusual hours or from a new IP | First sign-in from a never-seen IP | Medium |
| Server health | ≥ 5 database connection errors, or ≥ 10 `5xx` in 5 min | High |

**Classification is conservative.** Rules only ever produce **suspicious** or **policy violation**. "Verified unauthorised access" and "confirmed compromise" are set by a developer on an incident, never by the engine.

**Alerts:**

- Critical and High alerts show as a toast on the dashboard immediately (SSE), are stored, and are emailed through a configurable provider. Brevo comes first, with its own API key and sender.
- Repeats of an open alert don't send another email until the alert is resolved, or until a cooldown passes (30 min by default).

**Blocking:**

- Off by default per rule.
- A developer can block an IP or CIDR for 15 minutes to 24 hours.
- CampusHub pulls the blocklist every 60 seconds and enforces it locally. If Sentinel is unreachable, CampusHub keeps the last list until it expires (fails open).
- The allowlist can't be blocked, which prevents locking yourself out.

## 4. Sentinel security (Part 6 of the brief)

- **Sign-in and sessions:**
  - Argon2id password hashes with a 12-character minimum, plus a check against a bundled list of common passwords.
  - TOTP is mandatory: an account can't do anything until it has enrolled. There are 10 single-use recovery codes.
  - Lockout per account (exponential) and per IP.
- **Cookies and CSRF:**
  - The session is an opaque random token in an `HttpOnly; Secure; SameSite=Strict` cookie; only its hash is stored. Sessions time out after 30 minutes idle, with a 12-hour absolute limit, and are rotated at sign-in.
  - CSRF defence: `SameSite=Strict`, an `Origin` check, and a required `X-Requested-With` header on every state-changing request.
- **Re-authentication:** needed for sensitive actions (create a developer, delete a rule, change retention, export).
- **API hardening:**
  - Strict CORS (none at all with the recommended same-origin hosting), helmet with a strict CSP.
  - Zod `strictObject` on every input and parameterised SQL only.
  - Rate limits on every route group.
- **Authorisation:** checked on the server for every route, with two roles: `owner` (manage developers, settings) and `analyst` (view, triage).
- **Secrets:** environment variables are Zod-validated, and the service refuses to start if a secret is missing or too short.

## 5. Hosting

**Chosen: one Render service per app.** The Sentinel API also serves the built dashboard from the same origin. This gives first-party `HttpOnly` cookies without needing a custom domain, no CORS surface for the admin API, and one fewer deployment.

**Alternative (as in the brief): Cloudflare Pages for the dashboard plus Render for the API.** This needs a shared custom domain (`sentinel.example.com` and `sentinel-api.example.com`) for cookie-based sessions. Without one, sessions would be bearer tokens held in memory, so you'd sign in again on every reload.

**Render free plan caveat:** a workspace gets 750 free instance hours a month, *shared* by all free services. The CampusHub API and Sentinel both kept awake would need about 1 440 hours. Free services also sleep after 15 minutes idle, and the first event wakes Sentinel after a cold start of about a minute; CampusHub's queue and retry absorb that. For dependable monitoring, put Sentinel on Starter (about $7 a month), or accept occasional gaps on the free plan.

## 6. Phases

| Phase | Deliverables | Your input needed |
|---|---|---|
| **2. CampusHub critical and high fixes** | **F-01 containment:** rotate or deactivate the demo accounts, scrub the README; you switch Render to production. **F-05** production demo-data guard. **F-02** per-account sign-in back-off (Postgres) and TOTP for Super Admin (Better Auth `twoFactor`, plus a TOTP step on `/admin/login`). Cheap Low items, unless you object: F-07 push-host allowlist, F-08 pixel limit, F-09 password rules, F-10 12-hour Super Admin sessions, F-12 dev dependency update. Tests for each fix. | Containment choice; Render env change |
| **3. Sentinel backend and database** | Scaffold, env validation, migrations for every table above, role and grant scripts, developer CLI (`admin:create`, `admin:reset-mfa`), sign-in with TOTP, sessions, audit log. Also `/security` tooling (see below). | Create the Neon project `campushub-sentinel` (one command; I'll give it to you) |
| **4. Visitor analytics** | `/collect`, sessionisation (30-minute inactivity), geo lookup, user-agent parsing, new vs returning, aggregation queries, retention job. CampusHub `analytics.ts` (route-change page views and a visibility-aware 30-second heartbeat), passive privacy notice, CSP `connect-src` update. | — |
| **5. Security events and detection** | `/ingest/v1/events` with HMAC, rule engine, alerts with de-duplication, incidents, suspicious-IP scoring, blocklist API, email notifier. | Brevo key for Sentinel (optional) |
| **6. Sentinel dashboard** | React + Vite + Recharts. Dark theme by default; status colours green, amber and red. Nine pages (Overview, Live Visitors, Traffic Analytics, Threats, Security Events, Suspicious IPs, Incidents, Audit Reports, Settings), responsive, SSE live updates. The Overview health status is computed from open alerts and ingestion freshness, never decorative. | — |
| **7. CampusHub integration** | `backend/src/lib/sentinel.ts` (queue, HMAC, back-off). Event hooks: Better Auth sign-in result, error handler (401, 403, object 404s), 429 handler, upload rejections, audit-log actions, database errors, per-minute traffic counters, observe-only injection-signature inspector. Blocklist middleware (fails open). **F-03** (logging), **F-04** (least-privilege role and append-only `audit_logs`), **F-06** (database-backed auth rate limits). | Switch Render's `DATABASE_URL` to the new role |
| **8. End-to-end validation** | Run locally (both apps plus embedded Postgres), and against staging only if you set one up: repeated failed sign-ins, password spraying, student calling admin APIs, IDOR enumeration, rate-limit triggering, harmless SQLi and XSS strings, oversized and fake uploads. Each must appear in Sentinel with the expected rule and severity. Authorisation matrix (every role × every endpoint). Scanners. Results recorded in `AUDIT.md` (retest column) and `security/reports/`. | — |
| **9. Documentation** | README for both apps (architecture, local run, env vars, deployment, notifications, severity guide, incident playbook). | — |

### `/security` tooling (Phase 3, finished in Phase 8)

| Command (root `package.json`) | What it runs |
|---|---|
| `npm run security:dependencies` | `npm audit` for both apps plus OSV-Scanner (pinned binary, checksum-verified) → JSON and Markdown |
| `npm run security:secrets` | gitleaks over the full history (pinned binary) plus a secret-pattern scan of both built bundles |
| `npm run security:sast` | Semgrep (`p/typescript`, `p/nodejs`, `p/react`, `p/owasp-top-ten`, plus project rules); falls back to CI if it can't install locally |
| `npm run security:probe` | Safe active tests: authorisation matrix, IDOR, CORS, headers, injection strings, rate limits. **Refuses any host but `localhost` unless given `--target` plus `--i-own-this`.** It never targets the production hostnames. |
| `npm run security:scan` | OWASP ZAP baseline (passive) through GitHub Actions; there's no Docker locally |
| `npm run security:audit` | All of the above, then `security/reports/<date>.md` grouped Critical → Info, with the 9 fields per finding the brief asks for |

## 7. Ground rules carried through every phase

- No destructive or active tests against production; active tests run locally or on staging.
- No denial-of-service.
- No changes to real user data.
- No real credentials in reports.
- A test is reported as passed only if it ran, with its output.
- Simulated attack traffic is tagged `simulated=true` in Sentinel and shown with a "Simulated" badge, so it never mixes with real monitoring results.
- No mock data ships in production builds.
