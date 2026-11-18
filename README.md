# CampusHub Sentinel

CampusHub Sentinel is the CampusHub developers' monitoring site. It covers two things:

- **Visitor analytics** for the CampusHub website.
- **Security monitoring:** security events, rule-based threat detection, alerts and incident handling.

It runs as its own application, with its own database and its own accounts. CampusHub users, including CampusHub's
Super Admin, cannot sign in to it.

> **Status (2026-11-18): backend and dashboard.**
> - **Built:**
>   - the database schema, developer sign-in with a mandatory authenticator app, sessions, roles, the audit log and
>     tamper resistance;
>   - visitor analytics: the `/collect` beacon, sessions, location and the reporting API;
>   - security monitoring: signed ingestion, the detection engine, alerts, emails, incidents, suspicious IPs, blocks
>     and the allowlist;
>   - the live stream (`/api/stream`);
>   - the dashboard (`frontend/`, 9 pages, served by the API on the same origin).
> - **Not built yet:** CampusHub sending its security events and enforcing blocks (Phase 7).
>
> See [docs/security/PLAN.md](docs/security/PLAN.md) for the plan and
> [docs/security/AUDIT.md](docs/security/AUDIT.md) for the CampusHub security audit.

## Architecture

```
CampusHub SPA ──page views──▶  /collect          (public, write-only, origin-checked)        ┐
CampusHub API ──signed events▶ /ingest/v1/*      (HMAC, server-to-server)                    ├─ Sentinel API ─▶ Neon "campushub-sentinel"
Developers    ──dashboard────▶ /api/*  + the SPA (same origin; session cookie + TOTP)        ┘   (Render, one service)
```

- **No coupling:** CampusHub never waits on Sentinel. If Sentinel is down, CampusHub keeps working, and its own
  security controls stay in force.
- **Database:** its own Neon project. The API connects as `sentinel_app`, which has data access only and can't change
  table definitions. Audit logs, security events and incident notes are append-only.

## Run it locally

Node 22. This machine exports `NODE_ENV=production`, so always install with `--include=dev`:

```bash
npm install --include=dev
npm run db:local                 # PostgreSQL 17 on :5434 (databases sentinel + sentinel_test), data in .localdb/
cp backend/.env.example backend/.env
# Put a real key in backend/.env:
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"   # → DATA_ENCRYPTION_KEY
npm run db:migrate               # and: npm run db:migrate:test
npm run admin:create -w @sentinel/backend -- --email you@college.edu --name "Your Name" --role owner
npm run dev                      # API on :4100 + dashboard on http://localhost:5180 (Vite proxies /api)
```

`admin:create` prints a temporary password once. At first sign-in you replace it and set up an authenticator app.

**Choosing the local origin.** The CSRF check compares each request's `Origin` with `APP_ORIGIN`, so set it to the
address you open in the browser:

| How you run it | `APP_ORIGIN` in `backend/.env` |
|---|---|
| `npm run dev` (dashboard with hot reload) | `http://localhost:5180` |
| `npm run build && npm start` (production-like) | `http://localhost:4100` |

The local Postgres cluster keeps running in the background after `npm run db:local`. If a command fails with an empty
message or `ECONNREFUSED`, the cluster has stopped: run `npm run db:local` again.

## Dashboard

The API serves `frontend/dist`, so the dashboard and the API share one origin: first-party HttpOnly cookies and no
CORS. Every number comes from the API; nothing in the dashboard is mock data.

| Page | What it shows |
|---|---|
| **Overview** | Visitors today, online now, API requests, threats detected, critical alerts and system health (computed by the API), plus today's traffic, the security timeline, geography, devices, recent threats and latest visits |
| **Live Visitors** | Who is online now (updates live), and every visit in the chosen range: location, device, browser, OS, screen size, pages, duration, source, new or returning, first visit, network (/24 or /48 only) |
| **Traffic Analytics** | Range filters (today, 7, 30 or 90 days, custom). Visitors, sessions and page views over time (one measure at a time, never two y-axes), hour of day, new vs returning, and breakdowns by page, source, referrer, country, city, device, browser, OS, screen size and entry page |
| **Security Threats** | Event counts by severity, active alerts, incidents, suspicious IPs, the severity timeline, the most targeted endpoints, and the alert queue. An alert's page shows the reason, the evidence events and the triage actions, and can open an incident |
| **Security Events** | The event log, filtered by severity, category, IP or CIDR, account, route and real vs simulated, with an event's redacted details |
| **Suspicious IPs** | Addresses ranked by risk; an IP's events, alerts and block history; temporary blocks and the allowlist (owners) |
| **Incidents** | Case files with status, severity, classification, owner, linked alerts and append-only notes |
| **Audit Reports** | The append-only audit log of everything done in Sentinel. The section for CampusHub scan reports is empty until the scanning tooling exists |
| **Settings** | Your session, alert emails and password; developers (owners); detection rules; the monitored app and secret rotation; data and privacy (including the DB-IP credit) |

**Behaviour:**
- **Live updates:** they arrive over SSE. High and critical alerts appear as notifications at once, and pages refresh
  at most every 5 seconds while things change, so nothing polls on a timer.
- **Re-confirmation:** a sensitive action asks for your password and a code in a dialog, then continues.

**Design:**
- Dark by default.
- Chart colours are validated for colour-blind separation and contrast on the card surface: categorical
  `#3987e5 / #d95926 / #199e70`, severity stack `#3987e5 / #c98500 / #d03b3b`.
- Status always pairs colour with an icon and a word.
- Each time chart has a "Show as table" view.

## Visitor analytics

### How it works

1. CampusHub's browser code (`frontend/src/lib/analytics.ts` in the CampusHub repo) sends `POST /collect`:
   - a page view when the page changes;
   - a heartbeat every 30 s while the tab is visible and in use (used for session length).
2. The body is `text/plain` JSON of at most 2 KB, so it is a simple cross-origin request: no preflight and no CORS.
3. Sentinel builds the sessions. A session continues while hits arrive within 30 minutes, and the next hit after
   that starts a new one.
4. A random visitor ID kept in the visitor's browser tells new visitors from returning ones. If it is cleared, the
   visitor counts as new.

### What is stored

- **Path:** without its query string or fragment (password-reset links carry tokens), and with record IDs replaced
  by `:id`.
- **Where they came from:** the referrer's host only (search, social, referral, campaign or direct), plus `utm_*`
  campaign tags.
- **Device:** browser and OS (an in-house parser, because the popular library's current version is AGPL), device
  type, and viewport size range.
- **Location:** country (or city) from an offline DB-IP database.
- **IP address:** only the /24 (IPv4) or /48 (IPv6) network and a keyed hash. The full address is never stored.
- **Nothing** about what people type, no cookies, and no CampusHub account (unless CampusHub sets
  `VITE_SENTINEL_LINK_USERS=true`).

### Accepted with a 204 but not stored

- bots (crawlers, headless browsers, `curl` and the like);
- `DNT: 1` or `Sec-GPC: 1` requests.

### Refused

- an unknown or inactive site key;
- an `Origin` that isn't one of the app's origins;
- a malformed or oversized body;
- more than 120 beacons a minute from one visitor (`COLLECT_RATE_PER_MINUTE`). The per-IP ceiling is a loose 5,000 a
  minute, because a whole campus can share one address.

### Set-up

```bash
npm run app:register -w @sentinel/backend -- --slug campushub --name CampusHub --origin https://<your CampusHub site>
npm run geoip:fetch          # DB-IP Lite: country by default; GEOIP_EDITION=city on a paid instance (~130 MB RAM)
```

- **Site key:** `app:register` prints the public site key, which goes into CampusHub's `VITE_SENTINEL_SITE_KEY`.
  Set `VITE_SENTINEL_URL` to this service's URL.
- **Ingestion key and secret:** printed once, for Phase 5.
- **Attribution:** location data is [IP Geolocation by DB-IP](https://db-ip.com), licensed CC BY 4.0. The dashboard
  must show this credit (Phase 6).

### Reporting API

All endpoints need a signed-in developer. Query parameters for each:

- `range=today|7d|30d|90d|custom`, with `from`/`to` (dates, inclusive, at most 400 days) for `custom`;
- `app=<slug>`, optional.

"Today", daily buckets and hour-of-day charts use `REPORT_TIMEZONE`.

| Endpoint | Returns |
|---|---|
| `GET /api/analytics/overview` | visitors (new and returning), sessions, page views, average session length, bounce rate, online now, visitors today / this week / this month, all-time totals |
| `GET /api/analytics/timeseries` | visitors, sessions and page views per hour (ranges up to 2 days) or per day, with empty buckets filled |
| `GET /api/analytics/hours` | sessions by hour of day |
| `GET /api/analytics/breakdown?dimension=…` | `device`, `browser`, `os`, `country`, `city`, `source`, `referrer`, `viewport`, `entry`, `exit`, `visitor_type` or `page` |
| `GET /api/analytics/sessions` | paginated sessions (`live=true` for visitors online now; filter by `country`, `device`) |
| `GET /api/analytics/sessions/:id` | one session with the pages it visited |
| `GET /api/stream` | Server-Sent Events: a summary (online now, page views in the last 5 minutes) pushed at most every 2 s while something changes. The stream closes when the session ends. |

**Retention:** `sentinel_purge()` runs 5 minutes after start and then every 6 hours. It removes page views and
sessions older than the app's retention (395 days by default).

## Security monitoring

### Ingestion (CampusHub's API → Sentinel)

Server to server only. Every request is signed with the app's ingestion secret; the browser never holds it.

```
POST /ingest/v1/events        body: { "events": [...], "traffic": [...] }   (≤ 256 KB, ≤ 500 events, ≤ 120 minutes)
GET  /ingest/v1/blocklist     → { blocks: [{ cidr, expiresAt }] }           (the active blocks to enforce)
POST /ingest/v1/reports       body: a security scan report (≤ 1 MB)       (CampusHub: npm run security:audit -- --upload)

X-Sentinel-Key:        ik_…                                  (app:register / app:rotate-secret)
X-Sentinel-Signature:  t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<METHOD>.<path>.<raw body>")>
```

**Signatures:**
- The timestamp must be within 5 minutes.
- Signing the method and path means a captured request can't be replayed against another endpoint.
- Replays of the same request do nothing: events are de-duplicated by their `id`, and a minute's traffic counts are
  overwritten, not added.
- An empty batch is a heartbeat. It keeps "last data received" fresh, which the health status uses.

**An event:**
```json
{ "id": "8–64 chars [A-Za-z0-9_-], unique per event", "occurredAt": "ISO 8601", "category": "auth.login_failed",
  "severity": "info|low|medium|high|critical", "sourceIp": "203.0.113.9", "userRef": "user id", "actorRole": "student",
  "method": "POST", "route": "/api/auth/sign-in/email", "path": "…", "statusCode": 401,
  "description": "≤ 500 chars", "details": { "accountKey": "keyed hash of the email" }, "simulated": false }
```

**What the receiver does with it:**
- Fields in `details` whose names look like credentials (password, token, secret, cookie, API key, session, OTP) are
  stored as `[redacted]`.
- Future timestamps are clamped to now, and events older than 7 days are dropped.
- The secret is stored encrypted. Rotate it with `npm run app:rotate-secret -w @sentinel/backend -- --slug campushub`
  or from the dashboard (owner, re-confirmed); the old secret stops working at once.

**Connecting CampusHub's API** (the sender is `backend/src/lib/sentinel.ts` in the CampusHub repo):
1. `npm run app:rotate-secret -w @sentinel/backend -- --slug campushub` (against this Sentinel's database). It prints
   `SENTINEL_INGEST_KEY_ID` and `SENTINEL_INGEST_SECRET` once.
2. On CampusHub's Render service, set those two plus `SENTINEL_URL=https://<this Sentinel's origin>`, and redeploy.
3. Within a minute, the overview shows CampusHub's ingestion as current. CampusHub sends a heartbeat every minute
   when idle, so "stale" (over 10 minutes) means it is down or misconfigured.

CampusHub marks test traffic with `X-Sentinel-Simulated: 1` (outside production only). Simulated events raise
alerts marked "simulated", but never send email, change an address's risk score, block it, or affect the health status.

### Detection

The 15 rules are rows in `detection_rules`. Owners can change their thresholds, windows, severity, cooldown and
automatic blocking, after confirming their password and a code.

- **How a rule matches:** each new event is checked by the rules that listen to its category. A rule counts matching
  events in its window, measured back from the event's own time, grouped by IP, user, account or IP + route.
- **One alert per group:** reaching the threshold opens an alert, or adds to the one already open for that group.
  Severity can rise (for example `member_admin_api` goes from medium to high at 3), but never drops.
- **Cooldowns:** marking an alert *false positive* silences the same rule and group for the rule's cooldown (30
  minutes by default). *Resolved* means the next match opens a new alert immediately.
- **Conservative labels:** rules label only "suspicious" or "policy violation". "Unauthorised access verified" and
  "compromise confirmed" are set on an incident by an owner.
- **Simulated events** (`simulated: true`, used for test attacks) raise alerts marked as simulated. They are never
  emailed and don't affect the health status.

### Health status

| Status | When |
|---|---|
| **critical** | An open critical alert |
| **warning** | An open high alert, or no data from the app for 10 minutes |
| **healthy** | Otherwise |

The status is computed from these signals (`GET /api/security/status`), never set by hand.

### Suspicious IPs and blocks

- **Risk score:** each event from an IP adds a weight (low 1, medium 3, high 8, critical 20), and an alert about it
  adds 10. The score halves every day without activity. It ranks addresses; it isn't proof.
- **Blocks** are temporary (15 minutes to 7 days) and owner-only, with a fresh confirmation. They are never broader
  than an IPv4 /16 or IPv6 /48, and never over an address on the allowlist.
- **Allowlist:** adding an address lifts any block that covers it. This protects you from locking yourselves or the
  campus network out.
- **Automatic blocking** is off for every rule until an owner turns it on.
- **Enforcement:** CampusHub pulls the active list and enforces it (Phase 7). If Sentinel is unreachable it keeps its
  last copy until the blocks expire.

### Alert emails

- **When:** a new alert, or one whose severity rises; never for each repeat.
- **Who:** every active developer whose preference covers the severity. The default is high and critical; set it
  yours at `PUT /api/me/notifications`.
- **Quiet hours** hold back everything except critical alerts.
- **Transport:** `EMAIL_TRANSPORT=brevo` sends (`BREVO_API_KEY`, `ALERT_EMAIL_FROM`); `log` only logs. Every attempt
  is recorded in `notification_log`.
- **The message** says plainly that a detection is not proof of a compromise.

### Dashboard API

All endpoints need a signed-in developer. Analysts and owners can both triage.

| Endpoint | Purpose |
|---|---|
| `GET /api/security/overview`, `/timeseries`, `/status` | Severity counts, active alerts, incidents, suspicious IPs, active blocks, requests, top targeted endpoints, recent events; the timeline; health |
| `GET /api/security/events`, `/events/:id` | Event log (filters: severity, category, IP or CIDR, user, route prefix, simulated) |
| `GET /api/security/alerts`, `/alerts/:id`, `PATCH /alerts/:id` | Alerts with sample evidence (up to 50 events); triage to acknowledged, resolved, false positive or open, with an optional note |
| `GET/POST /api/security/incidents`, `GET/PATCH /incidents/:id`, `POST /incidents/:id/notes` | Incidents: new → investigating → resolved / false positive; owner, severity, classification, linked alerts, append-only notes |
| `GET /api/security/ips`, `/ips/:ip` | Suspicious IPs by risk; one IP's events, alerts and blocks |
| `GET/POST /api/security/blocks`, `POST /blocks/:id/lift` | Blocks (creating one: owner, re-confirmed) |
| `GET/POST /api/security/allowlist`, `DELETE /allowlist/:id` | Never-block list (owner, re-confirmed) |
| `GET /api/security/rules`, `PATCH /rules/:key` | Detection rules (changing one: owner, re-confirmed) |

Every change is written to the audit log.

## Tests

| Command | What it runs |
|---|---|
| `npm test` | Unit tests: crypto, passwords, TOTP against the RFC vectors, sign-in steps |
| `npm run test:integration` | The real app against `sentinel_test`, after `npm run db:migrate:test` |
| `npm run lint` | ESLint, including a rule that refuses values interpolated into SQL |
| `npm run typecheck` | TypeScript |

## Security model

### Developer sign-in

1. **Email and password.** Passwords are hashed with argon2id (m = 19 MiB, t = 2). They must be at least 12
   characters, not a common password, and not contain the email address.
2. **Throttling.** Five failures for an account lock it, starting at 1 minute and doubling up to 60. Twenty failures
   from one IP lock that IP for 30 minutes. Counters are stored in Postgres as keyed hashes, never as email addresses.
3. **Indistinguishable failures.** A wrong password and an unknown email get the same answer with the same timing.
4. **Steps before access.** First the authenticator code (if one is set up), then the new password (if the current
   one is temporary), then authenticator setup (if there is none yet). Until every step is done, the session lasts at
   most 15 minutes and can only reach the step endpoints.
5. **Authenticator codes.** Each code works once. Five wrong codes pause the step, starting at 5 minutes and doubling
   up to an hour. There are 10 single-use recovery codes, stored as hashes; the secret is stored with AES-256-GCM.

### Sessions

- **Token:** an opaque 256-bit token in an `HttpOnly; Secure; SameSite=Strict` cookie (`__Host-` prefix in
  production). The database stores only its SHA-256. It is replaced when sign-in completes, so a token captured
  earlier can't be fixed onto the session.
- **Lifetime:** 30 minutes idle, or 12 hours after sign-in, whichever comes first. Signing out, changing the
  password, being deactivated or having the authenticator reset ends it.

### Cross-site request protection

Three checks, all required on every state-changing request:

- the `SameSite=Strict` cookie;
- an `Origin` (or `Sec-Fetch-Site`) check against `APP_ORIGIN`;
- a custom `X-Requested-With: sentinel` header.

There is no CORS at all.

### Roles and sensitive actions

- **owner:** manages developer accounts.
- **analyst:** views and triages.

Both are checked by the server on every route. Adding a developer, deactivating one or resetting their authenticator
also needs the password and a fresh code from the last 10 minutes (`POST /api/auth/reauth`).

### Audit log

Every sign-in (success and failure), sign-in step, sign-out and account change is recorded with time, account, IP and
browser. An unknown email is stored only as a keyed hash, in case a password was typed into the email field.

### HTTP

- Strict CSP: `script-src 'self'`, `frame-ancestors 'none'`.
- `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a `Permissions-Policy`, and HSTS in production.
- No `X-Powered-By` header; `Cache-Control: no-store` on the API.
- Error answers carry a code and request ID, never a stack trace.

## Database roles (production, once)

1. Create a Neon project named `campushub-sentinel` (Singapore), separate from `campus-hub`. Copy the owner role's
   DIRECT connection string.
2. Run the migrations as the owner. CI does this on each deploy (`SENTINEL_OWNER_DATABASE_URL`); by hand it's
   `npx dbmate --migrations-dir database/migrations --no-dump-schema --url "<owner url>" up`. This creates the
   `sentinel_app` role, without login rights.
3. Give `sentinel_app` login rights, with a long random password, in the Neon SQL editor:
   ```sql
   alter role sentinel_app with login password '<64 random characters>';
   ```
4. Render's `DATABASE_URL` is the same DIRECT host with `sentinel_app` and that password.

With that setup the app can read and write data but can't drop tables, disable triggers, or change or delete audit
logs and security events. `sentinel_purge()` removes rows past retention: analytics 395 days, security events 90
days (evidence of open alerts and incidents is kept), audit log 2 years.

## Environment

| Variable | Meaning |
|---|---|
| `APP_ORIGIN` | The dashboard's origin, as the browser sees it; must be https in production. Used for the CSRF check. |
| `DATABASE_URL` | Neon DIRECT endpoint, role `sentinel_app`. The `-pooler` endpoint is refused. |
| `DATA_ENCRYPTION_KEY` | 32+ random bytes, base64. Encrypts TOTP and ingestion secrets and keys every HMAC. **Changing it** makes stored authenticator secrets unreadable, so every developer must then be reset with `admin:reset-mfa`. |
| `TRUST_PROXY` | Number of proxy hops in front of the API (Render: `1`). |
| `SESSION_IDLE_MINUTES`, `SESSION_ABSOLUTE_HOURS`, `REAUTH_MINUTES` | Session lifetimes; defaults 30, 12 and 10. |
| `GEOIP_EDITION` | `country` (default, about 8 MB of RAM), `city` (about 130 MB), or `off`. |
| `REPORT_TIMEZONE` | IANA timezone for reports. The default is `UTC`; Render uses `Asia/Kolkata`. |
| `COLLECT_RATE_PER_MINUTE` | Beacons per visitor per minute (default 120). |
| `EMAIL_TRANSPORT` | `log` (the default: alert emails are only logged), `brevo` (sends), or `off`. |
| `BREVO_API_KEY`, `ALERT_EMAIL_FROM`, `ALERT_EMAIL_FROM_NAME` | For `brevo`: Sentinel's own API key and a verified sender. |

## Deploy (Render)

The full runbook (first-time setup order, where every secret lives, rotation, alert response, failure modes,
free-plan limits) is **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**. The short version:

1. Push this repository to a **private** GitHub repository.
2. In Render: **New → Blueprint → this repository** (`render.yaml`). Render asks for `APP_ORIGIN`, `DATABASE_URL` and
   `DATA_ENCRYPTION_KEY`.
3. Set these GitHub repository secrets:
   - `SENTINEL_OWNER_DATABASE_URL`: the owner connection string, used for migrations.
   - `SENTINEL_RENDER_DEPLOY_HOOK_URL`: from Render's service settings.
4. Add an environment named `production` with required reviewers if you want manual approval of deploys.
5. Create the first owner: run `admin:create` with `ENV_FILE=none` and the production `DATABASE_URL` and
   `DATA_ENCRYPTION_KEY` set in the shell.

**Lost authenticator and no recovery codes:** an owner resets it from the dashboard, or someone with database access
runs `npm run admin:reset-mfa -w @sentinel/backend -- --email <address>`.
"# CampusHub-Sentinel" 

tnbttechnologies@gmail.com
