# CampusHub security audit

| | |
|---|---|
| Scope | This repository (`backend`, `frontend`, `shared`, `database`, CI, `render.yaml`) and the live API `campushub-api-kq6c.onrender.com` (read-only probes) |
| Phase | 1: inspection and assessment (2026-11-17). 2: Critical/High fixes plus cheap Low fixes (2026-11-17), see [Phase 2 retest](#phase-2-retest-2026-11-17). |
| Commit | `8f4ea89` (also the commit the live API reports on `/health`) |
| Date | 2026-11-17 |
| Method | Manual code review against the OWASP Top 10 (2021) and OWASP API Security Top 10 (2023), `npm audit`, git-history review, and read-only checks of the Neon dev branch and the live API |

## How to read this report

**Severity** (risk to CampusHub's users and data, considering how easily the issue can be exploited):

| Severity | Meaning |
|---|---|
| Critical | Exploitable now, by anyone, with no special access; leads to full compromise or exposure of user data. Fix immediately. |
| High | Realistic path to account takeover or data exposure; fix before production use. |
| Medium | Weakens a defence or removes visibility; an attacker needs another weakness or a lot of effort. |
| Low | Defence in depth, hard to exploit, or small impact. |
| Info | Observation or hardening note; no direct risk. |

**How each finding was checked.** *Verified* means a check was actually run and its output is quoted. *Code review* means the conclusion comes from reading the code; no test was run. Nothing in this report was exploited against the live site. The Critical finding was confirmed with read-only database queries and a local password-hash check, with no sign-in.

**Status:** the summary table, the [Phase 2 retest](#phase-2-retest-2026-11-17) the [Phase 7 retest](#phase-7-retest-2026-11-18) and [Phase 8 validation](#phase-8-validation-2026-11-19) are current. The `Status` and `Retest` lines inside each finding record the Phase 1 assessment.

## Summary

| ID | Severity | Finding | Checked by | Status |
|---|---|---|---|---|
| [F-01](#f-01) | **Critical** | Live API runs on the Neon **dev** branch, where the demo Super Admin's password is published in this public repo's README | Verified | **Fixed** 2026-11-17: the live API is on the production branch (retest below). Guard (F-05) prevents a repeat. |
| [F-02](#f-02) | High | Sign-in is throttled per IP only: no per-account limit, no lockout and no second factor, including for the Super Admin | Code review | Per-account back-off: **fixed**. Two-step verification: built, but **switched off on 2026-11-19 by owner decision** (`SUPER_ADMIN_MFA=off`; Sentinel `MFA_MODE=off`). Accepted risk, see below. |
| [F-03](#f-03) | Medium | Security events are not recorded or alerted on: failed sign-ins, 401s and rate-limit hits are invisible (OWASP A09) | Code review | **Fixed in code** (not deployed): CampusHub reports security events to Sentinel; retest below |
| [F-04](#f-04) | Medium | The API connects to Postgres as `neondb_owner`, and `audit_logs` is not append-only | Verified | **Fixed in code** (not deployed): `campushub_app` role and append-only `audit_logs`. Needs the role's password and Render's `DATABASE_URL` switched (owner step). |
| [F-05](#f-05) | Medium | No guard stops a production start against a database holding seeded demo accounts | Code review | **Fixed in code** (not deployed) |
| [F-06](#f-06) | Low | Rate-limit counters live in process memory, so they reset on every deploy, restart and Render spin-down | Code review | **Fixed in code** (not deployed): Better Auth's limits are in Postgres (atomic upsert). The Express per-route limiters stay in memory, as accepted for one instance. |
| [F-07](#f-07) | Low | A push subscription accepts any `https://` endpoint; the server later POSTs to it (limited blind SSRF) | Code review | **Fixed in code** (not deployed) |
| [F-08](#f-08) | Low | Venue photo decoding has no pixel limit (admin-only; memory exhaustion on a 512 MB instance) | Code review | **Fixed in code** (not deployed) |
| [F-09](#f-09) | Low | Password policy is 8 characters with a letter and a digit, with no breached-password check | Code review | **Fixed in code** (common-password list; 12+ for Super Admin) |
| [F-10](#f-10) | Low | Session token in `localStorage`; 7-day rolling sessions, the same for the Super Admin | Code review | Partly fixed: Super Admin sessions capped at 12 h. Token storage accepted until a shared custom domain exists. |
| [F-11](#f-11) | Low | Account enumeration through self-registration (`EMAIL_ALREADY_REGISTERED`) | Code review | Open (accepted trade-off) |
| [F-12](#f-12) | Low | 7 moderate advisories, all in dev-only tooling (`typescript-eslint` → `minimatch`) | Verified | **Fixed** (`npm audit` 0 at the time; see F-16) |
| [F-13](#f-13) | Info | GitHub Actions pinned by tag, not commit SHA; `npx -y wait-on` unpinned in CI | Code review | Open |
| [F-14](#f-14) | Info | `/health` publishes the build version and commit hash | Verified | Open |
| [F-15](#f-15) | Info | Developer machine: `NODE_TLS_REJECT_UNAUTHORIZED=0` is set in the shell | Verified | Open |
| [F-16](#f-16) | Low | New advisory GHSA-fc5q-39xc-vjpf (`picomatch` ReDoS, every version, no fix yet) in the lint and test tooling of both repos | Verified | Open: accepted until upstream ships a fix |
| F-17 | Low | With the database down, the API answered 500 instead of 503: Better Auth wraps the pool's connection error, which the error mapper didn't unwrap (monitoring saw `server.error`, not `db.error`) | Verified (Phase 8) | **Fixed in code**: `isConnectionError()` follows `cause` and `AggregateError.errors` |
| F-18 | Low | Admin changes made by test traffic were reported as real (`privilege.changed`, `config.changed`): a staging test would email developers and raise the admin address's risk score | Verified (Phase 8) | **Fixed in code**: `Actor.simulated` carries the flag into audit events |
| F-19 | Low | Sentinel: real activity joining an open *simulated* alert turned it real without any email | Code review (Phase 8) | **Fixed in code**: an alert that becomes real is announced like a new one |
| F-20 | Info | Sentinel dashboard: dialogs had no accessible name | Verified (Phase 8 browser check) | **Fixed in code** |
| F-21 | Medium | Weekly backups were not being made: `backup.yml` failed (last run 2026-11-15, "Dump and encrypt"), as did CI's first deploy (2026-11-18, "Migrate production"). Both read GitHub's `PROD_DATABASE_URL`, which appears missing or invalid. Neon's point-in-time restore was the only safety net. | Verified (Phase 9, run history) | Open: owner must set the secret, then run `backup.yml` by hand to confirm |
| F-22 | Low | The encrypted backup is uploaded as a GitHub Actions artifact. On a public repository any signed-in GitHub user can download it, so the full database (personal data, password hashes) is protected only by `BACKUP_PASSPHRASE`. | Code review (Phase 9) | Open: use a long random passphrase (32+ characters); better, run the backup from a private repository |

Nothing found in these areas, by code review and existing tests (details in [What held up](#what-held-up)): IDOR on bookings and complaints, role escalation, mass assignment, SQL injection, stored XSS, CSRF, CORS, upload type spoofing, CSV injection, email HTML injection, open redirects, secrets in git history or in the frontend bundle.

---

**Owner decision, 2026-11-19: two-step verification off for now, in both apps.** CampusHub's Super Admin and
Sentinel's developers sign in with a password only, and Sentinel's sensitive actions re-confirm the password only.
The code stays in place: `SUPER_ADMIN_MFA=required` (CampusHub) and `MFA_MODE=required` (Sentinel) turn it back on,
and authenticators already set up are kept. With it off, an account is protected by its password (12+ characters for
Super Admins and developers, common passwords refused), per-account and per-address sign-in back-off, session caps
(12 hours), and Sentinel alerting on sign-in attacks and on a Super Admin signing in from a new address. A phished or
reused password is now enough to take over an admin account; turning two-step verification back on removes that risk.

## Findings

### F-01
**Live API runs on the Neon dev branch, and the demo Super Admin's password is public. Severity: Critical.**

- **Affected:** the Render service `campushub-api` (its `DATABASE_URL`), the Neon `dev` branch, and `README.md` lines 43–47.
- **Description:** the live API answers `GET /api/v1/settings/public` with `"institutionName":"Demo College"`, the dev seed's value; production has "Your Institution". The dev branch holds an active `super_admin`, `admin@demo.edu`. The README of the **public** GitHub repo `hshamajain49/CampusHubWeb` lists its password, and the stored hash matches that password. Self-registration is enabled on the live site.
- **Impact:** anyone on the internet can sign in to the live site as Super Admin. From there they can read every user, booking and complaint (with photos), create accounts, change roles, delete venues, and send password-reset emails from the institution's Brevo sender. The branch also holds 2 non-demo accounts, created 2026-11-15/16.
- **Evidence (verified 2026-11-17, read-only):**
  - `GET https://campushub-api-kq6c.onrender.com/health` → `200 {"version":"1.1.0+8f4ea89"}`
  - `GET …/api/v1/settings/public` → `200 {"institutionName":"Demo College","selfRegistrationEnabled":true}`
  - Neon dev branch: `admin@demo.edu` → `{role: super_admin, active: true, mustChangePassword: false}`. The README password matches the stored hash: `true` (checked locally with Better Auth's own verifier; no sign-in attempted).
  - The demo Super Admin last signed in on 2026-11-17 at 04:05 UTC. That session no longer exists, so its source IP is unknown. The 3 surviving sessions created through Render all come from one public IP. **The data cannot tell whether anyone other than the owner has used the account.**
- **Steps to reproduce safely:** request the two URLs above and compare `institutionName` with the production branch's `app_settings`. Do not sign in with the published password on the live site.
- **Recommended fix:**
  1. **Now:** rotate the passwords of all `@demo.edu` accounts on the dev branch, or deactivate them, and revoke their sessions.
  2. Point Render's `DATABASE_URL` and `AWS_*` at the **production** branch (dashboard only; this repo has no Render API access).
  3. Remove the passwords from `README.md` and refer to the seed script instead. The old values stay in git history, which is why step 1 is required.
  4. Add the start-up guard from [F-05](#f-05) so this misconfiguration can't happen silently again.
  5. Review the dev branch's `audit_logs` for actions you don't recognise, and confirm the 04:05 UTC sign-in was yours.
- **Status:** Open. Owner decision 2026-11-17: the owner switches Render to production. Step 3 is done: README passwords removed. The same passwords remain in `seed-dev.ts`, the tests and the e2e config, so the exposure ends only when Render stops using the dev branch.
- **Retest:** pending. Expected: `GET /api/v1/settings/public` no longer returns `"Demo College"`.

### F-02
**Sign-in has no per-account throttling, lockout or second factor. Severity: High.**

- **Affected:** `backend/src/lib/auth.ts` (Better Auth `rateLimit`, `emailAndPassword`; no `twoFactor` plugin).
- **Description:** in production `/api/auth/sign-in/email` allows 10 attempts per 5 minutes **per IP**, stored in memory. Nothing counts failures per account. An attacker with many IPs can keep guessing one account's password indefinitely (credential stuffing or distributed brute force). IPv6 addresses are grouped by /64, which helps against a single IPv6 attacker. The Super Admin has no second factor, and the password policy is weak ([F-09](#f-09)).
- **Header spoofing checked, no bypass.** Better Auth 1.7.18 accepts `X-Forwarded-For` only when it holds exactly one address (`@better-auth/core/dist/utils/ip.mjs`, `getIPFromHeader`). A spoofed header gives a two-entry list behind Render, which falls into one shared bucket, so spoofing does not bypass the limit. Render forwards a single public client IP: 4 sessions created through Render recorded a public address.
- **Impact:** takeover of any account whose password is guessable or reused. For the Super Admin that means the whole tenant.
- **Steps to reproduce safely (local or staging only):** start the API with `RATE_LIMIT_TESTS=1 NODE_ENV=production`. Send 11 wrong-password sign-ins for one email with 11 different single-entry `X-Forwarded-For` values and `TRUST_PROXY=1`. Every attempt is evaluated, none is blocked, and nothing records that one account was targeted.
- **Recommended fix:**
  - Per-account failure counter with exponential back-off, stored in Postgres keyed by a keyed hash of the normalised email. Example: 5 failures, then 1 minute, doubling up to 30 minutes. Same generic error for locked and wrong-password, so it doesn't leak whether an account exists.
  - TOTP second factor, required for `super_admin` and optional for everyone else (Better Auth `twoFactor` plugin with backup codes). This is not a replacement of the auth system.
  - Emit the failures to monitoring ([F-03](#f-03)).
- **Status:** Open · **Retest:** pending.

### F-03
**Security events are not recorded or alerted on. Severity: Medium (OWASP A09).**

- **Affected:** `backend/src/middleware/error-handler.ts`, `backend/src/middleware/rate-limiters.ts`, `backend/src/lib/auth.ts`.
- **Description:** the code logs 403s at `warn` to stdout. It does not log 401s, rate-limit rejections (429) or failed sign-ins (handled inside Better Auth). Nothing aggregates, alerts on or keeps these beyond Render's short log retention. `audit_logs` covers successful admin changes only.
- **Impact:** a brute-force run, an authorisation probe or an account takeover would go unnoticed. The F-01 exposure is an example: nobody knows whether it was used.
- **Recommended fix:** Phase 7 integration with CampusHub Sentinel (see [PLAN.md](PLAN.md)): asynchronous, signed security events from the API, with detection rules and alerts.
- **Status:** Open · **Retest:** pending.

### F-04
**The database role is over-privileged and the audit log can be rewritten. Severity: Medium.**

- **Affected:** the `DATABASE_URL` in use (user `neondb_owner`, verified on the dev branch; production is set up the same way per `render.yaml`) and `public.audit_logs`.
- **Description:** the API runs as the owner role. It can `DROP` or `ALTER` any table, disable the triggers that enforce booking and complaint rules (`CB004` and `CC003` immutability guards), and `UPDATE`, `DELETE` or `TRUNCATE` `audit_logs`.
- **Impact:** any future injection or code-execution bug in the API becomes full database control, including erasing its own audit trail.
- **Recommended fix:**
  - A `campushub_app` role with `SELECT/INSERT/UPDATE/DELETE` on application tables only, `EXECUTE` on the functions the API calls, and no DDL. Migrations keep running as the owner from CI.
  - Revoke `UPDATE, DELETE, TRUNCATE` on `audit_logs` from the app role, plus a trigger that rejects changes. The trigger must allow the single update the `on delete set null` foreign key needs (`actor_id` → `null` when an account is deleted).
  - Render's `DATABASE_URL` then switches to the new role; that is a dashboard step for you.
- **Status:** Open · **Retest:** pending.

### F-05
**No start-up guard against demo data in production. Severity: Medium.**

- **Affected:** `backend/src/server.ts`. `seed-dev.ts` refuses to *write* to production, but nothing stops a production API from *reading* a seeded database.
- **Description:** this is the root cause that let [F-01](#f-01) persist unnoticed for at least four days.
- **Recommended fix:** with `NODE_ENV=production`, refuse to start, with a clear log line, when the database contains `@demo.edu` accounts, unless `ALLOW_DEMO_DATA=true` is set explicitly (for an intentional public demo).
- **Status:** Open · **Retest:** pending.

### F-06
**Rate-limit state is in memory. Severity: Low.**

- **Affected:** `backend/src/middleware/rate-limiters.ts` (`express-rate-limit` default store) and `auth.ts` (`rateLimit.storage: 'memory'`).
- **Description:** counters reset on every deploy, restart and free-plan spin-down, and would not be shared across instances.
- **Recommended fix:** Better Auth `rateLimit.storage: 'database'` for the auth endpoints. The F-02 per-account counter is in Postgres anyway. The in-memory Express limiters are acceptable for one instance.
- **Status:** Open · **Retest:** pending.

### F-07
**Push endpoint lets the server POST to any HTTPS host. Severity: Low.**

- **Affected:** `shared/src/schemas/index.ts` (`pushSubscriptionBody.endpoint`: any `https://` URL) and `backend/src/lib/push.ts`.
- **Description:** a signed-in user can register an arbitrary HTTPS URL. The server then sends encrypted Web Push POSTs to it whenever that user gets a notification (blind SSRF: no response is returned to the attacker, the body is encrypted, and the user controls how often it fires).
- **Recommended fix:** allow only the known push-service hosts: `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `*.notify.windows.com`, `web.push.apple.com`.
- **Status:** Open · **Retest:** pending.

### F-08
**Venue photo has no decode limit. Severity: Low.**

- **Affected:** `backend/src/lib/image-store.ts` (`render()` calls `sharp(buffer, { failOn: 'error' })` without `limitInputPixels`).
- **Description:** a 5 MB compressed image can declare up to libvips' default of about 268 megapixels, which needs roughly 1 GB to decode. Complaint photos already cap this at 144 MP (`lib/images.ts`). Only the Super Admin can reach this endpoint.
- **Recommended fix:** reuse the complaint-photo limit and signature sniffing.
- **Status:** Open · **Retest:** pending.

### F-09
**Weak password policy. Severity: Low.**

- **Affected:** `shared/src/schemas/index.ts` (`passwordSchema`).
- **Description:** the minimum is 8 characters with at least one letter and one digit; `Password1` passes. Hashing is Better Auth's scrypt, which is fine.
- **Recommended fix:** raise the minimum length (12 for staff and admin accounts), and reject the most common or breached passwords. Use a bundled top-N list rather than a third-party call, to keep sign-up independent of external services.
- **Status:** Open · **Retest:** pending.

### F-10
**Session token in localStorage. Severity: Low.**

- **Affected:** `frontend/src/lib/session-token.ts`, `backend/src/lib/auth.ts` (`expiresIn` 7 days, `updateAge` 1 day).
- **Description:** any script running on the CampusHub origin could read the bearer token. This is a deliberate design: the API is on `onrender.com` and the app on Cloudflare Pages, so cookies would be third-party. The strict CSP (`script-src 'self'`, no `unsafe-eval`) and the absence of `dangerouslySetInnerHTML` keep the XSS risk low. The Super Admin's sessions last as long as a student's.
- **Recommended fix:**
  - Short-term: cap Super Admin sessions at 12 hours (checked in `authenticate`).
  - Long-term: put the app and API on one registrable domain (`app.` and `api.` subdomains), then switch to `HttpOnly; Secure; SameSite=Lax` cookies.
- **Status:** Open (accepted until a custom domain exists) · **Retest:** pending.

### F-11
**Account enumeration through registration. Severity: Low.**

- **Affected:** `POST /api/v1/auth/register` returns `EMAIL_ALREADY_REGISTERED`.
- **Description:** sign-in and password reset do not reveal whether an account exists; registration does. It is throttled to 5 per hour per IP.
- **Recommended fix:** accept the trade-off (the clear message helps students), or switch to an "if this address can register, we've emailed it" flow. Monitoring will flag repeated attempts.
- **Status:** Open · **Retest:** pending.

### F-12
**Dev-only dependency advisories. Severity: Low.**

- **Evidence:** `npm audit --include=dev` → 7 moderate, all from `typescript-eslint` pulling a vulnerable `minimatch` (ReDoS). `npm audit --omit=dev` → **0** in production dependencies.
- **Recommended fix:** `npm update typescript-eslint` (a semver-compatible fix is available), then run lint again.
- **Status:** Open · **Retest:** pending.

### F-13
**CI supply chain. Severity: Info.**

- **Description:** `actions/checkout@v4`, `gitleaks/gitleaks-action@v2` and the other actions are pinned by mutable tag. `npx -y wait-on` installs whatever the latest version is.
- **Recommended fix:** pin actions to commit SHAs (Dependabot can keep them current) and add `wait-on` as a pinned dev dependency.
- **Status:** Open · **Retest:** pending.

### F-14
**Version disclosure. Severity: Info.**

- **Description:** `/health` returns `1.1.0+<commit>`. This is mildly useful to an attacker and useful to you; keep it, or drop the commit hash in production.
- **Status:** Open · **Retest:** pending.

### F-15
**TLS verification disabled on the developer machine. Severity: Info.**

- **Description:** the shell exports `NODE_TLS_REJECT_UNAUTHORIZED=0`, so any Node tool that doesn't override it (CLIs, scripts) accepts forged certificates. The API's database pool sets `rejectUnauthorized: true` explicitly and is not affected. The variable's source is unknown: it is not in the user or machine environment variables.
- **Recommended fix:** find and remove it (check your shell profile, VS Code `terminal.integrated.env.*`, and any `.npmrc` or `.bashrc`).
- **Status:** Open · **Retest:** pending.

### F-16
**`picomatch` ReDoS in development tooling. Severity: Low. Found 2026-11-17, after the Phase 2 retest.**

- **Evidence:**
  - Advisory GHSA-fc5q-39xc-vjpf covers every `picomatch` version; 4.0.7, the latest, is affected. `npm audit` reports
    it through `vitest` → `tinyglobby` and `typescript-eslint`: 6 high in CampusHub, 10 high in Sentinel.
  - Sentinel's production dependencies: **0** (`npm audit --omit=dev`).
  - CampusHub's `--omit=dev` count also shows it. The only reason is that `better-auth` declares `vitest` as an
    *optional peer* for its test helpers (`dist/test-utils`), which the API never imports.
- **Impact:** a crafted glob pattern can make the matcher slow. Only the lint and test tools match globs, and only
  against patterns developers write. No user input reaches them, and the running APIs never load them.
- **Recommended fix:** none available. `npm audit fix --force` would *downgrade* vitest to 3.x and typescript-eslint
  to 8.47, which is worse. Upgrade when `picomatch` publishes a fix, and re-run `npm audit`.
- **Status:** Open (accepted, monitored) · **Retest:** pending upstream.

---

## Phase 2 retest (2026-11-17)

Every result below comes from a run on 2026-11-17 on the developer machine: the local Postgres test and dev clusters,
plus read-only checks against Neon dev. **None of these fixes is deployed yet.** The live API still runs `8f4ea89`.

| Finding | What changed | How it was retested | Result |
|---|---|---|---|
| F-01 | README passwords removed; the F-05 guard prevents a repeat | `GET …/api/v1/settings/public` on the live API | **Fixed** (retested 2026-11-17 18:10 UTC, after the owner switched Render): returns `"Your Institution"`, the production branch's value; `/health/ready` reports the database ok. Earlier the same day it still returned `"Demo College"`. The deployed code is still `8f4ea89`, so the Phase 2 fixes go live with the next deploy. |
| F-02 sign-in | `backend/src/lib/login-throttle.ts` + Better Auth before/after hooks. Per account + IP: 5 failures in 15 min → 1–15 min lock. Per account: 20 failures in 60 min → 15 min. HMAC keys, no emails stored. Reset clears the locks. | `tests/integration/auth-hardening.test.ts` (7 tests) | Pass. The 6th attempt, even with the right password, gets `429 SIGN_IN_LOCKED` with `Retry-After`. An unknown email answers identically. No `@` in stored keys. Other accounts unaffected. A password reset lifts the lock. A 403 deactivated account is not counted. |
| F-02 two-step | TOTP for `super_admin` (`modules/mfa`, `requireMfa` in the guard chain, `/admin/two-factor` page, profile card, `reset-mfa` scripts). AES-256-GCM secret, hashed recovery codes, single-use time steps, 5-failure lock. | Integration (9 tests) and e2e `two-factor.spec.ts` (browser, `E2E_MFA=1`); unit tests against the RFC 6238 and RFC 4226 vectors | Pass. Enrolment required before any admin API (`403 MFA_ENROLLMENT_REQUIRED`). A new session needs a code (`403 MFA_REQUIRED`). Replayed and wrong codes are refused. A recovery code works once and is audited. Locked after 5 wrong codes (`429 MFA_LOCKED`). Members are unaffected. In the browser: temporary password → setup → recovery codes survive a window-focus refetch → dashboard → sign out → code required → wrong code refused → right code accepted. |
| F-05 | `backend/src/lib/demo-guard.ts`, called before `listen` in `server.ts` | The real API started with `NODE_ENV=production` against the Neon dev branch (read-only count query); unit tests for each branch of the guard | Pass. Exit code 1 with `Refusing to start … (demoAccounts=7)`. With `ALLOW_DEMO_DATA=true` it starts (`API listening`). |
| F-07 | `isAllowedPushEndpoint`: FCM, Mozilla, Apple, WNS only; https, no credentials, port 443 | Unit (13 cases, including suffix tricks and the metadata IP); integration | Pass. `https://attacker.example/hook` → 400; an FCM endpoint passes validation |
| F-08 | Venue photos: magic-byte check + `limitInputPixels` (144 MP), as for complaint photos | Code review; typecheck | Not exercised by a test (the Neon store isn't used in tests) |
| F-09 | `isCommonPassword` in `passwordSchema` (register, change, admin-created, reset); 12+ characters for Super Admin (change, reset, `create-super-admin`) | Unit (27 cases); integration | Pass. `Password123` refused on change and register; an 11-character Super Admin password refused on change and reset. The suites' own passwords still accepted. |
| F-10 | Super Admin session lifetime capped (`SUPER_ADMIN_SESSION_HOURS`, default 12); the expired session is deleted | Integration | Pass. A session aged 13 h → `401` "Your admin session has ended" |
| F-12 | `typescript-eslint` 8.73.0 | `npm audit --include=dev` | Pass at the time: **0 vulnerabilities** (production and dev). A later advisory in the same tooling is tracked as [F-16](#f-16). |

**Full regression run (2026-11-17):** typecheck clean; lint clean (including `campushub/sql-no-values`).

| Suite | Tests passed |
|---|---|
| shared | 62 |
| backend unit | 60 |
| frontend | 39 |
| database | 22 |
| integration | 74 |
| e2e (desktop, mobile WebKit, tablet) | 20 |
| e2e `two-factor` (MFA on) | 1 |

**Deployment notes:**
- Migration `20261117000100_auth_hardening.sql` must reach every database the new code runs against. It is additive (three new tables). CI's deploy job migrates production. Neon dev needs it before local development against dev works again: `GET /me` queries `user_mfa`.
- After deployment, the production Super Admin sets up an authenticator at the next sign-in.

---

## What held up

These were checked and are sound. Code review means no test was run. Some are also covered by existing tests, as noted.

| Area | What was checked | Result |
|---|---|---|
| Broken access control / IDOR | Every booking read and write is filtered by `requester_id`; complaints by `reporter_id` (reporter) or `department_id` (staff), under a row lock; notifications and push subscriptions by `user_id`. Unknown and foreign IDs both return 404 (no existence oracle). | Sound. Covered by tests `BT-BKG-07` and `CBT-05`. |
| Function-level authorisation | Each router declares its roles; a start-up self-check refuses any non-public router without a role list (`routes.ts` `mountRoutes`). Admin routes require `super_admin`; staff routes also require an active service department. | Sound |
| Privilege escalation | `createUserBody` and `updateUserBody` limit `role` to `MEMBER_ROLES`; Super Admin is grantable only by the SQL function `provision_super_admin()` (EXECUTE revoked from PUBLIC). Admins can't edit themselves or another Super Admin (`PROTECTED_ACCOUNT`). The last Super Admin can't delete their account. | Sound |
| Mass assignment | Every request body is a Zod `strictObject`; unknown keys are rejected. Dynamic `UPDATE`s take column names from fixed maps. | Sound |
| SQL injection | All values are bound parameters. A custom ESLint rule (`campushub/sql-no-values`) fails the build on interpolated values inside `.query` template literals. `ORDER BY` comes from whitelists, and `LIKE` input is escaped. | Sound |
| XSS | No `dangerouslySetInnerHTML`, `innerHTML` or `eval` in the frontend. Email templates HTML-escape every value. CSV export guards against formulas. | Sound |
| CSRF | The API authenticates only with a `Bearer` header, so a cross-site form or image request carries no credentials. CORS has `credentials: false`. Better Auth checks the origin on its own routes. | Not applicable by design |
| CORS | The origin allowlist comes from `CORS_ORIGINS`; no wildcard. | Sound |
| Security headers (frontend) | `_headers` sets a strict CSP (`script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`), HSTS (2 years), `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy` and `Permissions-Policy`. Source maps are off (Vite default). The dev-only `/dev/break-ui` route is removed from production builds. | Sound (header delivery to be confirmed with ZAP in Phase 8) |
| Security headers (API) | `helmet()` defaults; `x-powered-by` disabled; `Cache-Control: no-store` on authenticated responses. | Sound |
| Complaint photo upload | Max 3 files of 5 MB; type taken from the file's magic bytes, then a full decode with a 144 MP cap, then re-encoded to WebP, which strips EXIF/GPS and any appended payloads. Private bucket with 10-minute presigned URLs. | Sound |
| Password reset | Tokens expire after 1 hour; all sessions are revoked on reset; the email is sent without awaiting it, so response time doesn't reveal whether the account exists; the reset link points only at `FRONTEND_URL`. | Sound |
| Session invalidation | Password change revokes the other sessions; deactivation revokes all sessions and push devices; sign-in is refused for deactivated accounts in a Better Auth hook. | Sound |
| Error handling | Responses carry a code, a safe message and a request ID. Stack traces and SQL errors are logged server-side only. | Sound |
| Secrets | `.env*` is git-ignored (except `.env.example` and the throwaway `backend/.env.test`). No secret file has ever been committed (`git log --all --diff-filter=A`). CI greps the built bundle for secret patterns and runs gitleaks. Env vars are Zod-validated, and `fake` stores are refused in production. | Sound |
| Cron endpoint | `/internal/jobs/run` requires a ≥ 32-character bearer secret, compared in constant time, and is rate-limited. | Sound |
| Database TLS | The pool sets `rejectUnauthorized: true` and refuses Neon's `-pooler` host. | Sound |
| Backups | Weekly `pg_dump`, AES-256 encrypted with `gpg` before upload, kept for 90 days as a GitHub artifact. | Design reviewed in Phase 1, but it was **not running** (F-21), and the artifact is downloadable by any GitHub user because the repository is public (F-22). Restore not yet tested. |

## Architecture as inspected

- **Frontend:** React 19 SPA (Vite, React Router data router, TanStack Query, Tailwind) on Cloudflare Pages. Role guards in `routes/guards.tsx` are for user experience only; every permission is re-checked by the API. The session token is in `localStorage`. Realtime runs over Ably, using per-user channels with tokens scoped to that user.
- **Backend:** Express 5 on Render (free plan, one instance, `trust proxy 1`). Middleware order: request ID → pino logging (with redaction) → helmet → CORS → global rate limit → health checks → Better Auth (`/api/auth/*`) → JSON body parser (100 kB) → routers, each with its guard chain → 404 → error handler. 11 routers with about 90 endpoints.
- **Auth:** self-hosted Better Auth 1.7.18 on the API's own Postgres tables (`auth_*`), using the `bearer` plugin. Public sign-up is disabled; accounts are created by self-registration (`/api/v1/auth/register`, student role only), by the Super Admin, or by the provisioning script.
- **Roles:** `student`, `faculty_staff`, `department_staff` (bound to a service department) and `super_admin`.
- **Database:** Neon Postgres 18, project `campus-hub`, with branches `production` and `dev`. Integrity is enforced in the database itself: exclusion constraints stop overlapping confirmed bookings, and triggers guard status transitions and immutable columns. Migrations use dbmate, forward-only, run by CI before deploy.
- **Storage:** Neon Object Storage. `venue-photos` is public-read; `complaint-photos` is private and served through presigned URLs.
- **Integrations:**
  - Brevo (email)
  - VAPID Web Push
  - Ably (realtime)
  - Cloudinary (optional, not used)
  - cron-job.org plus a GitHub Actions backup scheduler for `/internal/jobs/run`
- **Logging:** pino JSON to stdout, with authorisation headers, cookies and passwords redacted. Admin actions are written to `audit_logs` in the same transaction as the change.

## Tooling status

| Tool | Status |
|---|---|
| `npm audit` | Run (see F-12) |
| gitleaks | Runs in CI. Not installed locally; Phase 3 adds a pinned, checksum-verified download. |
| Semgrep | Not installed. Planned through pip, or in CI if Python 3.15 wheels aren't available. |
| OSV-Scanner | Not installed. Planned as a pinned binary. |
| OWASP ZAP baseline | No Docker locally; planned as a GitHub Actions job against a staging or local URL. |

Not run in Phase 1: any active test (authorisation matrix, injection strings, rate-limit triggering) and any scanner other than `npm audit`. These run in Phase 8, against a local or staging environment only.

---

## Phase 7 retest (2026-11-18)

All runs were **local**: the CampusHub API on the local dev and test databases, and Sentinel on its own local
database. Nothing was sent to the live site. Every attack request carried `X-Sentinel-Simulated: 1`, so Sentinel
stored them as simulated (never emailed, left out of the health status, no IP scoring or blocking).

| Finding | Check | Result |
|---|---|---|
| F-03 | Integration tests against a fake Sentinel that verifies every HMAC signature (`backend/tests/integration/sentinel.test.ts`, 11 tests) | **Pass.** Sign-in failures and successes (accounts as a keyed hash; no email in any event), 403/401 on the admin API, record lookups that miss (IDs replaced by `:id`), injection-like input (field names only), role and settings changes (sent only after commit), traffic counts, the simulated flag. |
| F-03 | Local end-to-end: real CampusHub API → real Sentinel API. Simulated attacks: 12 wrong passwords for 12 accounts, a student calling the admin API 3 times, one SQL-injection-like query, 2 record misses | **Pass.** 19 events stored, all marked simulated. Alerts opened: `brute_force_ip` (high), `password_spraying` (high), `member_admin_api` (escalated to high). 0 events contained an email address; 0 suspicious-IP rows were created. |
| F-03 | Blocklist, end to end: a 75-second block of the loopback addresses written to Sentinel's database | **Pass.** CampusHub answered `403 ACCESS_BLOCKED` after its next 60-second pull, `/health` stayed 200, access returned on its own at expiry, and Sentinel received 1 `blocklist.hit` event. |
| F-03 | Sentinel stopped while CampusHub served requests | **Pass.** Requests were answered normally (29 ms for two requests). The event made during the outage was delivered after Sentinel restarted. |
| F-04 | `backend/tests/db/03-security-hardening.test.ts` (4 tests) | **Pass.** `UPDATE` and `DELETE` on `audit_logs` are refused for the owner too (`CA001`), except the account-deletion foreign key nulling `actor_id`. `campushub_app` is refused `UPDATE`/`DELETE`/`TRUNCATE` on `audit_logs`, `TRUNCATE`, `DROP`, `ALTER ... DISABLE TRIGGER`, `CREATE TABLE` and `schema_migrations` (`42501`). |
| F-04 | The full CampusHub integration and concurrency suite with the API connected as `campushub_app` (`select current_user` confirmed) | **Pass**, 90/90. The API needs no privilege beyond the role's. |
| F-06 | `backend/tests/integration/auth-rate-limit.test.ts` (5 tests) | **Pass.** 10 allowed, then refused with the time left; the count is capped; a new window starts after the old one; 25 concurrent requests let exactly 10 through; addresses and paths are kept apart. |

**Found and fixed in Sentinel during this phase:** simulated events could raise an address's risk score and, for a
rule with automatic blocking switched on, block it. Simulated traffic now never scores or blocks
(`security.test.ts` covers it).

**Not yet retested on production:** none of this is deployed. F-04 needs the owner steps in CampusHub's README
("Database roles"). Re-check after deployment: Render's `DATABASE_URL` user is `campushub_app`, and Sentinel's
overview shows CampusHub's ingestion as current.

---

## Phase 8 validation (2026-11-19)

**What "local staging" means here.** No separate staging deployment exists, so active testing ran against a local
copy: the CampusHub API on the local dev database, configured like production where it matters (two-step
verification required, one trusted proxy hop) and reporting to a local Sentinel. Every active request carried
`X-Sentinel-Simulated: 1`. Production received only GET and CORS preflight requests.

### Production, passive only (`security:headers`, 2026-11-18 19:36 UTC)

56 pass, 0 fail across the API, the site (`campushubweb.pages.dev`) and Sentinel:
- HTTPS everywhere; plain HTTP redirects; certificates valid for 32 more days.
- HSTS, nosniff and Referrer-Policy present. The site CSP has `script-src 'self'` and refuses framing.
- CORS grants nothing to a foreign origin and never allows credentials.
- Protected endpoints refuse anonymous calls and made-up tokens. Sentinel's API and ingestion refuse unauthenticated
  and unsigned calls, and a cross-site POST is refused (CSRF).
- No credentials in the site bundle, no published source maps, no `/.env`. Better Auth's sign-up endpoint is off.
- The live API runs commit `4681462` on the production database ("Your Institution").

### Static (`security:scan`)

- **Dependencies:** 0 known vulnerabilities in 854 packages, production and development. 450 registry signatures
  verified. The F-16 advisory no longer appears in `npm audit`; its acceptance entry stays until its review date.
- **Secrets:** 326 working-tree files, the built site, and all 41,805 lines ever added across 8 commits: no
  credentials. The only hits are the local test values in `backend/.env.test` and test fixtures.
- **Static analysis:** no eval, raw HTML, TLS bypass, CORS wildcard, open redirect, or request value in SQL. All ~30
  SQL template interpolations were reviewed by hand: placeholders from the `Where` builder, fixed `ORDER BY` maps
  and constant fragments. The reviews are recorded in `security/accepted.json`; any new interpolation is flagged.
- **Not executed:**
  - Semgrep: it doesn't install on this machine's Python 3.15. It runs in `security.yml` on GitHub, not yet
    triggered.
  - OWASP ZAP baseline: a manual workflow input.

### Authorization matrix (`backend/tests/integration/authz-matrix.test.ts`)

The test sends every one of the 91 routes in the router table as anonymous, student, faculty, department staff and
Super Admin. **0 violations:**
- Anonymous gets 401 everywhere except the 2 pinned public routes.
- Roles outside a router get `403 FORBIDDEN`, and admitted roles always pass the guard.
- The 5 deliberately narrower routes are listed with reasons: the member dashboard, and the four two-step routes
  that are Super Admin only.
- Better Auth's sign-up, update-user, change-email, delete-user, change-password, session-listing and
  account-linking endpoints answer 404.

The test runs in CI, so a new route is covered automatically.

### Active probe (`security:probe --xff --spike 400`, local staging): 67 pass, 0 fail

- **Sign-in:**
  - spraying and brute force are refused;
  - the per-account lock engages on the 6th try, with `Retry-After`;
  - existing and unknown accounts get the same answer and the same timing (136 ms vs 142 ms median);
  - forged and signed-out tokens are refused;
  - password reset reveals nothing and refuses a foreign redirect (`INVALID_REDIRECT_URL`).
- **Access:**
  - anonymous, faculty and staff are refused on the admin API;
  - a student can't read or act on another student's complaint (404, no existence leak);
  - another department can't read it; the right one can;
  - 22 guessed booking ids all return 404;
  - injected role, `__proto__`, `status` and `requesterId` fields are rejected.
- **Input:**
  - 21 SQL / script / traversal / template payloads across 3 search endpoints: no 5xx, no leak, no filter bypass;
  - a `pg_sleep(3)` payload returned in normal time;
  - stored script text is served as JSON only;
  - oversized and malformed bodies get clean 400s; encoded traversal and NUL bytes are harmless.
- **Uploads:**
  - rejected, with the API staying healthy: an SVG with a script, HTML posing as JPEG, a 3.6-gigapixel
    decompression bomb, and a 6 MB file;
  - an image with an appended PHP payload is accepted and re-encoded to WebP, with the payload gone;
  - a photo URL without its signature is refused.
- **Rate limits:** self-registration is refused after 5 per hour per address, with `Retry-After`.
- **Super Admin:**
  - the admin area is closed until two-step verification is set up;
  - a wrong enrolment code is refused, and a new session is held at the second step;
  - 6 wrong codes give `MFA_LOCKED`, and even the right code is refused while paused;
  - the API can't create a Super Admin or change one;
  - the probe's setting and role changes were reverted.

### Detection coverage: all 15 Sentinel rules fired

`account_under_attack`, `admin_new_ip`, `admin_probing`, `brute_force_ip`, `config_change`, `injection_probing`,
`member_admin_api` (escalated to high), `mfa_failures`, `object_enumeration`, `password_spraying`,
`privilege_change`, `rate_limit_abuse`, `server_health`, `suspicious_uploads`, `traffic_spike`.

- **Simulated preconditions (not real traffic):**
  - `traffic_spike` needed 20 minutes of history, seeded at 10 requests a minute, then a 400-request burst;
  - `server_health` came from 12 `db.error` events during a deliberate 20-second stop of the local database.
- **Side effects that must not happen:** 0 blocks created, 0 addresses scored, 0 events containing an email or
  password.
- **Marked simulated:** every event and alert, except `traffic_spike`. Request counts carry no simulated flag, so a
  spike caused by a test looks real and would email. Accepted; warn the team before a staging load test.
- **During the outage:** `/health` stayed 200 (Render keeps the instance) and `/health/ready` returned 503.

### Reports

The combined report (83 pass, 0 fail, 0 warn) was uploaded to the local Sentinel and checked in a real browser. The
reports list and the detail view (Problems / All checks) work, with 0 px overflow at 390 px and 320 px.

### Not covered (honest limits)

- No active test of production, by design. No staging deployment exists to test the as-deployed configuration
  (Render proxy, Neon, Cloudflare).
- Semgrep and ZAP results are pending their first GitHub run.
- No manual penetration test and no code-level fuzzing.
- The probe exercises representative endpoints, not every parameter of every route. The authorization matrix covers
  every route, but only for the guard decision.
