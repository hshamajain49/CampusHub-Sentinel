# Deploying and operating CampusHub Sentinel

The runbook for the whole monitoring setup: Sentinel itself, and the pieces of CampusHub that talk to it. Settings
are described in [README "Environment"](../README.md#environment); this file covers order, procedures and what to do
when something happens. CampusHub's own runbook is `docs/DEPLOYMENT.md` in the CampusHub repository (public: it holds
no values).

## 1. The system

```
 browsers ──page views (site key)──────────────────────────────▶ Sentinel /collect
 CampusHub site (Cloudflare Pages)                                      │
 CampusHub API (Render) ──signed events, request counts (HMAC)──▶ Sentinel /ingest/v1/events
                        ◀──active blocks, every 60 s────────────  Sentinel /ingest/v1/blocklist
 CampusHub CI (security.yml) ──signed scan reports──────────────▶ Sentinel /ingest/v1/reports
 developers ──dashboard (cookie session + TOTP)─────────────────▶ Sentinel /  and /api/*
                                                                         │
                                                         Neon project campushub-sentinel
```

- **Sentinel:** Render web service `campushub-sentinel` (free plan). The API serves the dashboard on the same origin.
  `render.yaml`; `autoDeploy: false`.
- **Database:** Neon project `campushub-sentinel`, separate from CampusHub's `campus-hub`. The app connects as
  `sentinel_app` (data only, append-only tables); migrations run as the owner.
- **Isolation:** CampusHub never depends on Sentinel. If Sentinel is down, CampusHub keeps working, queues up to
  1,000 events, and lets existing blocks expire on schedule.

## 2. Where every secret lives

| Value | Lives in | Used by |
|---|---|---|
| `DATA_ENCRYPTION_KEY` | Render (Sentinel), and a copy in your password manager | Sentinel: encrypts TOTP and ingestion secrets, keys every HMAC |
| Sentinel `DATABASE_URL` (`sentinel_app`) | Render (Sentinel) | Sentinel API |
| Owner connection string | GitHub `SENTINEL_OWNER_DATABASE_URL` (Sentinel repo) | CI migrations |
| `SENTINEL_RENDER_DEPLOY_HOOK_URL` | GitHub (Sentinel repo) | CI deploy |
| `BREVO_API_KEY`, `ALERT_EMAIL_FROM` | Render (Sentinel); its own Brevo key, not CampusHub's | Alert emails |
| Ingestion key id + secret | Render (CampusHub API) **and** GitHub `SENTINEL_INGEST_KEY_ID` / `SENTINEL_INGEST_SECRET` (CampusHub repo) | Signing events and scan reports |
| `SENTINEL_URL` | Render (CampusHub API), GitHub (CampusHub repo) | Where to send them |
| Site key (public) | Cloudflare Pages `VITE_SENTINEL_SITE_KEY` | Browser page views |

Losing `DATA_ENCRYPTION_KEY` makes every stored authenticator secret and ingestion secret unreadable. Keep the copy.

## 3. First-time setup (or rebuilding from scratch)

1. **Database:** create the Neon project `campushub-sentinel` (Singapore) and copy the owner's **direct** string.
2. **Repository:** push this repository to a private GitHub repo. Add the secrets `SENTINEL_OWNER_DATABASE_URL` and
   `SENTINEL_RENDER_DEPLOY_HOOK_URL`, and optionally an environment `production` with required reviewers.
3. **Render:** New, then Blueprint, then this repo. Enter `APP_ORIGIN`, `DATA_ENCRYPTION_KEY` (generate it with
   `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`), `BREVO_API_KEY` and
   `ALERT_EMAIL_FROM`. Put the owner string in `DATABASE_URL` for now.
4. **Migrations:** push to `main`. CI runs the migrations, which creates `sentinel_app`, then deploys.
5. **App role:** in the Neon SQL editor, run `alter role sentinel_app with login password '<64 random chars>';`.
   Then switch Render's `DATABASE_URL` to `sentinel_app`. Use SQL, not the console: console-created roles join
   `neon_superuser`.
6. **First owner:** run `admin:create` with `ENV_FILE=none` and the production `DATABASE_URL` and
   `DATA_ENCRYPTION_KEY` in the shell. Sign in and set a new password. (With `MFA_MODE=required` you also set up an
   authenticator: **save the recovery codes**.)
7. **Register CampusHub:**
   `npm run app:register -w @sentinel/backend -- --slug campushub --name CampusHub --origin https://<CampusHub site>`.
   It prints the site key and the ingestion key id and secret (the secret is shown once).
8. **Connect CampusHub:**
   - its Render API gets `SENTINEL_URL`, `SENTINEL_INGEST_KEY_ID` and `SENTINEL_INGEST_SECRET`;
   - Cloudflare Pages gets `VITE_SENTINEL_URL` and `VITE_SENTINEL_SITE_KEY`, and the site must be redeployed;
   - the CampusHub GitHub repo gets the same three `SENTINEL_*` secrets, for the weekly scan.
9. **Check:** the overview shows CampusHub's ingestion as current, visitors appear, and a manual
   **Security scan** run in the CampusHub repo shows up under Audit Reports.

## 4. A normal deploy

Push to `main`. CI runs typecheck, lint and tests, plus a secret scan. Only if they pass, the `deploy` job:
1. applies migrations as the owner;
2. calls the deploy hook.

The new code therefore never runs before its tables exist. Migrations are forward-only (no `down`), so write them
additive: the previous release must keep working against the new schema.

**Check it:**
- `GET /health` shows the new commit.
- From the CampusHub repo, `npm run security:headers -- --sentinel https://<sentinel>` has 0 failures.
- You can sign in.

**Roll back:** Render, then **Deploys**, then the previous deploy. Because migrations are additive, the older code
runs fine.

## 5. Accounts

- **Add a developer:** Settings, then Developers (owner, after re-confirming with password and code). Or use the
  `admin:create` script. They set a password at first sign-in (and an authenticator, with `MFA_MODE=required`).
- **Remove a developer:** deactivate them (accounts are never deleted, so the audit log stays attributable). Their
  sessions end at once.
- **Two-step verification** is **off** for now (`MFA_MODE=off`): sign-in and sensitive actions ask for the password
  only. Set `MFA_MODE=required` on Render to turn it back on; authenticators already set up are kept.
- **Lost authenticator** (with `MFA_MODE=required`): another owner resets it from Settings. With no owner able to sign in, run
  `npm run admin:reset-mfa -w @sentinel/backend -- --email <address>` with database access.
- **Alert email preferences:** each developer chooses a minimum severity (default high) and quiet hours in Settings.
  Critical alerts ignore quiet hours. Simulated alerts are never emailed.

## 6. Rotating secrets

| What | How | Effect |
|---|---|---|
| Ingestion secret | Dashboard (owner) or `npm run app:rotate-secret -w @sentinel/backend -- --slug campushub`. Then update the CampusHub API on Render and the CampusHub GitHub secrets. | The old secret stops at once. CampusHub queues events (up to 1,000) until it has the new pair. |
| `sentinel_app` password | `alter role sentinel_app with login password '…'`, then Render `DATABASE_URL` | Sentinel can't connect until Render restarts with the new value |
| Owner password | Neon console, then GitHub `SENTINEL_OWNER_DATABASE_URL` | Only CI migrations are affected |
| `DATA_ENCRYPTION_KEY` | Avoid. If it leaked: set a new one, re-run `app:rotate-secret`, then reset every developer's authenticator | Stored TOTP and ingestion secrets become unreadable |
| Brevo key | Brevo, then Render | Alert emails stop until updated |

## 7. When an alert arrives

Open the alert (Security Threats). It shows the rule, the evidence (sample events), the source address and the
account. Then:

1. **Triage:** acknowledge it. If it's benign, mark it **false positive** (that starts a cooldown for the same
   rule and group). If it's serious, open an **incident** and keep notes there.
2. **Contain** (owners, re-confirmed): **block** the address or range for a set time. CampusHub enforces blocks
   within 60 seconds. Allowlist the campus gateway, so a block can never cut off the whole campus.
3. **Act in CampusHub** as needed: deactivate an account, reset a password (that also lifts its sign-in lock), reset
   a Super Admin's two-step verification (`reset-mfa:prod`), rotate a leaked secret.
4. **Close:** resolve the alert and record the outcome in the incident.

| Rule | What it usually means | First moves |
|---|---|---|
| `brute_force_ip`, `password_spraying` | Password guessing from one address | Per-account locks already slow it. Block the address if it continues. |
| `account_under_attack` | One account targeted from several addresses | Tell the account owner. Force a password reset if there's any sign of success. |
| `admin_probing`, `member_admin_api` | Someone probing the admin API | Check whether the member account is compromised. Block anonymous probers. |
| `object_enumeration` | Guessing booking or complaint ids | Ownership checks hold (404s). Check the account and consider deactivating it. |
| `injection_probing`, `suspicious_uploads` | Attack tooling at work | Observed only; validation is the control. Block if persistent. |
| `privilege_change` | A role changed, or a **new Super Admin appeared** | Confirm it was planned. An unexplained Super Admin is a critical incident: deactivate it, reset admin passwords, rotate `BETTER_AUTH_SECRET`, review the CampusHub audit log. |
| `config_change` | A booking or registration setting changed | Confirm it with the Super Admin |
| `admin_new_ip` | The Super Admin signed in from a new address | Confirm with them |
| `mfa_failures` | Wrong two-step codes for a Super Admin | Someone may hold the password: reset it |
| `rate_limit_abuse`, `traffic_spike` | Heavy traffic | Find out whether it's an event on campus or abuse; block if abuse |
| `server_health` | Repeated 5xx or database errors | Check Neon and Render; CampusHub's `/health/ready` shows the database |

## 8. Failure modes

| Symptom | Cause | Response |
|---|---|---|
| Health "warning", ingestion stale | The CampusHub API is asleep (free plan, at night), or the ingestion secret is wrong | Expected at night. By day, check CampusHub's logs for "Sentinel unreachable" or 401s. |
| No visitors | Site key or origin mismatch, or most visitors send Do-Not-Track / GPC | Check the registered origin (Settings, then Applications) matches the site exactly |
| No alert emails | `EMAIL_TRANSPORT` isn't `brevo`, an unverified sender, or preferences above the alert's severity | Check the Render log for "alert notification failed" |
| Sentinel down | Render or Neon | CampusHub is unaffected; events queue. Fix and redeploy. |
| Dashboard 403 on every action | `APP_ORIGIN` doesn't match the address in the browser | Make them identical (scheme and host) |

## 9. Housekeeping

- **Retention** runs in-process every 6 hours: analytics 395 days, security events 90 days (evidence of open alerts
  and incidents is kept), audit log and scan reports 2 years.
- **Weekly:** the CampusHub **Security scan** workflow uploads a report. Review failures and warnings under Audit
  Reports.
- **Quarterly, or before a big release:** run the active probe against a local or staging copy:
  `npm run security:audit -- --target <local api> --xff --upload`. See CampusHub `security/README.md`; never point
  it at production.
- **When a review date passes:** entries in CampusHub's `security/accepted.json` turn back into warnings. Re-decide
  them.
- **Backups:** Sentinel has no `pg_dump` workflow; it relies on Neon's point-in-time restore, which is limited on the
  free plan. Add a backup like CampusHub's `backup.yml` if the history matters to you.

## 10. Free-plan limits

Both services are on Render's free plan. Free services sleep after 15 minutes without requests, and draw on one
monthly pool of free instance hours per workspace. CampusHub reports to Sentinel every minute while it is awake, so
Sentinel is awake whenever CampusHub is. Two services awake most of the day can use up the pool before the month
ends, and Render then suspends them until the next month. Watch Render's usage page in the first month. If it's
tight, move Sentinel to a paid instance; nothing else changes.
