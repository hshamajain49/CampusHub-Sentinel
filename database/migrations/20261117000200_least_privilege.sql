-- migrate:up
-- =====================================================================
-- Least privilege and tamper resistance.
--
-- 1. sentinel_app: the role the API connects as in production (DML only, no DDL). Created NOLOGIN here; the
--    operator gives it a password once (README "Database roles"). Migrations keep running as the owner.
-- 2. Append-only records: audit_logs, security_events and incident_notes can't be updated or deleted by
--    sentinel_app (privileges), and triggers refuse it for every role, the owner included, outside the
--    retention purge. Administrator accounts are deactivated, never deleted.
-- 3. sentinel_purge(): the one way old rows leave, by the retention settings. SECURITY DEFINER, so the API can run
--    it without holding DELETE on the protected tables.
--
-- New tables get sentinel_app's DML grants automatically (default privileges). A new append-only table must also
-- revoke UPDATE/DELETE and attach public.forbid_change().
-- =====================================================================

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'sentinel_app') then
    create role sentinel_app nologin;
  end if;
end $$;

grant usage on schema public to sentinel_app;
grant select, insert, update, delete on all tables in schema public to sentinel_app;
grant usage, select on all sequences in schema public to sentinel_app;
alter default privileges in schema public grant select, insert, update, delete on tables to sentinel_app;
alter default privileges in schema public grant usage, select on sequences to sentinel_app;

revoke update, delete, truncate on public.audit_logs, public.security_events, public.incident_notes from sentinel_app;
revoke delete, truncate on public.administrator_accounts from sentinel_app;
do $$
begin
  if to_regclass('public.schema_migrations') is not null then
    execute 'revoke all on public.schema_migrations from sentinel_app';
  end if;
end $$;

-- ───────────────────────────── append-only triggers ─────────────────────────────
create function public.forbid_change() returns trigger language plpgsql as $$
begin
  -- Only sentinel_purge() deletes, and only after setting this transaction-local flag.
  if tg_op = 'DELETE' and current_setting('sentinel.purge', true) = 'on' then
    return old;
  end if;
  if tg_op = 'TRUNCATE' and current_setting('sentinel.purge', true) = 'on' then
    return null;
  end if;
  raise exception '% is append-only (% refused)', tg_table_name, tg_op using errcode = 'SA001';
end $$;

create trigger audit_logs_append_only before update or delete on public.audit_logs
  for each row execute function public.forbid_change();
create trigger audit_logs_no_truncate before truncate on public.audit_logs
  for each statement execute function public.forbid_change();
create trigger security_events_append_only before update or delete on public.security_events
  for each row execute function public.forbid_change();
create trigger security_events_no_truncate before truncate on public.security_events
  for each statement execute function public.forbid_change();
create trigger incident_notes_append_only before update or delete on public.incident_notes
  for each row execute function public.forbid_change();
create trigger incident_notes_no_truncate before truncate on public.incident_notes
  for each statement execute function public.forbid_change();

-- ───────────────────────────── retention ─────────────────────────────
create function public.sentinel_purge() returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  out jsonb := '{}';
  n integer;
begin
  perform set_config('sentinel.purge', 'on', true);

  delete from analytics_events e using monitored_applications a
   where a.id = e.app_id and e.occurred_at < now() - make_interval(days => a.retention_analytics_days);
  get diagnostics n = row_count; out := out || jsonb_build_object('analytics_events', n);

  delete from analytics_sessions s using monitored_applications a
   where a.id = s.app_id and s.last_activity_at < now() - make_interval(days => a.retention_analytics_days);
  get diagnostics n = row_count; out := out || jsonb_build_object('analytics_sessions', n);

  delete from analytics_visitors v using monitored_applications a
   where a.id = v.app_id and v.last_seen_at < now() - make_interval(days => a.retention_analytics_days)
     and not exists (select 1 from analytics_sessions s where s.visitor_id = v.id);
  get diagnostics n = row_count; out := out || jsonb_build_object('analytics_visitors', n);

  delete from traffic_minutes t using monitored_applications a
   where a.id = t.app_id and t.minute < now() - make_interval(days => a.retention_security_days);
  get diagnostics n = row_count; out := out || jsonb_build_object('traffic_minutes', n);

  -- Evidence behind an alert that is still open, or an incident still being worked on, is kept.
  delete from security_events e using monitored_applications a
   where a.id = e.app_id and e.occurred_at < now() - make_interval(days => a.retention_security_days)
     and not exists (
       select 1 from alert_events ae
         join security_alerts al on al.id = ae.alert_id
         left join security_incidents i on i.id = al.incident_id
        where ae.event_id = e.id
          and (al.status in ('open', 'acknowledged') or i.status in ('new', 'investigating')));
  get diagnostics n = row_count; out := out || jsonb_build_object('security_events', n);

  delete from audit_logs where occurred_at < now() - interval '730 days';
  get diagnostics n = row_count; out := out || jsonb_build_object('audit_logs', n);

  delete from administrator_sessions where expires_at < now() - interval '30 days' or revoked_at < now() - interval '30 days';
  get diagnostics n = row_count; out := out || jsonb_build_object('administrator_sessions', n);

  delete from login_throttle where updated_at < now() - interval '1 day' and (locked_until is null or locked_until < now());
  get diagnostics n = row_count; out := out || jsonb_build_object('login_throttle', n);

  perform set_config('sentinel.purge', 'off', true); -- the rest of the caller's transaction gets no exemption
  return out;
end $$;

revoke all on function public.sentinel_purge() from public;
grant execute on function public.sentinel_purge() to sentinel_app;

-- migrate:down
-- Forward-only: intentionally empty. dbmate requires the marker.
