-- migrate:up
-- Security scan reports uploaded by a monitored app's tooling (CampusHub: npm run security:audit -- --upload).
-- Signed like every ingestion call. Append-only: a report is evidence of what was checked and found at the time,
-- so nobody edits or deletes one; sentinel_purge_reports() removes reports older than two years.

create table public.scan_reports (
  id           uuid        primary key default gen_random_uuid(),
  app_id       uuid        not null references public.monitored_applications (id),
  received_at  timestamptz not null default now(),
  started_at   timestamptz not null,
  finished_at  timestamptz not null,
  source       text        not null check (length(source) between 1 and 80),
  environment  text        not null check (environment in ('local', 'staging', 'production', 'ci')),
  git_commit   text        check (git_commit ~ '^[0-9a-f]{4,40}$'),
  summary      jsonb       not null,
  sections     jsonb       not null,
  constraint scan_reports_times check (finished_at >= started_at)
);
create index scan_reports_app_idx on public.scan_reports (app_id, received_at desc);

grant select, insert on public.scan_reports to sentinel_app;
revoke update, delete, truncate on public.scan_reports from sentinel_app;

create trigger scan_reports_append_only before update or delete on public.scan_reports
  for each row execute function public.forbid_change();
create trigger scan_reports_no_truncate before truncate on public.scan_reports
  for each statement execute function public.forbid_change();

create function public.sentinel_purge_reports() returns integer
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  n integer;
begin
  perform set_config('sentinel.purge', 'on', true);
  delete from scan_reports where received_at < now() - interval '730 days';
  get diagnostics n = row_count;
  perform set_config('sentinel.purge', 'off', true);
  return n;
end $$;

revoke all on function public.sentinel_purge_reports() from public;
grant execute on function public.sentinel_purge_reports() to sentinel_app;

-- migrate:down
-- Forward-only: intentionally empty. dbmate requires the marker.
