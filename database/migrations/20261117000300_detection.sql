-- migrate:up
-- =====================================================================
-- Detection support (Phase 5).
--   severity_rank()         orders severities, so an alert can escalate but never silently downgrade
--   security_alerts.simulated  an alert raised only by simulated (test) events: shown with a badge, never emailed
--   per-account index       "account under attack" / "password spraying" count failures by the keyed account hash
-- (One active block per network is enforced by the API under an advisory lock: "active" depends on now(), which an
--  index predicate can't use.)
-- =====================================================================

create function public.severity_rank(s text) returns integer language sql immutable parallel safe as $$
  select coalesce(array_position(array['info', 'low', 'medium', 'high', 'critical'], s), 0)
$$;

alter table public.security_alerts add column simulated boolean not null default false;

create index security_events_account_idx on public.security_events ((details ->> 'accountKey'), occurred_at desc)
  where details ? 'accountKey';
create index security_events_route_idx on public.security_events (app_id, route, occurred_at desc) where route is not null;

-- migrate:down
-- Forward-only: intentionally empty. dbmate requires the marker.
