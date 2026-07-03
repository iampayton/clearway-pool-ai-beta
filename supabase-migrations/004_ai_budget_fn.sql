-- ============================================================================
-- 004_ai_budget_fn.sql — REV 1 (2026-07-02, Fable 5 sweep)
-- Atomic daily AI-spend bump for the ai-extract edge fn (v12 budget breaker).
-- Race-safe upsert; service_role ONLY (the standard revoke pattern applies).
-- Rollback: drop function public.bump_ai_usage(numeric);
-- ============================================================================
begin;

create or replace function public.bump_ai_usage(add_cents numeric)
returns numeric
language sql
security definer
set search_path = ''
as $$
  insert into public.ai_usage_daily as t (day, cents, calls)
  values ((now() at time zone 'utc')::date, greatest(coalesce(add_cents, 0), 0), 1)
  on conflict (day) do update
    set cents = t.cents + greatest(coalesce(excluded.cents, 0), 0),
        calls = t.calls + 1,
        updated_at = now()
  returning cents;
$$;

revoke execute on function public.bump_ai_usage(numeric) from public, anon, authenticated;
grant execute on function public.bump_ai_usage(numeric) to service_role;

commit;
