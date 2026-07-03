-- 003_rollback.sql — undoes 003_hardening.sql (REV 1, 2026-07-02)
-- Order-safe; each step is independent.
begin;

-- (b) drop the delete policy (bucket returns to append-only)
drop policy if exists "org photos delete" on storage.objects;

-- (a) restore prior grants (the pre-003 state the advisor flagged)
grant execute on function public.my_org_ids() to anon;
grant execute on function public.is_org_supervisor(uuid) to anon;
grant execute on function public.add_owner_as_supervisor() to anon, authenticated;
grant execute on function public.enforce_org_membership_on_checks() to anon, authenticated;
grant execute on function public.rls_auto_enable() to anon, authenticated;

-- (c) keep the ledger table by default (harmless, service-role only).
-- To fully remove it instead, uncomment:
-- drop table if exists public.ai_usage_daily;

commit;
