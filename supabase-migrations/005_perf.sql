-- ============================================================================
-- 005_perf.sql — REV 1 (2026-07-07, final pre-launch pass)
-- Performance-advisor fixes, additive + behavior-identical:
--
-- (a) Covering indexes for the advisor-flagged FKs + the two hot query shapes
--     (org history by created_at; legacy reads by user_id).
--
-- (b) auth_rls_initplan: the three ORG-era policies re-evaluated auth.uid() per
--     row; rewrapped as (select auth.uid()) so it evaluates once per query.
--     Semantics identical (Supabase-documented pattern). The three LEGACY
--     anonymous policies ("own or unclaimed read", "own insert", "claim or own
--     update") are intentionally NOT touched — they are scheduled for removal
--     at the anonymous-cutover migration, not for optimization.
--
-- Post-apply: isolation re-proven in a rolled-back txn (see session log).
-- Rollback: drop the indexes; recreate the three policies without the
-- (select ...) wrappers (definitions in 001 REV5).
-- ============================================================================

begin;

-- (a) indexes
create index if not exists idx_pool_checks_tech_id on public.pool_checks(tech_id);
create index if not exists idx_pool_checks_org_created on public.pool_checks(org_id, created_at desc);
create index if not exists idx_pool_checks_user_id on public.pool_checks(user_id);
create index if not exists idx_organizations_owner on public.organizations(owner_user_id);

-- (b) initplan rewrites (org-era policies only)
drop policy if exists "checks_tech_rw" on public.pool_checks;
create policy "checks_tech_rw" on public.pool_checks
  for all to authenticated
  using (org_id in (select public.my_org_ids()) and tech_id = (select auth.uid()))
  with check (org_id in (select public.my_org_ids()) and tech_id = (select auth.uid()) and user_id = (select auth.uid()));

drop policy if exists "pools_tech_read" on public.pools;
create policy "pools_tech_read" on public.pools
  for select to authenticated
  using (org_id in (select public.my_org_ids()) and assigned_tech_id = (select auth.uid()));

drop policy if exists "org_create" on public.organizations;
create policy "org_create" on public.organizations
  for insert to authenticated
  with check ((select auth.uid()) = owner_user_id);

commit;
