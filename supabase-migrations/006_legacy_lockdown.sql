-- ============================================================================
-- 006_legacy_lockdown.sql — REV 1 (2026-07-07, Codex P0 findings 1+2)
-- Retires the legacy "unclaimed" access paths. Safe NOW because prod data says
-- so: 0 pool_checks rows with user_id NULL (every row is claimed), and 0
-- legacy-bucket photos without an owner. In-app photo display uses stored
-- signed URLs, so the storage read-scope change is invisible to users.
--
-- (a) pool_checks: reads/updates were "own OR unclaimed(user_id is null)" —
--     any signed-in account could read/claim unclaimed rows. Now own-only.
--     ("own insert" recreated too, picking up the initplan (select auth.uid())
--     pattern while we're here.) Org policies (checks_tech_rw / supervisor /
--     restrictive membership clamp) are untouched.
--
-- (b) pool-check-photos: read was bucket-wide for any authenticated user.
--     Now owner-scoped. Upload stays as-is (owner is stamped by storage).
--
-- Post-apply: proof 6/6 in a rolled-back txn (see session log).
-- Rollback: recreate prior policies from 001 REV5 / original app setup.
-- ============================================================================

begin;

-- (a) pool_checks own-only access
drop policy if exists "own or unclaimed read" on public.pool_checks;
create policy "own read" on public.pool_checks
  for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists "claim or own update" on public.pool_checks;
create policy "own update" on public.pool_checks
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

drop policy if exists "own insert" on public.pool_checks;
create policy "own insert" on public.pool_checks
  for insert to authenticated
  with check (user_id = (select auth.uid()));

-- (b) legacy photo bucket: owner-scoped read
drop policy if exists "auth photo read" on storage.objects;
create policy "legacy photos read own" on storage.objects
  for select to authenticated
  using (bucket_id = 'pool-check-photos' and owner = (select auth.uid()));

commit;
