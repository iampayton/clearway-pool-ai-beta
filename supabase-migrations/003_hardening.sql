-- ============================================================================
-- 003_hardening.sql — REV 1 (2026-07-02, Fable 5 sweep)
-- Post-sweep security hardening. Three additive changes, no behavior breaks:
--
-- (a) Backport the agreed 002 grant pattern ("every public SECURITY DEFINER fn
--     revokes execute from BOTH public AND anon") to the five 001-era fns the
--     advisor still flags. my_org_ids/is_org_supervisor keep `authenticated`
--     (RLS policies evaluate them as the querying role). Trigger/event-trigger
--     fns (add_owner_as_supervisor, enforce_org_membership_on_checks,
--     rls_auto_enable) need NO caller execute — Postgres checks EXECUTE at
--     trigger creation, not fire time — so they lose authenticated too.
--
-- (b) "org photos delete" policy on storage.objects. Closes the known gap
--     (org photos were append-only → deleting a check orphaned its photos, and
--     techs couldn't remove a wrong-pool shot). Tech: may delete only inside
--     their own <org>/<tech>/ folder. Supervisor: any photo of an org they
--     supervise. Path segments compared as TEXT (REV2 lesson: never uuid-cast
--     a path segment). Deletes still flow through the Storage API only — the
--     storage.protect_delete statement trigger keeps blocking raw SQL deletes.
--
-- (c) public.ai_usage_daily — daily AI spend ledger for the ai-extract edge
--     function's budget breaker (v12). Service-role only: RLS enabled with no
--     policies + all client grants revoked. The edge fn reads/increments it
--     with the service key (bypasses RLS).
--
-- Rollback: see 003_rollback.sql.
-- ============================================================================

begin;

-- (a) function execute grants -------------------------------------------------
revoke execute on function public.my_org_ids() from public, anon;
revoke execute on function public.is_org_supervisor(uuid) from public, anon;
revoke execute on function public.add_owner_as_supervisor() from public, anon, authenticated;
revoke execute on function public.enforce_org_membership_on_checks() from public, anon, authenticated;
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;

-- (b) org photo delete policy -------------------------------------------------
drop policy if exists "org photos delete" on storage.objects;
create policy "org photos delete" on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'org-pool-photos'
    and (
      (
        (storage.foldername(name))[1] in (select t::text from public.my_org_ids() t)
        and (storage.foldername(name))[2] = auth.uid()::text
      )
      or exists (
        select 1 from public.my_org_ids() t
        where t::text = (storage.foldername(name))[1]
          and public.is_org_supervisor(t)
      )
    )
  );

-- (c) AI daily budget ledger (edge-fn/service-role only) ----------------------
create table if not exists public.ai_usage_daily (
  day date primary key,
  cents numeric not null default 0,
  calls integer not null default 0,
  updated_at timestamptz not null default now()
);
alter table public.ai_usage_daily enable row level security;
revoke all on table public.ai_usage_daily from public, anon, authenticated;

commit;
