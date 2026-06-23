-- ClearWay Pool AI — Multi-tenant backbone (migration 001, REV 5)
-- STATUS: DRAFT for review. Do NOT apply live until Codex signs off.
--
-- REV 5 addresses the REV 4 re-review (P0):
--   The live legacy pool_checks read policy still grants any row where
--   user_id = auth.uid() regardless of org, so a tech REMOVED from an org could
--   keep reading the org scans they authored. Fixed with a RESTRICTIVE membership
--   policy (checks_org_membership_required) AND-ed onto every permissive path: an
--   org-scoped row is reachable only by a CURRENT member of its org; org_id IS NULL
--   legacy rows pass through untouched. No need to alter/drop the live legacy
--   policies — the restrictive policy clamps them.
--
-- REV 4 addresses the REV 3 re-review (P0):
--   Every org-scoped pool_checks write must stamp user_id = auth.uid(). The live
--   legacy "own or unclaimed read" policy exposes rows with user_id IS NULL to any
--   authenticated user, so an org row written with a null user_id would leak across
--   orgs. Enforced in the trigger (all writes) + checks_tech_rw with-check (defense
--   in depth). Closes the last isolation hole.
--
-- REV 2 addressed Codex review #1–#5 (see below).
-- REV 3 addressed the REV 2 re-review:
--   #A explicit `authenticated` grants on the new app-facing tables (SQL-created
--      tables in the exposed public schema get no automatic API grants)
--   #B every new policy scoped `to authenticated` (clean denial for anon, and no
--      security-definer fn permission errors on unauthenticated requests)
--   #C pool_checks trigger: org-scoped non-supervisor writes MUST set tech_id =
--      auth.uid() (closes the tech_id = null org-row hole)
--   #D rollback never disables RLS on tenant tables (see 001_rollback.sql)
--
-- REV 2 addressed the original Codex review:
--   #1 separate private photo bucket (legacy broad read policy can't cover org photos)
--   #2 no uuid casts on storage paths — text comparison only
--   #3 scan writes require proven org membership (RLS + enforcement trigger)
--   #4 security-definer fns: locked search_path = '' + execute revoked from public
--   #5 rollback split into data-preserving + pre-production-destructive (see 001_rollback.sql)
--
-- ADDITIVE + NON-BREAKING: new tables, a new bucket, and nullable columns only.
-- The existing single-tenant app, the pool-check-photos bucket, and all current
-- policies/data are left untouched. Tenant isolation is the boundary we never cut.

-- ───────────────────────────────────────────────────────────────────────────
-- 1. Organizations — one pool company = one org
create table if not exists organizations (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  owner_user_id uuid references auth.users(id),
  created_at    timestamptz not null default now()
);

-- 2. Membership — maps an auth user to an org with a role
do $$ begin
  create type org_role as enum ('supervisor','tech');
exception when duplicate_object then null; end $$;

create table if not exists org_members (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references organizations(id) on delete cascade,
  user_id    uuid references auth.users(id),          -- null until an invited tech accepts
  email      text not null,
  name       text,
  role       org_role not null default 'tech',
  status     text not null default 'invited',          -- invited | active
  created_at timestamptz not null default now(),
  unique (org_id, email)
);

-- 3. Pools — owned by an org, assignable to a tech and a service day
create table if not exists pools (
  id               uuid primary key default gen_random_uuid(),
  org_id           uuid not null references organizations(id) on delete cascade,
  name             text,
  address          text,
  pool_type        text,
  volume_gallons   int,
  service_day      text,
  assigned_tech_id uuid references auth.users(id),
  profile          jsonb not null default '{}',
  created_at       timestamptz not null default now()
);

-- 4. Tie scans to org + tech (nullable so the current app keeps working untouched)
alter table pool_checks add column if not exists org_id  uuid references organizations(id);
alter table pool_checks add column if not exists tech_id uuid references auth.users(id);

-- ───────────────────────────────────────────────────────────────────────────
-- Helper functions  (Codex #4: SECURITY DEFINER + locked search_path + revoked public execute)
create or replace function my_org_ids()
  returns setof uuid language sql security definer stable
  set search_path = '' as $$
  select org_id from public.org_members
  where user_id = auth.uid() and status = 'active'
$$;
revoke execute on function my_org_ids() from public;
grant  execute on function my_org_ids() to authenticated;

create or replace function is_org_supervisor(target_org uuid)
  returns boolean language sql security definer stable
  set search_path = '' as $$
  select exists (
    select 1 from public.org_members
    where org_id = target_org and user_id = auth.uid()
      and role = 'supervisor' and status = 'active'
  )
$$;
revoke execute on function is_org_supervisor(uuid) from public;
grant  execute on function is_org_supervisor(uuid) to authenticated;

-- Bootstrap: new org auto-gets its owner as an active supervisor
create or replace function add_owner_as_supervisor()
  returns trigger language plpgsql security definer
  set search_path = '' as $$
begin
  insert into public.org_members (org_id, user_id, email, role, status)
  values (new.id, new.owner_user_id,
          coalesce((select email from auth.users where id = new.owner_user_id), ''),
          'supervisor', 'active');
  return new;
end $$;
revoke execute on function add_owner_as_supervisor() from public;

drop trigger if exists trg_org_owner on organizations;
create trigger trg_org_owner after insert on organizations
  for each row execute function add_owner_as_supervisor();

-- Integrity guard (Codex #3): ANY pool_checks write carrying an org_id must come from
-- an active member of that org; a tech-written row must be the tech's own. Enforced by
-- trigger so it holds even if the legacy permissive single-tenant insert policy allowed
-- the row — closes the cross-org injection path.
create or replace function enforce_org_membership_on_checks()
  returns trigger language plpgsql security definer
  set search_path = '' as $$
begin
  if new.org_id is not null then
    if not exists (
      select 1 from public.org_members
      where org_id = new.org_id and user_id = auth.uid() and status = 'active'
    ) then
      raise exception 'pool_checks: writer % is not an active member of org %', auth.uid(), new.org_id;
    end if;
    -- (Codex REV4 P0) EVERY org-scoped write must stamp user_id = auth.uid().
    -- The live legacy "own or unclaimed read" policy exposes pool_checks rows where
    -- user_id IS NULL to ANY authenticated user. An org row with user_id null would
    -- therefore leak outside the org. `is distinct from` rejects null and any other
    -- id, for supervisors and techs alike, so org rows are always owned (never unclaimed).
    if new.user_id is distinct from auth.uid() then
      raise exception 'pool_checks: org-scoped writes must set user_id = auth.uid()';
    end if;
    -- Supervisors may write on behalf of any tech (or leave tech_id null). Everyone
    -- else MUST stamp their own id. `is distinct from` rejects tech_id = null too,
    -- closing the org-scoped row with no tech_id hole.
    if not public.is_org_supervisor(new.org_id)
       and new.tech_id is distinct from auth.uid() then
      raise exception 'pool_checks: non-supervisor writes must set tech_id = auth.uid()';
    end if;
  end if;
  return new;
end $$;
revoke execute on function enforce_org_membership_on_checks() from public;

drop trigger if exists trg_checks_org_guard on pool_checks;
create trigger trg_checks_org_guard before insert or update on pool_checks
  for each row execute function enforce_org_membership_on_checks();

-- ───────────────────────────────────────────────────────────────────────────
-- Grants + Row-Level Security  (Codex REV3 #A)
-- Supabase: tables created via SQL in the exposed `public` schema receive NO
-- automatic API grants. Without these, authenticated app/proof queries fail with
-- permission errors even when RLS is correct. RLS is the row filter; the grant is
-- the door. pool_checks keeps its pre-existing grants (untouched).
grant select, insert, update, delete on organizations to authenticated;
grant select, insert, update, delete on org_members  to authenticated;
grant select, insert, update, delete on pools        to authenticated;

alter table organizations enable row level security;
alter table org_members  enable row level security;
alter table pools        enable row level security;

-- All new policies are scoped `to authenticated` (Codex REV3 #B): anon requests get
-- a clean RLS denial instead of hitting the security-definer helpers (whose execute
-- is revoked from public), which would otherwise surface as function permission errors.
create policy org_create on organizations for insert to authenticated with check (auth.uid() = owner_user_id);
create policy org_read   on organizations for select to authenticated using (id in (select my_org_ids()));
create policy org_update on organizations for update to authenticated using (is_org_supervisor(id));

create policy members_read  on org_members for select to authenticated using (org_id in (select my_org_ids()));
create policy members_write on org_members for all to authenticated
  using (is_org_supervisor(org_id)) with check (is_org_supervisor(org_id));

create policy pools_supervisor on pools for all to authenticated
  using (is_org_supervisor(org_id)) with check (is_org_supervisor(org_id));
create policy pools_tech_read on pools for select to authenticated
  using (org_id in (select my_org_ids()) and assigned_tech_id = auth.uid());

-- pool_checks org policies REQUIRE org membership (Codex #3). The trigger above is the
-- belt-and-suspenders against the legacy permissive insert policy.
create policy checks_org_supervisor on pool_checks for select to authenticated
  using (org_id is not null and is_org_supervisor(org_id));
create policy checks_tech_rw on pool_checks for all to authenticated
  using      (org_id in (select my_org_ids()) and tech_id = auth.uid())
  with check (org_id in (select my_org_ids()) and tech_id = auth.uid()
              and user_id = auth.uid());  -- (Codex REV4 P0) never write an unclaimed org row

-- (Codex REV5 P0) RESTRICTIVE membership gate. While the legacy single-tenant
-- pool_checks policies remain live, they grant access to ANY row where
-- user_id = auth.uid() regardless of org_id — so a tech REMOVED from an org could
-- still read the org scans they authored. A RESTRICTIVE policy is AND-ed with every
-- permissive policy (legacy ones included), so it clamps ALL paths: an org-scoped
-- row is reachable only by a CURRENT member of its org. Rows with org_id IS NULL
-- (Trin's legacy single-tenant data) are explicitly allowed through, so nothing
-- breaks pre-cutover. Removing the legacy policies later only loosens nothing here.
create policy checks_org_membership_required on pool_checks
  as restrictive for all to authenticated
  using      (org_id is null or org_id in (select my_org_ids()))
  with check (org_id is null or org_id in (select my_org_ids()));

-- ───────────────────────────────────────────────────────────────────────────
-- Storage: DEDICATED private bucket for multi-tenant photos (Codex #1 + #2)
-- Separate bucket = the legacy bucket's broad "auth photo read" policy cannot apply
-- here. Text-only path comparison = no uuid-cast errors. Path: <org_id>/<tech_id>/<check_id>/...
insert into storage.buckets (id, name, public)
  values ('org-pool-photos', 'org-pool-photos', false)
  on conflict (id) do nothing;

create policy "org photos read" on storage.objects for select to authenticated
  using (bucket_id = 'org-pool-photos'
    and (storage.foldername(name))[1] in (select t::text from my_org_ids() as t));
create policy "org photos insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'org-pool-photos'
    and (storage.foldername(name))[1] in (select t::text from my_org_ids() as t));
create policy "org photos update" on storage.objects for update to authenticated
  using (bucket_id = 'org-pool-photos'
    and (storage.foldername(name))[1] in (select t::text from my_org_ids() as t));

-- ───────────────────────────────────────────────────────────────────────────
-- Indexes
create index if not exists idx_pools_org    on pools(org_id);
create index if not exists idx_pools_tech   on pools(assigned_tech_id);
create index if not exists idx_members_user on org_members(user_id);
create index if not exists idx_members_org  on org_members(org_id);
create index if not exists idx_checks_org   on pool_checks(org_id);

-- NEXT (separate steps, after approval + apply):
--   • app: uploadOne() writes to org-pool-photos at <org_id>/<tech_id>/<check_id>/...
--   • magic-link auth + supervisor "invite tech by email" flow
--   • supervisor route-assignment UI; tech login -> server-side route
--   • cutover: retire the anonymous-auth single-tenant pool_checks policies (the
--     REV5 restrictive gate already makes org rows safe while they remain)
--   • (separate) revoke the pre-existing public rls_auto_enable security-definer fn flagged by advisors
