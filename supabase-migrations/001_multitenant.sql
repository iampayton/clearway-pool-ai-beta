-- ClearWay Pool AI — Multi-tenant backbone (migration 001)
-- STATUS: DRAFT. Do NOT apply to live Supabase until Payton approves.
--
-- DESIGN GOAL: ADDITIVE. This adds the company/tech model WITHOUT breaking the
-- live single-tenant app Trin uses. New tables only + nullable columns on
-- pool_checks; the existing single-tenant RLS policies stay in place until we
-- deliberately cut over. Tenant isolation (one company can never see another's
-- data) is enforced by RLS on every table below — the one thing we never cut corners on.
--
-- MODEL: organization (a pool company) -> org_members (users + role) -> pools
-- (owned by org, assignable to a tech + service day) -> pool_checks (scans).

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
  service_day      text,                                -- '' | Mon..Sun
  assigned_tech_id uuid references auth.users(id),
  profile          jsonb not null default '{}',         -- equipment, heater, filter, products, gate code, etc.
  created_at       timestamptz not null default now()
);

-- 4. Tie scans to org + tech (nullable so the current app keeps working untouched)
alter table pool_checks add column if not exists org_id  uuid references organizations(id);
alter table pool_checks add column if not exists tech_id uuid references auth.users(id);

-- ───────────────────────────────────────────────────────────────────────────
-- Helper functions (SECURITY DEFINER so RLS policies can call them safely)
create or replace function my_org_ids()
  returns setof uuid language sql security definer stable as $$
  select org_id from org_members where user_id = auth.uid() and status = 'active'
$$;

create or replace function is_org_supervisor(target_org uuid)
  returns boolean language sql security definer stable as $$
  select exists (
    select 1 from org_members
    where org_id = target_org and user_id = auth.uid()
      and role = 'supervisor' and status = 'active'
  )
$$;

-- Bootstrap: when an org is created, auto-add its owner as an active supervisor
-- (resolves the chicken-and-egg of "supervisor manages members" needing a supervisor).
create or replace function add_owner_as_supervisor()
  returns trigger language plpgsql security definer as $$
begin
  insert into org_members (org_id, user_id, email, role, status)
  values (new.id, new.owner_user_id,
          coalesce((select email from auth.users where id = new.owner_user_id), ''),
          'supervisor', 'active');
  return new;
end $$;

drop trigger if exists trg_org_owner on organizations;
create trigger trg_org_owner after insert on organizations
  for each row execute function add_owner_as_supervisor();

-- ───────────────────────────────────────────────────────────────────────────
-- Row-Level Security  (the isolation boundary)
alter table organizations enable row level security;
alter table org_members  enable row level security;
alter table pools        enable row level security;

-- organizations: any signed-in user can create one (becomes owner); members read; supervisor updates
create policy org_create on organizations for insert
  with check (auth.uid() = owner_user_id);
create policy org_read   on organizations for select
  using (id in (select my_org_ids()));
create policy org_update on organizations for update
  using (is_org_supervisor(id));

-- org_members: members of an org can see its roster; supervisors add/edit/remove members
create policy members_read  on org_members for select
  using (org_id in (select my_org_ids()));
create policy members_write on org_members for all
  using (is_org_supervisor(org_id))
  with check (is_org_supervisor(org_id));

-- pools: supervisor sees/edits all org pools; a tech sees only pools assigned to them
create policy pools_supervisor on pools for all
  using (is_org_supervisor(org_id))
  with check (is_org_supervisor(org_id));
create policy pools_tech_read on pools for select
  using (org_id in (select my_org_ids()) and assigned_tech_id = auth.uid());

-- pool_checks: ADD org-scoped policies (existing single-tenant policies remain for now).
-- Supervisor reads every scan in their org; a tech reads/writes only their own org scans.
create policy checks_org_supervisor on pool_checks for select
  using (org_id is not null and is_org_supervisor(org_id));
create policy checks_tech_rw on pool_checks for all
  using (org_id is not null and tech_id = auth.uid())
  with check (org_id is not null and tech_id = auth.uid());

-- ───────────────────────────────────────────────────────────────────────────
-- Indexes
create index if not exists idx_pools_org     on pools(org_id);
create index if not exists idx_pools_tech    on pools(assigned_tech_id);
create index if not exists idx_members_user  on org_members(user_id);
create index if not exists idx_members_org   on org_members(org_id);
create index if not exists idx_checks_org    on pool_checks(org_id);

-- ───────────────────────────────────────────────────────────────────────────
-- Storage photo isolation  (bucket: pool-check-photos)
-- Multi-tenant uploads are pathed with org_id as the FIRST folder:
--   <org_id>/<tech_id>/<check_id>/<label>-<i>-<ts>.jpg
-- Only members of that org may read/write objects under that org's prefix —
-- this is the photo-side of the same tenant boundary as the table RLS above.
-- ADDITIVE: existing household-pathed photos keep their current authenticated
-- storage policies; these org policies govern new org-pathed uploads. The app's
-- uploadOne() switches to org_id paths at cutover (separate app change).
create policy "org members read pool photos" on storage.objects for select
  using (
    bucket_id = 'pool-check-photos'
    and (storage.foldername(name))[1]::uuid in (select my_org_ids())
  );
create policy "org members upload pool photos" on storage.objects for insert
  with check (
    bucket_id = 'pool-check-photos'
    and (storage.foldername(name))[1]::uuid in (select my_org_ids())
  );
create policy "org members update pool photos" on storage.objects for update
  using (
    bucket_id = 'pool-check-photos'
    and (storage.foldername(name))[1]::uuid in (select my_org_ids())
  );

-- NEXT (separate steps, after this is approved + applied):
--   • magic-link auth + the supervisor "invite tech by email" flow
--   • supervisor route-assignment UI (assign pool -> tech + day)
--   • tech login -> server-side route (replaces localStorage routes)
--   • cutover: once orgs are live, retire the anonymous-auth single-tenant policies
