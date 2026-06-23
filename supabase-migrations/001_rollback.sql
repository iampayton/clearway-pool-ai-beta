-- Rollback for 001_multitenant.sql (REV 4)
-- TWO paths. Pick deliberately.

-- ════════════════════════════════════════════════════════════════════════════
-- SECTION A — SOFT DISABLE (data-preserving).
-- Use if multi-tenant is LIVE with real pilot data and you need to turn the new
-- enforcement OFF without losing tenant linkage. Keeps all tables, columns,
-- the org-pool-photos bucket, and data. Only removes the policy/trigger/function layer.
-- ════════════════════════════════════════════════════════════════════════════

-- storage policies
drop policy if exists "org photos read"   on storage.objects;
drop policy if exists "org photos insert" on storage.objects;
drop policy if exists "org photos update" on storage.objects;
-- pool_checks org policies
drop policy if exists checks_org_supervisor on pool_checks;
drop policy if exists checks_tech_rw        on pool_checks;
-- pools / members / orgs policies
drop policy if exists pools_supervisor on pools;
drop policy if exists pools_tech_read  on pools;
drop policy if exists members_read  on org_members;
drop policy if exists members_write on org_members;
drop policy if exists org_create on organizations;
drop policy if exists org_read   on organizations;
drop policy if exists org_update on organizations;
-- triggers
drop trigger if exists trg_checks_org_guard on pool_checks;
drop trigger if exists trg_org_owner        on organizations;
-- functions
drop function if exists enforce_org_membership_on_checks();
drop function if exists add_owner_as_supervisor();
drop function if exists is_org_supervisor(uuid);
drop function if exists my_org_ids();
-- Deny-by-default on the new tenant tables (Codex REV3 #D).
-- NEVER `disable row level security` here: once these tables carry `authenticated`
-- grants, disabling RLS exposes EVERY org's rows to EVERY authenticated user. Instead
-- we keep RLS enabled (with all policies dropped above, Postgres denies all row access
-- by default) AND revoke the app grants as belt-and-suspenders. The legacy single-tenant
-- pool_checks policies/grants are untouched, so the current app keeps working.
revoke all on organizations from authenticated;
revoke all on org_members  from authenticated;
revoke all on pools        from authenticated;
-- (RLS stays ENABLED on organizations/org_members/pools.)
-- NOTE: tables, columns (pool_checks.org_id/tech_id), the org-pool-photos bucket,
-- and ALL data are intentionally preserved here.

-- ════════════════════════════════════════════════════════════════════════════
-- SECTION B — FULL DESTRUCTIVE TEARDOWN.  ⚠ PRE-PRODUCTION / DRY-RUN ONLY ⚠
-- Drops columns, tables, type, and the bucket. This DELETES all org/pool data and
-- the org_id/tech_id linkage on scans. DO NOT run after real pilot data has landed.
-- Run Section A first, then the lines below.
-- ════════════════════════════════════════════════════════════════════════════

-- alter table pool_checks drop column if exists tech_id;
-- alter table pool_checks drop column if exists org_id;
-- drop table if exists pools;
-- drop table if exists org_members;
-- drop table if exists organizations;
-- drop type  if exists org_role;
-- delete from storage.objects where bucket_id = 'org-pool-photos';  -- bucket must be emptied first
-- delete from storage.buckets where id = 'org-pool-photos';
