-- Rollback for 001_multitenant.sql
-- Reverts the multi-tenant backbone cleanly. Does NOT touch the pre-existing
-- single-tenant pool_checks policies, the existing household-pathed storage
-- policies, or any data. Safe to run if 001 needs to be undone.

-- Storage policies
drop policy if exists "org members read pool photos"   on storage.objects;
drop policy if exists "org members upload pool photos" on storage.objects;
drop policy if exists "org members update pool photos" on storage.objects;

-- pool_checks org-scoped policies (added by 001; originals remain)
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

-- Trigger + functions
drop trigger  if exists trg_org_owner on organizations;
drop function if exists add_owner_as_supervisor();
drop function if exists is_org_supervisor(uuid);
drop function if exists my_org_ids();

-- Added columns (additive on pool_checks)
alter table pool_checks drop column if exists tech_id;
alter table pool_checks drop column if exists org_id;

-- Tables (children first)
drop table if exists pools;
drop table if exists org_members;
drop table if exists organizations;

-- Enum
drop type if exists org_role;
