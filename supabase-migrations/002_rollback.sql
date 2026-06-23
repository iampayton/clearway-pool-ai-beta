-- Rollback for 002_app_auth.sql (REV 2)
-- Removes only the function added by 002. Data-preserving; nothing else is touched.
-- The legacy anonymous pool_checks path and the 001 multi-tenant objects are unaffected.

drop function if exists public.accept_org_invite();
