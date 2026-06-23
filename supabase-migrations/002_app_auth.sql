-- ClearWay Pool AI — App/Auth layer, migration 002 (REV 3)
-- STATUS: DRAFT for review. Do NOT apply live until Codex signs off.
--
-- REV 3 addresses a gap found by the POST-APPLY verification of REV 2 on the live DB:
--   Supabase's default privileges grant EXECUTE on new public-schema functions to
--   BOTH `anon` and `authenticated` explicitly. `revoke ... from public` removes only
--   the PUBLIC default, leaving an explicit `anon=X` grant (confirmed via pg_proc.proacl
--   live: anon=X/postgres + authenticated=X/postgres). So `anon` could still EXECUTE the
--   function. Low functional risk (an anon caller has no auth.uid()/email, so the body
--   raises immediately), but it misses the "public/anon execute revoked" requirement.
--   Fix: also `revoke execute ... from anon`. Re-running this file is idempotent.
--   (Pattern note: every future SECURITY DEFINER fn should revoke from anon too.)
--
-- REV 2 addressed Codex review of REV 1:
--   • accept_org_invite() only claims rows with status = 'invited' (so a revoked/
--     removed/paused unclaimed row can't be silently reactivated by logging in)
--   • trim + lowercase BOTH auth.email() and org_members.email before matching
--   • schema-qualify the function + org_role type (and in the rollback)
--
-- Purpose: let a magic-link (verified-email) tech self-link to the org_members
-- invite row their supervisor created for them, so the app can then write
-- org-scoped pool_checks and read assigned pools under RLS.
--
-- ADDITIVE + NON-BREAKING. Adds ONE security-definer function. Touches no tables,
-- no existing policies, and nothing in the legacy anonymous pool_checks path.
-- The legacy anonymous flow (Trin / current app) keeps working unchanged.
--
-- Depends on 001 (REV 5, applied 2026-06-23): organizations / org_members(role,status)
-- / pools / pool_checks(+org_id,+tech_id) + RLS + the restrictive membership gate.

-- ───────────────────────────────────────────────────────────────────────────
-- accept_org_invite(): claim any UNCLAIMED org_members invite rows whose email
-- matches the caller's VERIFIED email, then return the caller's active memberships.
--
-- Why a SECURITY DEFINER function (not a plain UPDATE policy): the members_write
-- RLS policy only lets a supervisor write org_members. A tech accepting their own
-- invite must set their own user_id, which the policy forbids — so we do it through
-- this tightly-scoped definer fn instead of loosening the policy.
--
-- Safety properties:
--   • auth.uid() + auth.email() come from the verified JWT; magic-link guarantees
--     the caller actually controls that mailbox.
--   • Only rows with user_id IS NULL are claimed → cannot hijack a membership that
--     already belongs to someone else.
--   • Only rows whose email equals the caller's verified email are claimed → a user
--     can only ever attach themselves to invites addressed to them.
--   • search_path = '' + fully-qualified names; execute revoked from public.
create or replace function public.accept_org_invite()
  returns table(org_id uuid, role public.org_role)
  language plpgsql security definer
  set search_path = '' as $$
declare
  v_uid   uuid := auth.uid();
  v_email text := lower(nullif(btrim(auth.email()), ''));
begin
  if v_uid is null or v_email is null then
    raise exception 'accept_org_invite: caller must be signed in with a verified email';
  end if;

  -- Link PENDING invites addressed to this verified email to this user.
  -- status = 'invited' is required so a revoked/removed/paused unclaimed row
  -- can never be silently reactivated just by the user logging in.
  update public.org_members m
     set user_id = v_uid,
         status  = 'active'
   where lower(btrim(m.email)) = v_email
     and m.user_id is null
     and m.status = 'invited';

  -- Return the caller's current active memberships (one row per org).
  return query
    select m.org_id, m.role
    from public.org_members m
    where m.user_id = v_uid
      and m.status = 'active';
end $$;

-- Lock execute down to signed-in users only. Both revokes are required: PUBLIC for
-- the default grant, and anon for the explicit grant Supabase adds via default
-- privileges (see REV 3 note above).
revoke execute on function public.accept_org_invite() from public;
revoke execute on function public.accept_org_invite() from anon;
grant  execute on function public.accept_org_invite() to authenticated;

-- ───────────────────────────────────────────────────────────────────────────
-- CONCIERGE PROVISIONING (run separately, as the postgres/service role, NOT part
-- of this migration's app surface). Documented here so the pilot setup is repeatable:
--   1. Supervisor logs in once via magic link so we know their auth.uid() (= S).
--   2. insert into organizations(name, owner_user_id) values ('Edgewater', S);
--      → trg_org_owner makes S an active supervisor automatically.
--   3. For each tech: insert into org_members(org_id, email, role, status)
--        values (<org>, lower('tech@email'), 'tech', 'invited');
--   4. Assign pools: insert into pools(org_id, name, address, assigned_tech_id, service_day, ...)
--      (assigned_tech_id can be set after the tech accepts and we have their uid).
--   5. Tech logs in via magic link → app calls accept_org_invite() → membership active.
--
-- NEXT (after this is approved + applied, in the app layer):
--   • magic-link login UI (signInWithOtp) coexisting with anonymous sign-in
--   • on login: call accept_org_invite(); load org + pools where assigned_tech_id = auth.uid()
--   • org-mode writes: pool_checks.org_id/tech_id/user_id = auth.uid(); photos to
--     org-pool-photos at <org_id>/<tech_id>/<check_id>/...
--   • (later, separate reviewed migration) retire legacy anonymous pool_checks policies
