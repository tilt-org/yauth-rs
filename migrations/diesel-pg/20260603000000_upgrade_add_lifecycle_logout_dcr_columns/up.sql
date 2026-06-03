-- In-place upgrade for existing databases: add columns introduced after the prior
-- release to tables that already exist. The generated `CREATE TABLE IF NOT EXISTS`
-- snapshots do NOT alter existing tables, so these additive ALTERs are required when
-- upgrading a populated database (a fresh database already has them via the snapshot).
-- Idempotent (`IF NOT EXISTS`). See ../../../UPGRADING.md.

-- User lifecycle (suspend / staged activation / kill switch). Read on every user load.
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS suspended_reason VARCHAR;
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS activates_at TIMESTAMPTZ;

-- OIDC RP-Initiated + Back-Channel Logout client metadata + DCR stale-sweep bookkeeping.
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS dynamically_registered BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
