-- Reverse the additive upgrade. Drops are guarded so this is safe on databases that
-- never had the columns.
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS dynamically_registered;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS backchannel_logout_session_required;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS backchannel_logout_uri;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS post_logout_redirect_uris;
ALTER TABLE yauth_users DROP COLUMN IF EXISTS activates_at;
ALTER TABLE yauth_users DROP COLUMN IF EXISTS suspended_reason;
ALTER TABLE yauth_users DROP COLUMN IF EXISTS suspended_at;
