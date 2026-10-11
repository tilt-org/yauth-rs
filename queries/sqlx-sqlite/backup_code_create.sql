-- Create a backup code.
-- Params: ? id (TEXT), ? user_id (TEXT), ? code_hash (VARCHAR, Argon2id PHC string)
-- Returns: nothing
-- Plugin: mfa
INSERT INTO yauth_backup_codes (id, user_id, code_hash, used, created_at)
VALUES (?, ?, ?, false, datetime('now'));
