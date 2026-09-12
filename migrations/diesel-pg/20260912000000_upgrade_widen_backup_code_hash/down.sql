-- Reverse the widening. Rows written by this release hold 97-character Argon2id
-- PHC strings that the previous release can neither fit in VARCHAR(64) nor
-- verify (it compares bare SHA-256 hex), so they are dropped before the column
-- narrows; affected users regenerate their backup codes after the downgrade.
DELETE FROM yauth_backup_codes WHERE length(code_hash) > 64;
ALTER TABLE yauth_backup_codes ALTER COLUMN code_hash TYPE VARCHAR(64);
