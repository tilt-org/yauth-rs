-- In-place upgrade for existing databases: widen yauth_backup_codes.code_hash.
-- Backup codes are now stored as Argon2id PHC strings (97 characters at the
-- default parameters, salt embedded) instead of a 64-character hex SHA-256, so
-- the VARCHAR(64) the previous snapshot created rejects every new enrolment on
-- insert. The regenerated snapshot creates the column unbounded on a fresh
-- database; this ALTER brings an existing one in line. Idempotent: altering to
-- the type the column already has is a no-op. See ../../../UPGRADING.md.
ALTER TABLE yauth_backup_codes ALTER COLUMN code_hash TYPE VARCHAR;
