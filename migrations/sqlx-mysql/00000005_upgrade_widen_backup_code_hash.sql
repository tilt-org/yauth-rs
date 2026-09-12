-- In-place upgrade for existing databases: widen yauth_backup_codes.code_hash.
-- Backup codes are now stored as Argon2id PHC strings (97 characters at the
-- default parameters, salt embedded) instead of a 64-character hex SHA-256, so
-- the VARCHAR(64) the previous snapshot created rejects every new enrolment on
-- insert. The regenerated snapshot creates the column as VARCHAR(255) on a
-- fresh database; this MODIFY brings an existing one in line. Idempotent:
-- modifying to the definition the column already has is a no-op.
-- See ../../UPGRADING.md.
ALTER TABLE `yauth_backup_codes` MODIFY `code_hash` VARCHAR(255) NOT NULL;
