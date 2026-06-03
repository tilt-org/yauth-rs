# Upgrading yauth

## Schema model (read this first)

yauth uses **consumer-owned migrations**: the library does not run migrations at
runtime. You generate ORM-native migration files with `cargo yauth generate` and apply
them with your ORM's CLI (`diesel migration run`, `sqlx migrate run`, …). The generated
SQL is a full-schema snapshot of `CREATE TABLE IF NOT EXISTS` statements.

**Consequence for upgrades that add *columns* to *existing* tables:** because the
generated DDL is `CREATE TABLE IF NOT EXISTS`, re-applying a newer snapshot against a
database that already has the tables is a **no-op** — the new columns are *not* added.
New *tables* upgrade cleanly (the `CREATE` runs); new *columns* on tables you already
have do not. For those you must run an additive `ALTER TABLE` once, by hand, against your
existing database. This page records those column deltas per release.

> A fresh database is unaffected — the snapshot creates every table with all current
> columns. This only concerns **in-place upgrades of an existing database.**

---

## Adding lifecycle + logout + DCR columns (this release)

This release adds columns to two **existing** tables:

| Table | New columns |
|-------|-------------|
| `yauth_users` | `suspended_at`, `suspended_reason`, `activates_at` |
| `yauth_oauth2_clients` | `post_logout_redirect_uris`, `backchannel_logout_uri`, `backchannel_logout_session_required`, `dynamically_registered`, `last_used_at` |

The `yauth_users` columns are **read on every user load** (the auth hot path). If you
bump yauth against an existing database without adding them, **all authentication fails**
until they exist. Run the upgrade SQL *before* (or as part of) the deploy that ships the
new yauth.

### PostgreSQL (the supported production path — verified)

Idempotent and safe to re-run; no-ops if a column already exists (e.g. on a
freshly-snapshotted schema):

```sql
-- User lifecycle (suspend / staged activation / kill switch).
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS suspended_reason VARCHAR;
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS activates_at TIMESTAMPTZ;

-- OIDC RP-Initiated + Back-Channel Logout client metadata + DCR stale-sweep bookkeeping.
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS post_logout_redirect_uris JSONB;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS dynamically_registered BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
```

This SQL is also mirrored as a migration file you can apply directly:
`migrations/sqlx-pg/00000010_upgrade_add_lifecycle_logout_dcr_columns.sql`
(sqlx) and `migrations/diesel-pg/20260603000000_upgrade_add_lifecycle_logout_dcr_columns/`
(diesel).

### MySQL / SQLite (library-completeness backends — adapt as needed)

MySQL 8 and SQLite do **not** support `ADD COLUMN IF NOT EXISTS`, so apply these **once**
against an un-upgraded database (a second run errors with "duplicate column"). On a fresh
database the snapshot already created the columns — do not run these there.

```sql
-- MySQL / SQLite (run once, against an existing pre-upgrade DB only):
ALTER TABLE yauth_users ADD COLUMN suspended_at TIMESTAMP NULL;
ALTER TABLE yauth_users ADD COLUMN suspended_reason VARCHAR(255) NULL;
ALTER TABLE yauth_users ADD COLUMN activates_at TIMESTAMP NULL;
ALTER TABLE yauth_oauth2_clients ADD COLUMN post_logout_redirect_uris JSON NULL;     -- SQLite: TEXT
ALTER TABLE yauth_oauth2_clients ADD COLUMN backchannel_logout_uri TEXT NULL;
ALTER TABLE yauth_oauth2_clients ADD COLUMN backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE yauth_oauth2_clients ADD COLUMN dynamically_registered BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE yauth_oauth2_clients ADD COLUMN last_used_at TIMESTAMP NULL;
```

> Future direction: teach `cargo yauth generate` to emit an incremental `ALTER TABLE`
> diff (it already computes column diffs internally for the add-plugin path) so this
> manual step is generated automatically. Tracked as a follow-up.
