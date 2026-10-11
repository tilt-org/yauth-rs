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

## Sealed TOTP secrets, Argon2id backup codes, async email, mail admission (this release)

This release folds in the patch set that `tilt-org/frontend` carried on its vendored
copy of yauth 0.14.0 (its `third_party/yauth` tree), through 2026-10-07. It changes the
MFA plugin's storage format, tightens its login path, makes email delivery asynchronous,
meters every route that mails an unauthenticated caller's address and refuses those
requests when the meter is unavailable, and reshapes three config structs. Read the whole
section before bumping: two of the changes are **operational cutovers**, not just
recompiles.

### Compile-time changes

| Surface | Change | What to do |
|---------|--------|------------|
| `PasswordPolicyConfig` | `require_uppercase` / `require_lowercase` / `require_digit` / `require_special` are replaced by one `character_requirements: CharacterRequirements` | `AnyCharacters` (default) is the old all-`false`; `Complex` is the old all-`true`; `DigitOrSpecial` is new. Serialises as `any_characters` / `digit_or_special` / `complex`. |
| `MfaConfig` | New field `secret_cipher: Option<Arc<dyn TotpSecretCipher>>` (`#[serde(skip)]`, hand-written `Debug` that prints presence only) | Add it to struct literals (or use `..Default::default()`). `None` fails closed — see below. |
| `SmtpConfig` | New fields `username: Option<String>`, `password: Option<String>`, `from_name: Option<String>`, `reply_to: Option<String>` (all `#[serde(default)]`) | Add them to struct literals. A `Some` username/password pair ⇒ STARTTLS with credentials; `None` ⇒ the unauthenticated plaintext relay you had before. `from_name` / `reply_to` set the `From` display name and a `Reply-To` header; `None` or blank sends the bare address and no `Reply-To`. |
| `EmailService` | `new()` takes `username, password` after `app_url`; every `send_*_email` is now `async`; new `with_transport`, `with_templates`, `with_from_name`, `with_reply_to`, `send_already_registered_email`, and a public `build_message(to, subject, body_html) -> Result<lettre::Message, String>` | `.await` the sends; construct with the two extra arguments. `build_message` returns exactly what a send would submit, so a host can assert headers without an SMTP server. |
| `AuthEmailTemplates` | New provided method `plain_text_alternative(&self, body_html: &str) -> Option<String>` (default `None`) | Nothing. Return `Some(text)` to send the mail as `multipart/alternative`, text part first. |
| `YAuthBuilder` | New additive seams `with_email_transport(AsyncSmtpTransport<Tokio1Executor>)` and `with_email_templates(Arc<dyn AuthEmailTemplates>)` | Optional. Both only take effect when `config.smtp` is `Some`. |
| `AuthEvent` | New variant `MfaVerificationFailed { user_id: Option<Uuid>, reason: String }` (webhook type `mfa.verification_failed`); `MfaEnabled` is now actually emitted; `PasswordChanged` is now also emitted by password-reset completion | Exhaustive `match`es on `AuthEvent` need a new arm. |
| `ChallengeRepository` | New methods `try_claim_challenge(key, value, ttl_secs) -> bool` (default: non-atomic read-then-write) and `update_challenge_if_live(key, value) -> bool` (default: `Err(RepoError::NotImplemented)`) | Custom backends: implement both as single statements. Built-in coverage is listed under *Backends* below. |
| `yauth` dependencies | `tracing 0.1` moves from dev-dependencies to dependencies | Nothing, unless you pin a conflicting `tracing`. |
| Password-policy 400 body | Violations compose into one sentence via `yauth::auth::password_policy::compose_message` | If a client parsed the old `;`-joined list, parse the sentence instead (or mirror the policy client-side). |

### Operational cutover 1 — TOTP secrets are sealed at rest

`yauth_totp_secrets.encrypted_secret` used to hold the **raw base32 secret**. It now holds
whatever your `TotpSecretCipher::seal` returns, and `open` **must refuse** anything
`seal` did not produce — including a legacy plaintext row. Consequences:

- **You must configure `MfaConfig::secret_cipher` to keep TOTP working.** With `None`,
  `POST /mfa/totp/setup`, `POST /mfa/totp/confirm` and `POST /mfa/backup-codes/regenerate`
  answer `503 {"error": "MFA is temporarily unavailable"}`, and `POST /mfa/verify` skips
  the TOTP factor and accepts backup codes only. The plugin never falls back to plaintext.
- **Existing secret rows stop authenticating.** Either re-seal them with your cipher in a
  one-off host script *before* the new release takes traffic (read the plaintext, call
  `seal(user_id, secret)`, write it back), or purge them and have users re-enrol:
  `DELETE FROM yauth_totp_secrets;`. A user with no secret row simply has no second factor
  until they enrol again.
- **The sealing key is now as durable as the enrolled population.** There is no key id in
  the envelope, no dual-read and no re-seal path inside yauth: if the key is rotated or
  lost, `verify` logs `secret_unsealable` and falls through to backup codes, and every
  affected user must re-enrol. Treat the key as undeletable.

### Operational cutover 2 — backup codes are 48-bit and Argon2id-hashed

Codes are now `xxxx-xxxx-xxxx` (12 hex characters) and stored as an Argon2id PHC string
(97 characters at the default parameters) in `yauth_backup_codes.code_hash`, which
previously held a 64-character hex SHA-256.

- **Legacy rows never verify again** (they are not valid PHC strings). Delete them together
  with the secrets above, or leave them and let users regenerate; either way anyone who
  keeps their TOTP enrolment should call `POST /mfa/backup-codes/regenerate` once.
- **Widen the column** on an existing database before the first enrolment on the new
  release, or every enrolment fails on insert:

  ```sql
  -- PostgreSQL (idempotent; also shipped as
  -- migrations/sqlx-pg/00000011_upgrade_widen_backup_code_hash.sql and
  -- migrations/diesel-pg/20260912000000_upgrade_widen_backup_code_hash/)
  ALTER TABLE yauth_backup_codes ALTER COLUMN code_hash TYPE VARCHAR;

  -- MySQL (idempotent; also shipped as
  -- migrations/sqlx-mysql/00000005_upgrade_widen_backup_code_hash.sql)
  ALTER TABLE `yauth_backup_codes` MODIFY `code_hash` VARCHAR(255) NOT NULL;

  -- SQLite: nothing to do — the column has always been TEXT.
  ```

  If you own your DDL, give the column at least 128 characters. The regenerated
  `yauth_init` snapshots already create it wide on a fresh database.

### Login-path hardening (behaviour, no schema)

- A TOTP code is **single-use at login**: a successful `verify` claims a 120-second
  replay marker (`try_claim_challenge`) before the code is checked, so two simultaneous
  requests with one valid code mint one session. A replayed-but-genuine code is refused
  without spending an attempt.
- A pending login challenge allows **five** wrong codes and is then deleted. The attempt
  counter is persisted with `update_challenge_if_live`; on a backend whose challenge repo
  does not implement it (see *Backends*), the plugin cannot persist the counter and
  **deletes the challenge on the first wrong code**, so the user has to log in again.
- The backup-code branch runs only for input shaped like `xxxx-xxxx-xxxx`, so a wrong TOTP
  guess costs one comparison, not up to ten Argon2id verifies.
- Enrolment and regeneration hash the whole code set concurrently *before* dropping the
  old set: `backup_code_count` × ~19 MiB of Argon2id memory is in flight per call, so keep
  `setup` and `regenerate` on your rate-limit table.
- Enabling TOTP (`POST /mfa/totp/confirm`) revokes the user's other sessions and emits
  `MfaEnabled { method: "totp" }`.
- Every rejection logs one `mfa_verification_failed` line (`target: "yauth::mfa"`, fields
  `user_id`, `reason`) and publishes `AuthEvent::MfaVerificationFailed`. Account lockout is
  deliberately **not** wired to MFA failures.
- OAuth/OIDC callbacks now emit `LoginSucceeded` *before* minting a session and honour
  the plugin verdict: `RequireMfa` returns `200 {"mfa_required": true,
  "pending_session_id": …, "user": …}` with **no** session cookie; `Block` returns the
  plugin's status. An enrolment-lookup error now blocks the login (500) instead of
  letting it through. The pending challenge records the original login method and the
  `login_succeeded` audit entry is written once the factor passes.
- Password-reset completion sweeps every session (unchanged) and now emits
  `PasswordChanged`; a failed sweep is logged as `session_sweep_failed`
  (`target: "yauth::session"`) instead of being discarded silently.

### Registration and email

- Registering an email that already has an account still answers the enumeration-safe
  `200`, but now **mails the existing address**: a fresh verification link if the account
  is unverified, or an "already registered" message carrying a fresh password-reset link
  if it is verified. Best-effort; needs `smtp` configured. `AuthEmailTemplates` has a fifth
  method, `already_registered`, for it.
- `EmailService` sends over lettre's `AsyncSmtpTransport<Tokio1Executor>` — no more
  blocking SMTP calls inside async handlers.
- Every link mail now carries the same sender identity and hygiene headers: `From` with
  the `SmtpConfig::from_name` display name, `Reply-To` when `SmtpConfig::reply_to` is set,
  a `Message-ID` minted under the `From` address's domain (`<uuid-v7@domain>`; lettre adds
  none), `Auto-Submitted: auto-generated` (RFC 3834) and `MIME-Version: 1.0`. The built-in
  templates still send a single `text/html` part.

### Email admission (behaviour, no schema)

These apply to the four routes that send mail to an address an unauthenticated caller
chose: `POST /register`, `POST /resend-verification`, `POST /forgot-password` and
`POST /magic-link/send`.

- **They fail closed.** If the rate-limit store errors, they answer
  `503 {"error": "Email requests are temporarily unavailable"}` instead of letting the
  request through unmetered, and log one `email admission budget unavailable` warning
  (`target: "yauth.email"`) that deliberately carries neither the key nor the error, since
  either can contain an address. Every other rate-limited route keeps its fail-open policy.
- **One recipient budget spans all four.** On top of the per-operation limits
  (`EmailPasswordConfig::rate_limit`, magic-link's fixed 10 per 60 s), an address gets at
  most 10 of these requests per 60 s in total, so hopping between routes does not multiply
  its quota. It is a fixed ceiling, not a setting: `rate_limit: None` turns off only the
  per-operation limits. It is checked before any account, token or mail is created —
  duplicate registrations included — and answers `429 {"error": "Too many requests"}`.
- **Budget keys no longer contain addresses.** The per-address keys are `<scope>:` plus the
  SHA-256 hex of the canonical address (NUL bytes stripped, trimmed, lowercased) for the
  scopes `auth-email` (the shared budget), `resend`, `forgot` and `magic-link`, so every key
  has a fixed width — a bounded `yauth_rate_limits.key` column (for example
  `VARCHAR(255)`) can no longer turn a long address into a 503 — and the table stores no
  addresses. The digest is unkeyed: it obscures the key, it does not anonymise it. The
  format change restarts in-flight windows once, at deploy.
- **Magic-link input is normalised like email-password input** (`input::sanitize`, then
  lowercase) instead of `trim().to_lowercase()`.
- The `register_rate_limited` and `magic_link_rate_limited` OpenTelemetry events are gone;
  the latter exported the recipient as `user.email`.
- **`SeaOrmPgBackend`'s rate limiter is transactional.** Each check inserts the counter row
  if it is absent, then locks it (`SELECT … FOR UPDATE`) before deciding, so concurrent
  first requests and window resets can no longer lose increments, and an unexpected insert
  failure now propagates instead of being ignored. A capacity of N admits exactly N
  requests per window, as the in-memory backend always has (this backend used to admit
  N − 1);
  refused requests neither increment the counter nor extend the window; the first request
  after a window expires starts a new one; a capacity above `i32::MAX` or a zero or
  out-of-range window is an error. Other backends are unchanged, and with `with_redis()` the
  Redis decorator keeps counting in Redis and reaches the database only when Redis fails.

### Backends

| Backend | `try_claim_challenge` | `update_challenge_if_live` |
|---------|-----------------------|----------------------------|
| `InMemoryBackend` | atomic (under the map mutex) | implemented |
| `SeaOrmPgBackend` | atomic (`INSERT … ON CONFLICT … WHERE expires_at <= now`) | implemented (conditional `UPDATE`) |
| Redis decorator | delegates to the inner repo, caches the winner | delegates, evicts the cache entry |
| every other backend (diesel-*, sqlx-*, seaorm-mysql, seaorm-sqlite, yauth-toasty) | **trait default: non-atomic** read-then-write — the single-use guarantee holds only without concurrent requests | **trait default: `NotImplemented`** — first wrong code deletes the challenge |

The Postgres SeaORM implementation is the reference for adding the two statements to the
other backends; each is one conditional write returning `rows_affected`.

---

## Adding lifecycle + logout + DCR columns (0.14.0)

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
