//! Schema definitions for each built-in plugin.
//!
//! These functions are called by name from the CLI and from the yauth library.
//! They are always compiled (no feature gates) since this crate is a code generator.

use super::types::*;

/// Email-password plugin: passwords, email_verifications, password_resets.
pub fn email_password_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_passwords")
            .description("Hashed passwords. One row per user.")
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .primary_key()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("password_hash", ColumnType::Varchar)),
        TableDef::new("yauth_email_verifications")
            .description("Pending email verification tokens.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("token_hash", ColumnType::VarcharN(64)).unique())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_password_resets")
            .description("Pending password reset tokens.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("token_hash", ColumnType::VarcharN(64)).unique())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("used_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Passkey plugin: webauthn_credentials.
pub fn passkey_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_webauthn_credentials")
            .description("WebAuthn/passkey credentials. Multiple per user.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("name", ColumnType::Varchar))
            .column(ColumnDef::new("aaguid", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("device_name", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("credential", ColumnType::Json))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("last_used_at", ColumnType::DateTime).nullable()),
    ]
}

/// MFA plugin: totp_secrets, backup_codes.
pub fn mfa_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_totp_secrets")
            .description("TOTP secrets for MFA. One per user.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .unique()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("encrypted_secret", ColumnType::Varchar))
            .column(ColumnDef::new("verified", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_backup_codes")
            .description("MFA backup codes. Multiple per user, single-use.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            // Argon2id PHC string (97 chars for any realistic `m_cost`, salt
            // embedded), not the 64-char hex SHA-256 this column held before
            // 2026-08-10 — so `VarcharN(64)` no longer fits and every enrolment
            // would fail on insert.
            //
            // `ColumnType::Varchar` is not one width: Postgres renders a bare
            // `VARCHAR` (unbounded), SQLite `TEXT`, MySQL `VARCHAR(255)`. All
            // three hold 97 characters with room to spare, which is the bar
            // here; only the Postgres arm is genuinely unbounded. A host that
            // owns its own DDL must give this column at least 128 characters.
            .column(ColumnDef::new("code_hash", ColumnType::Varchar))
            .column(ColumnDef::new("used", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// OAuth plugin: oauth_accounts, oauth_states.
pub fn oauth_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_oauth_accounts")
            .description("Linked OAuth provider accounts.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("provider", ColumnType::Varchar))
            .column(ColumnDef::new("provider_user_id", ColumnType::Varchar))
            .column(ColumnDef::new("access_token_enc", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("refresh_token_enc", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("expires_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_oauth_states")
            .description("OAuth CSRF state tokens. Consumed on callback.")
            .column(ColumnDef::new("state", ColumnType::Varchar).primary_key())
            .column(ColumnDef::new("provider", ColumnType::Varchar))
            .column(ColumnDef::new("redirect_url", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Bearer plugin: refresh_tokens.
pub fn bearer_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_refresh_tokens")
            .description("JWT refresh tokens with rotation family tracking.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("token_hash", ColumnType::VarcharN(64)).unique())
            .column(ColumnDef::new("family_id", ColumnType::Uuid))
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("revoked", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// API key plugin: api_keys.
///
/// Issue #91 added `organization_id`, `role`, and `created_by_user_id`
/// to support org-scoped service-account keys alongside user-scoped keys.
/// Both `user_id` and `organization_id` are nullable; the application-layer
/// repo enforces the "exactly one owner" invariant. A future schema
/// upgrade should add a CHECK / partial-unique-index per dialect:
///   CHECK (
///     (user_id IS NULL) <> (organization_id IS NULL)
///   )
/// (omitted here because the declarative schema framework does not yet
/// emit CHECK constraints — tracked as a follow-up).
pub fn api_key_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_api_keys")
            .description(
                "API keys. Identified by prefix, verified by hash. \
                 Owned by either a user OR an organization (#91).",
            )
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            // No FK to yauth_organizations because the `organizations`
            // plugin is optional — its table may not be present in a
            // single-tenant deployment. The app-layer repo enforces
            // referential integrity. Operators who enable both plugins
            // can add the FK manually post-migration.
            .column(ColumnDef::new("organization_id", ColumnType::Uuid).nullable())
            .column(ColumnDef::new("key_prefix", ColumnType::VarcharN(12)).unique())
            .column(ColumnDef::new("key_hash", ColumnType::VarcharN(64)))
            .column(ColumnDef::new("name", ColumnType::Varchar))
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            // Issue #91: for org-scoped keys, the role the bearer acts as.
            // NULL for user-scoped keys.
            .column(ColumnDef::new("role", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("last_used_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            // Issue #91: audit trail — who minted the key. Always set.
            .column(
                ColumnDef::new("created_by_user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Restrict),
            ),
    ]
}

/// Magic link plugin: magic_links.
pub fn magic_link_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_magic_links")
            .description("Passwordless login tokens. Single-use, time-limited.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("email", ColumnType::Varchar))
            .column(ColumnDef::new("token_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("used", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// OAuth2 server plugin: oauth2_clients, authorization_codes, consents, device_codes.
pub fn oauth2_server_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_oauth2_clients")
            .description("Registered OAuth2 server clients.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("client_id", ColumnType::Varchar).unique())
            .column(ColumnDef::new("client_secret_hash", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("redirect_uris", ColumnType::Json))
            .column(ColumnDef::new("client_name", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("grant_types", ColumnType::Json))
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(ColumnDef::new("is_public", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("token_endpoint_auth_method", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("public_key_pem", ColumnType::Text).nullable())
            .column(ColumnDef::new("jwks_uri", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("banned_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("banned_reason", ColumnType::Varchar).nullable())
            // OIDC logout (RP-Initiated Logout 1.0 + Back-Channel Logout 1.0).
            //   post_logout_redirect_uris: JSON array of URIs the client may be
            //     redirected to after end_session (exact-match validated to
            //     prevent open redirect). Mirrors `scopes`: nullable JSON,
            //     decoded to an empty list when absent.
            //   backchannel_logout_uri: the client's Back-Channel Logout
            //     endpoint; when set, the OP POSTs a signed logout_token there.
            //   backchannel_logout_session_required: client wants a `sid` claim.
            .column(ColumnDef::new("post_logout_redirect_uris", ColumnType::Json).nullable())
            .column(ColumnDef::new("backchannel_logout_uri", ColumnType::Text).nullable())
            .column(
                ColumnDef::new("backchannel_logout_session_required", ColumnType::Boolean)
                    .default("false"),
            )
            // Stale-DCR-client garbage collection.
            //   dynamically_registered: true only for self-registered clients;
            //     scopes the sweep so admin-provisioned clients are never
            //     reclaimed.
            //   last_used_at: last successful token-endpoint use (NULL → fall
            //     back to created_at) so a client in active use is never swept
            //     regardless of age.
            .column(ColumnDef::new("dynamically_registered", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("last_used_at", ColumnType::DateTime).nullable()),
        TableDef::new("yauth_authorization_codes")
            .description("OAuth2 authorization codes. Single-use, time-limited.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("code_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("client_id", ColumnType::Varchar))
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(ColumnDef::new("redirect_uri", ColumnType::Varchar))
            .column(ColumnDef::new("code_challenge", ColumnType::Varchar))
            .column(ColumnDef::new("code_challenge_method", ColumnType::Varchar))
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("used", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("nonce", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_consents")
            .description("User consent records for OAuth2 clients.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("client_id", ColumnType::Varchar))
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_device_codes")
            .description("Device authorization flow codes.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("device_code_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("user_code", ColumnType::Varchar).unique())
            .column(ColumnDef::new("client_id", ColumnType::Varchar))
            .column(ColumnDef::new("scopes", ColumnType::Json).nullable())
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("status", ColumnType::Varchar).default("'pending'"))
            .column(ColumnDef::new("interval", ColumnType::Int).default("5"))
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("last_polled_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Account lockout plugin: account_locks, unlock_tokens.
pub fn account_lockout_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_account_locks")
            .description("Account lockout state. One row per user.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .unique()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("failed_count", ColumnType::Int).default("0"))
            .column(ColumnDef::new("locked_until", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("lock_count", ColumnType::Int).default("0"))
            .column(ColumnDef::new("locked_reason", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_unlock_tokens")
            .description("Account unlock tokens. Time-limited.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("token_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Webhooks plugin: webhooks, webhook_deliveries.
pub fn webhooks_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_webhooks")
            .description("Webhook endpoint configurations.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("url", ColumnType::Varchar))
            .column(ColumnDef::new("secret", ColumnType::Varchar))
            .column(ColumnDef::new("events", ColumnType::Json))
            .column(ColumnDef::new("active", ColumnType::Boolean).default("true"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_webhook_deliveries")
            .description("Webhook delivery attempts and responses.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("webhook_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_webhooks", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("event_type", ColumnType::Varchar))
            .column(ColumnDef::new("payload", ColumnType::Json))
            .column(ColumnDef::new("status_code", ColumnType::SmallInt).nullable())
            .column(ColumnDef::new("response_body", ColumnType::Text).nullable())
            .column(ColumnDef::new("success", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("attempt", ColumnType::Int).default("1"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}

/// Organizations plugin: organizations, memberships, invitations.
///
/// This is the foundational multi-tenancy primitive — see issue #87.
/// All three tables are additive; existing single-tenant deployments are
/// unaffected when the `organizations` feature is off.
pub fn organizations_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_organizations")
            .description("Organizations / tenants / workspaces. Top-level multi-tenant boundary.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("name", ColumnType::Varchar))
            // Slug uniqueness is case-insensitive per the trait contract
            // (see `crates/yauth/src/repo/organization.rs`). The DDL
            // generator enforces this via a functional unique index on
            // `LOWER(slug)` (Postgres/SQLite) or a generated `slug_lower`
            // shadow column (MySQL).
            .column(ColumnDef::new("slug", ColumnType::Varchar).case_insensitive_unique())
            .column(ColumnDef::new("display_name", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("avatar_url", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("metadata", ColumnType::Json).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_memberships")
            .description("Many-to-many: which users belong to which organizations + role.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("organization_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_organizations", "id", OnDelete::Cascade),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("role", ColumnType::Varchar).default("'member'"))
            .column(ColumnDef::new("status", ColumnType::Varchar).default("'active'"))
            .column(ColumnDef::new("invited_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("joined_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        TableDef::new("yauth_invitations")
            .description("Pending invitations to join an organization. Single-use, time-limited.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("organization_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_organizations", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("email", ColumnType::Varchar))
            .column(ColumnDef::new("role", ColumnType::Varchar).default("'member'"))
            .column(ColumnDef::new("token_hash", ColumnType::VarcharN(64)).unique())
            .column(
                ColumnDef::new("invited_by_user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("expires_at", ColumnType::DateTime))
            .column(ColumnDef::new("accepted_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
        // Verified email domains + JIT membership (issue #90).
        //
        // `domain` is deployment-wide unique and stored canonicalized
        // (lowercase, trimmed). Case-insensitive uniqueness matches the
        // organizations slug pattern: functional unique index on
        // `LOWER(domain)` for Postgres/SQLite; generated shadow column on
        // MySQL. Anti-abuse default `require_email_verified = true`.
        TableDef::new("yauth_organization_domains")
            .description(
                "Domain claims for an organization. Verified claims may auto-join \
                 matching users on signup (JIT membership).",
            )
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("organization_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_organizations", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("domain", ColumnType::Varchar).case_insensitive_unique())
            .column(ColumnDef::new("status", ColumnType::Varchar).default("'pending'"))
            .column(ColumnDef::new("verification_token", ColumnType::Varchar))
            .column(ColumnDef::new("verified_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("last_checked_at", ColumnType::DateTime).nullable())
            .column(ColumnDef::new("auto_join_on_signup", ColumnType::Boolean).default("false"))
            .column(
                ColumnDef::new("default_role_on_auto_join", ColumnType::Varchar)
                    .default("'member'"),
            )
            .column(ColumnDef::new("require_email_verified", ColumnType::Boolean).default("true"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        // Per-org auth policy (issue #92).
        //
        // One row per organization (1:1). Absence of a row means "inherit
        // global YAuthConfig" — see `crates/yauth-entity/src/organization_policy.rs`
        // for resolution rules. `organization_id` is BOTH primary key and
        // foreign key so the policy disappears when the org is dropped.
        // List/enum-shaped fields land in a JSON column for dialect parity
        // and forward-compat (e.g. adding `sso_oidc` to the auth method
        // catalogue is a no-DDL change).
        TableDef::new("yauth_organization_policies")
            .description(
                "Per-organization auth policy override — session/idle timeouts, \
                 MFA enforcement, IP allowlist, max concurrent sessions, allowed \
                 auth methods, and session binding mode.",
            )
            .column(
                ColumnDef::new("organization_id", ColumnType::Uuid)
                    .primary_key()
                    .references("yauth_organizations", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("max_session_duration_secs", ColumnType::Int).nullable())
            .column(ColumnDef::new("idle_timeout_secs", ColumnType::Int).nullable())
            .column(ColumnDef::new("mfa_required", ColumnType::Boolean).default("false"))
            .column(ColumnDef::new("mfa_grace_period_days", ColumnType::Int).default("14"))
            // MySQL forbids defaults on JSON columns; populate `[]` at the
            // application layer when inserting.
            .column(ColumnDef::new("ip_allowlist", ColumnType::Json))
            .column(ColumnDef::new("max_concurrent_sessions", ColumnType::Int).nullable())
            .column(ColumnDef::new("allowed_auth_methods", ColumnType::Json))
            .column(ColumnDef::new("session_binding", ColumnType::Varchar).default("'none'"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        // SSO connections — federated sign-in from an external IdP (issue #93).
        //
        // Each row attaches one OIDC (or, in #94, SAML) connection to one
        // organization. `kind` is a `VARCHAR` so adding a new federation
        // protocol is a no-DDL change. `config` is a JSON blob whose schema
        // is determined by `kind` — see `OidcConnectionConfig` in
        // `crates/yauth-entity/src/sso_connection.rs`. The embedded
        // `client_secret` is encrypted at rest at the repository boundary.
        TableDef::new("yauth_sso_connections")
            .description(
                "Federation connection (OIDC client / SAML SP) attached to one \
                 organization. `config` carries protocol-specific JSON and \
                 `client_secret` inside is encrypted at rest.",
            )
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("organization_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_organizations", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("kind", ColumnType::Varchar).default("'oidc_client'"))
            .column(ColumnDef::new("name", ColumnType::Varchar))
            .column(ColumnDef::new("status", ColumnType::Varchar).default("'draft'"))
            .column(ColumnDef::new("config", ColumnType::Json))
            .column(ColumnDef::new("jit_provisioning_enabled", ColumnType::Boolean).default("true"))
            .column(ColumnDef::new("default_role_on_jit", ColumnType::Varchar).default("'member'"))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()")),
        // External identity links — IdP `(provider, external_id)` pair
        // bound to a yauth user (issue #93). The pair is deployment-wide
        // unique so two yauth accounts can never share one IdP identity.
        // Cascade-on-user-delete: when the user goes, the link goes;
        // re-linking is the (new) user's job.
        TableDef::new("yauth_external_identities")
            .description(
                "External (IdP) identity linked to a yauth user. Unique on \
                 (provider, external_id) — one yauth user per IdP-side identity.",
            )
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(
                ColumnDef::new("user_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_users", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("provider", ColumnType::Varchar))
            .column(ColumnDef::new("external_id", ColumnType::Varchar))
            .column(ColumnDef::new("linked_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("last_login_at", ColumnType::DateTime).default("now()")),
        // SSO login states (issue #93, Phase B). One row per
        // `/sso/login` request; consumed at `/sso/callback`. The
        // `state` column is the primary lookup key — random opaque
        // token sent on the authorize URL, returned by the IdP.
        // Rows are reaped on read (consume-once) and on `expires_at`.
        TableDef::new("yauth_sso_login_states")
            .description(
                "Short-lived state for an OIDC `/sso/login` round-trip. \
                 One row created at authorize-request time, consumed \
                 (deleted) at callback time. Expires in 10 minutes.",
            )
            .column(ColumnDef::new("state", ColumnType::Varchar).primary_key())
            .column(
                ColumnDef::new("connection_id", ColumnType::Uuid)
                    .nullable()
                    .references("yauth_sso_connections", "id", OnDelete::Cascade),
            )
            .column(ColumnDef::new("issuer", ColumnType::Varchar))
            .column(ColumnDef::new("nonce", ColumnType::Varchar))
            .column(ColumnDef::new("pkce_verifier", ColumnType::Varchar))
            .column(ColumnDef::new("redirect_to", ColumnType::Varchar).nullable())
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
            .column(ColumnDef::new("expires_at", ColumnType::DateTime)),
    ]
}

/// OIDC plugin: oidc_nonces.
pub fn oidc_schema() -> Vec<TableDef> {
    vec![
        TableDef::new("yauth_oidc_nonces")
            .description("OIDC nonce values for replay protection.")
            .column(
                ColumnDef::new("id", ColumnType::Uuid)
                    .primary_key()
                    .default("gen_random_uuid()"),
            )
            .column(ColumnDef::new("nonce_hash", ColumnType::Varchar).unique())
            .column(ColumnDef::new("authorization_code_id", ColumnType::Uuid))
            .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()")),
    ]
}
