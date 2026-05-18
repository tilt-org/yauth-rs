//! SCIM 2.0 provisioning endpoints (issue #95).
//!
//! Mounts a tree of endpoints under
//! `/api/scim/v2/organizations/{org_id}/...` that IdPs (Okta, Entra,
//! OneLogin) use to provision users into yauth. Authentication is via
//! an **org-scoped API key** (issue #91) carried in
//! `Authorization: Bearer <key>` — the IdP admin generates the key on
//! the yauth side and pastes it into the IdP's SCIM connector.
//!
//! ## What's mounted
//!
//! | Method | Path                                                  | Module        |
//! |--------|-------------------------------------------------------|---------------|
//! | POST   | `/Users`                                              | [`users`]     |
//! | GET    | `/Users`                                              | [`users`]     |
//! | GET    | `/Users/{id}`                                         | [`users`]     |
//! | PUT    | `/Users/{id}`                                         | [`users`]     |
//! | PATCH  | `/Users/{id}`                                         | [`users`]     |
//! | DELETE | `/Users/{id}`                                         | [`users`]     |
//! | POST   | `/Groups`                                             | [`groups`]    |
//! | GET    | `/Groups`                                             | [`groups`]    |
//! | GET    | `/Groups/{id}`                                        | [`groups`]    |
//! | PUT    | `/Groups/{id}`                                        | [`groups`]    |
//! | PATCH  | `/Groups/{id}`                                        | [`groups`]    |
//! | DELETE | `/Groups/{id}`                                        | [`groups`]    |
//! | GET    | `/ServiceProviderConfig`                              | [`meta`]      |
//! | GET    | `/Schemas`                                            | [`meta`]      |
//! | GET    | `/ResourceTypes`                                      | [`meta`]      |
//!
//! ## Auth and content type
//!
//! Every endpoint does its own auth (bypassing the normal
//! cookie/JWT/X-Api-Key middleware) — IdPs only speak
//! `Authorization: Bearer <key>` and expect SCIM-shaped error JSON
//! (RFC 7644 §3.12), not yauth's normal envelope. Mounting SCIM as a
//! **public** route in the plugin system (no `auth_middleware` layer)
//! lets us control both.
//!
//! The success/failure response bodies all carry the
//! `application/scim+json` content type (RFC 7644 §3.8) — see
//! [`error::SCIM_CONTENT_TYPE`].
//!
//! ## Backend support
//!
//! - **Memory backend**: complete implementation.
//! - **SQL backends**: SCIM rides on the existing `Membership`,
//!   `User`, `ExternalIdentity`, and `ApiKey` repos — there are no
//!   new repo traits in this PR. SQL backends that already implement
//!   those traits get SCIM for free; backends that still stub them
//!   (per issues #87 / #93) will return 501 with `RepoError::NotImplemented`
//!   surfaced through the SCIM error envelope.
//!
//! ## Deliberate non-features (MVP)
//!
//! - Bulk endpoint (RFC 7644 §3.7) — declared unsupported.
//! - ETag concurrency — last-writer-wins; documented to admins.
//! - Sort — `?sortBy` is tolerated but ignored.
//! - Enterprise extension persistence — recognised in `schemas[]`, fields
//!   ignored.

#![forbid(unsafe_code)]
#![cfg(feature = "scim")]

use axum::Router;
use axum::routing::{get, post};

use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

pub mod auth;
pub mod error;
pub mod filter;
pub mod groups;
pub mod meta;
pub mod types;
pub mod users;

/// Plugin entry point. Mounts the SCIM tree on the **public** router so
/// the standard auth middleware doesn't run — SCIM does its own auth
/// and error shape.
pub struct ScimPlugin;

impl YAuthPlugin for ScimPlugin {
    fn name(&self) -> &'static str {
        "scim"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(scim_routes())
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }
}

/// Build the SCIM sub-router. Exposed for tests that want to mount
/// SCIM in isolation.
pub fn scim_routes() -> Router<YAuthState> {
    let base = "/api/scim/v2/organizations/{org_id}";
    Router::new()
        // ── Users ──
        .route(
            &format!("{base}/Users"),
            post(users::create_user).get(users::list_users),
        )
        .route(
            &format!("{base}/Users/{{user_id}}"),
            get(users::get_user)
                .put(users::put_user)
                .patch(users::patch_user)
                .delete(users::delete_user),
        )
        // ── Groups ──
        .route(
            &format!("{base}/Groups"),
            post(groups::create_group).get(groups::list_groups),
        )
        .route(
            &format!("{base}/Groups/{{group_id}}"),
            get(groups::get_group)
                .put(groups::put_group)
                .patch(groups::patch_group)
                .delete(groups::delete_group),
        )
        // ── Meta — no PATCH/POST, all GETs ──
        .route(
            &format!("{base}/ServiceProviderConfig"),
            get(|| async { meta::service_provider_config() }),
        )
        .route(
            &format!("{base}/Schemas"),
            get(|| async { meta::schemas() }),
        )
        .route(
            &format!("{base}/ResourceTypes"),
            get(|| async { meta::resource_types() }),
        )
}
