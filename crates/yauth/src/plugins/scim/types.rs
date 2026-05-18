//! SCIM 2.0 wire types (RFC 7643 Core User + Group, RFC 7644 envelopes).
//!
//! Hand-rolled rather than depending on the `scim_v2` crate. SCIM is a
//! REST + JSON CRUD spec — the type surface yauth actually needs is
//! small (Core User, Core Group, ListResponse, Error, PatchOp), and a
//! hand-rolled set keeps us free of an extra dependency and avoids the
//! risk of an unmaintained upstream.
//!
//! ## What's modelled
//!
//! - `urn:ietf:params:scim:schemas:core:2.0:User` (Core User)
//! - `urn:ietf:params:scim:schemas:core:2.0:Group` (Core Group)
//! - `urn:ietf:params:scim:api:messages:2.0:ListResponse`
//! - `urn:ietf:params:scim:api:messages:2.0:Error`
//! - `urn:ietf:params:scim:api:messages:2.0:PatchOp`
//!
//! Enterprise extension (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`)
//! is recognised as a known schema URN but its fields are not persisted
//! — see `ENTERPRISE_USER_SCHEMA`.
//!
//! ## Schema URN validation
//!
//! [`validate_schemas`] is the gate handlers MUST call before treating
//! a payload as Core User / Core Group. Unknown schema URNs are rejected
//! with `invalidSyntax` rather than silently passed through.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────
// Schema URN constants
// ──────────────────────────────────────────────

pub const CORE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const CORE_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const ENTERPRISE_USER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/// Known schema URNs a request payload is allowed to declare. Unknown
/// URNs in `schemas[]` get rejected with `invalidSyntax` per RFC 7644
/// §3.3 — this prevents arbitrary extension data from being passed
/// through to storage.
pub const KNOWN_REQUEST_SCHEMAS: &[&str] = &[
    CORE_USER_SCHEMA,
    CORE_GROUP_SCHEMA,
    ENTERPRISE_USER_SCHEMA,
    PATCH_OP_SCHEMA,
];

// ──────────────────────────────────────────────
// Resource metadata (RFC 7643 §3.1)
// ──────────────────────────────────────────────

/// Common `meta` block returned on every resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceMeta {
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    /// ISO-8601 `created`.
    pub created: String,
    /// ISO-8601 `lastModified`. We set it equal to `created` on create.
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    /// Fully-qualified location (`{base}/api/scim/v2/organizations/{org}/Users/{id}`).
    pub location: String,
}

// ──────────────────────────────────────────────
// Core User (RFC 7643 §4.1)
// ──────────────────────────────────────────────

/// Email entry on a SCIM User. RFC 7643 lists `value`, `type`, `primary`,
/// `display`. yauth uses `value` (the address) and `primary` only — the
/// rest are surfaced verbatim on response if present, but never drive
/// state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimEmail {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// Display name pair (`familyName` + `givenName`). yauth doesn't split
/// names internally — we serialise the assembled `displayName` and
/// accept either `name.formatted` or `givenName + familyName` on input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimName {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(
        default,
        rename = "familyName",
        skip_serializing_if = "Option::is_none"
    )]
    pub family_name: Option<String>,
    #[serde(default, rename = "givenName", skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(
        default,
        rename = "middleName",
        skip_serializing_if = "Option::is_none"
    )]
    pub middle_name: Option<String>,
}

/// Group reference inside a `User.groups[]` block. SCIM clients use this
/// for role assignment. RFC 7643 §4.1.2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimGroupRef {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(rename = "$ref", default, skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
}

/// SCIM Core User resource. Fields not present on a response are
/// omitted; on input we accept any subset and ignore unknown attributes
/// (see `serde(deny_unknown_fields = false)` — `deny` is OFF on
/// purpose, but the handler MUST still validate `schemas[]` via
/// [`validate_schemas`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimUser {
    /// Always populated on responses. Always empty on POST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `externalId` is the IdP-side stable id. yauth treats this as the
    /// primary join key on subsequent POSTs (idempotency).
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    /// Schema URNs declared on this payload. `schemas[]` MUST include
    /// `CORE_USER_SCHEMA`; additional entries are tolerated only when
    /// they appear in [`KNOWN_REQUEST_SCHEMAS`].
    #[serde(default)]
    pub schemas: Vec<String>,
    /// Username — RFC 7643 §4.1.1 requires unique within the IdP. yauth
    /// uses email as the canonical username; if `userName` differs from
    /// `emails[0].value` we still treat the email as the source of
    /// truth.
    #[serde(rename = "userName", default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    /// Display name (a separate field from `name`).
    #[serde(
        rename = "displayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    /// Structured name. Optional — `displayName` wins when both
    /// present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    /// Emails. yauth uses the first entry (or the entry marked
    /// `primary: true`) for the user's address.
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    /// `active: false` → membership goes to `suspended`. Missing field
    /// is treated as `true` on create (active) and as "no change" on
    /// update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// Group memberships. Read-only on User per RFC 7643 §4.1.2 — yauth
    /// computes this from `Membership` rows and ignores incoming
    /// `groups[]` on POST/PUT (group-to-role mapping happens via
    /// SsoConnection attribute mappings, or `setRole` on Groups).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ScimGroupRef>,
    /// `meta` block — populated on responses, empty on input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<ResourceMeta>,
}

impl ScimUser {
    /// Pull the canonical email out of a parsed user payload. Looks for
    /// the entry marked `primary: true` first, then falls back to the
    /// first entry, then to `userName` (which IdPs often set to an
    /// email address).
    pub fn canonical_email(&self) -> Option<String> {
        if let Some(primary) = self.emails.iter().find(|e| e.primary.unwrap_or(false)) {
            return Some(primary.value.clone());
        }
        if let Some(first) = self.emails.first() {
            return Some(first.value.clone());
        }
        self.user_name.clone()
    }

    /// Pull the display name. Prefers `displayName`, falls back to
    /// `name.formatted`, then to "givenName familyName".
    pub fn pick_display_name(&self) -> Option<String> {
        if let Some(d) = &self.display_name {
            return Some(d.clone());
        }
        if let Some(n) = &self.name
            && let Some(f) = &n.formatted
        {
            return Some(f.clone());
        }
        if let Some(n) = &self.name {
            match (&n.given_name, &n.family_name) {
                (Some(g), Some(f)) => return Some(format!("{g} {f}")),
                (Some(g), None) => return Some(g.clone()),
                (None, Some(f)) => return Some(f.clone()),
                (None, None) => {}
            }
        }
        None
    }
}

// ──────────────────────────────────────────────
// Core Group (RFC 7643 §4.2)
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimGroupMember {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(rename = "$ref", default, skip_serializing_if = "Option::is_none")]
    pub ref_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimGroup {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    #[serde(
        rename = "displayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    #[serde(default)]
    pub members: Vec<ScimGroupMember>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<ResourceMeta>,
}

// ──────────────────────────────────────────────
// PatchOp (RFC 7644 §3.5.2)
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PatchOp {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations", default)]
    pub operations: Vec<PatchOperation>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PatchOperation {
    /// "add" / "replace" / "remove". Case-insensitive per RFC 7644
    /// §3.5.2; we lowercase on read.
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

// ──────────────────────────────────────────────
// List response + error (RFC 7644 §3.4.2 + §3.12)
// ──────────────────────────────────────────────

/// Paginated list response envelope. `T` is one of `ScimUser` /
/// `ScimGroup` typically.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListResponse<T: Serialize> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: usize,
    #[serde(rename = "startIndex")]
    pub start_index: usize,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T: Serialize> ListResponse<T> {
    pub fn new(total: usize, start_index: usize, items_per_page: usize, resources: Vec<T>) -> Self {
        Self {
            schemas: vec![LIST_RESPONSE_SCHEMA.to_string()],
            total_results: total,
            start_index,
            items_per_page,
            resources,
        }
    }
}

/// SCIM error envelope (RFC 7644 §3.12).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScimError {
    pub schemas: Vec<String>,
    /// HTTP status code as a string (`"401"`, `"404"`, …). RFC 7644
    /// quirk — it really is a string.
    pub status: String,
    /// One of the well-known SCIM error types. Optional — only set when
    /// we have a concrete `scimType` to communicate.
    #[serde(rename = "scimType", default, skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    /// Free-form detail. Never includes secret material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ScimError {
    pub fn new(status: u16, scim_type: Option<&str>, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec![ERROR_SCHEMA.to_string()],
            status: status.to_string(),
            scim_type: scim_type.map(|s| s.to_string()),
            detail: Some(detail.into()),
        }
    }
}

// ──────────────────────────────────────────────
// Schema URN validation
// ──────────────────────────────────────────────

/// Validate the `schemas[]` array on an incoming request payload.
///
/// - MUST contain the expected primary URN (`primary`).
/// - MAY contain additional URNs, but they must all appear in
///   [`KNOWN_REQUEST_SCHEMAS`]. Unknown URNs are rejected so a bad IdP
///   can't smuggle arbitrary extension data through and rely on us
///   passing it untouched.
///
/// Returns a [`ScimError`] with `scimType = "invalidSyntax"` on
/// rejection — the handler maps it to a 400.
pub fn validate_schemas(schemas: &[String], primary: &str) -> Result<(), ScimError> {
    if !schemas.iter().any(|s| s == primary) {
        return Err(ScimError::new(
            400,
            Some("invalidSyntax"),
            format!("schemas[] must include {primary}"),
        ));
    }
    for s in schemas {
        if !KNOWN_REQUEST_SCHEMAS.contains(&s.as_str()) {
            return Err(ScimError::new(
                400,
                Some("invalidSyntax"),
                format!("unknown schema urn: {s}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_schemas_accepts_core_user() {
        assert!(validate_schemas(&[CORE_USER_SCHEMA.to_string()], CORE_USER_SCHEMA).is_ok());
    }

    #[test]
    fn validate_schemas_rejects_unknown() {
        let err = validate_schemas(
            &[
                CORE_USER_SCHEMA.to_string(),
                "urn:custom:made-up:1.0".to_string(),
            ],
            CORE_USER_SCHEMA,
        )
        .unwrap_err();
        assert_eq!(err.status, "400");
        assert_eq!(err.scim_type.as_deref(), Some("invalidSyntax"));
    }

    #[test]
    fn validate_schemas_rejects_missing_primary() {
        let err =
            validate_schemas(&[ENTERPRISE_USER_SCHEMA.to_string()], CORE_USER_SCHEMA).unwrap_err();
        assert_eq!(err.status, "400");
    }

    #[test]
    fn canonical_email_prefers_primary() {
        let u = ScimUser {
            schemas: vec![CORE_USER_SCHEMA.into()],
            emails: vec![
                ScimEmail {
                    value: "first@example.com".into(),
                    primary: Some(false),
                    r#type: None,
                    display: None,
                },
                ScimEmail {
                    value: "primary@example.com".into(),
                    primary: Some(true),
                    r#type: None,
                    display: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(u.canonical_email().as_deref(), Some("primary@example.com"));
    }

    #[test]
    fn canonical_email_falls_back_to_username() {
        let u = ScimUser {
            schemas: vec![CORE_USER_SCHEMA.into()],
            user_name: Some("alice@example.com".into()),
            ..Default::default()
        };
        assert_eq!(u.canonical_email().as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn pick_display_name_prefers_displayname() {
        let u = ScimUser {
            schemas: vec![CORE_USER_SCHEMA.into()],
            display_name: Some("Alice Wonderland".into()),
            name: Some(ScimName {
                given_name: Some("Alice".into()),
                family_name: Some("Other".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(u.pick_display_name().as_deref(), Some("Alice Wonderland"));
    }

    #[test]
    fn pick_display_name_assembles_from_given_family() {
        let u = ScimUser {
            schemas: vec![CORE_USER_SCHEMA.into()],
            name: Some(ScimName {
                given_name: Some("Alice".into()),
                family_name: Some("Smith".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(u.pick_display_name().as_deref(), Some("Alice Smith"));
    }

    #[test]
    fn scim_error_roundtrip() {
        let e = ScimError::new(404, Some("noTarget"), "not found");
        let j = serde_json::to_string(&e).unwrap();
        // ScimError MUST carry the messages:Error URN — IdPs parse this.
        assert!(j.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
        assert!(j.contains("\"status\":\"404\""));
        assert!(j.contains("\"scimType\":\"noTarget\""));
    }

    #[test]
    fn list_response_carries_listresponse_urn() {
        let lr: ListResponse<ScimUser> = ListResponse::new(0, 1, 100, vec![]);
        let j = serde_json::to_string(&lr).unwrap();
        assert!(j.contains("urn:ietf:params:scim:api:messages:2.0:ListResponse"));
        assert!(j.contains("\"totalResults\":0"));
        assert!(j.contains("\"Resources\":[]"));
    }
}
