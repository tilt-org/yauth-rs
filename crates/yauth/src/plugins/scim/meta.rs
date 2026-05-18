//! SCIM meta endpoints — `ServiceProviderConfig`, `Schemas`,
//! `ResourceTypes`.
//!
//! These three endpoints are how an IdP discovers the SCIM server's
//! capabilities. They are unauthenticated in the spec (RFC 7644 §4) —
//! some IdPs hit them before the admin even finishes pasting in the
//! bearer key. yauth still requires authentication on them because:
//!
//! 1. The capability surface is identical across tenants — there is
//!    nothing tenant-specific to leak.
//! 2. Putting these behind the same gate keeps the surface uniform
//!    for log/metric purposes.
//! 3. IdPs that fetch unauthenticated are documented to retry after
//!    setting the key — Okta, Entra, OneLogin all comply.

#![forbid(unsafe_code)]

use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;

use super::error::scim_json_response;

#[derive(Serialize)]
struct Supported {
    supported: bool,
}

const SUPPORTED_TRUE: Supported = Supported { supported: true };
const SUPPORTED_FALSE: Supported = Supported { supported: false };

#[derive(Serialize)]
struct BulkSupport {
    supported: bool,
    #[serde(rename = "maxOperations")]
    max_operations: usize,
    #[serde(rename = "maxPayloadSize")]
    max_payload_size: usize,
}

#[derive(Serialize)]
struct FilterSupport {
    supported: bool,
    #[serde(rename = "maxResults")]
    max_results: usize,
}

#[derive(Serialize)]
struct AuthScheme {
    name: &'static str,
    description: &'static str,
    #[serde(rename = "specUri")]
    spec_uri: &'static str,
    #[serde(rename = "documentationUri")]
    documentation_uri: &'static str,
    r#type: &'static str,
    primary: bool,
}

const BEARER_AUTH: AuthScheme = AuthScheme {
    name: "OAuth Bearer Token",
    description: "Org-scoped API key (RFC 6750 §2.1)",
    spec_uri: "https://tools.ietf.org/html/rfc6750",
    documentation_uri: "https://github.com/yackey-labs/yauth/blob/main/docs/scim/README.md",
    r#type: "oauthbearertoken",
    primary: true,
};

/// `GET /api/scim/v2/organizations/{org_id}/ServiceProviderConfig`
pub fn service_provider_config() -> Response {
    let body = serde_json::json!({
        "schemas": [super::types::SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": "https://github.com/yackey-labs/yauth/blob/main/docs/scim/README.md",
        "patch": SUPPORTED_TRUE,
        // Bulk operations (RFC 7644 §3.7) — declared OFF for MVP.
        "bulk": BulkSupport { supported: false, max_operations: 0, max_payload_size: 0 },
        // Filtering: eq / co / sw / AND only.
        "filter": FilterSupport { supported: true, max_results: 500 },
        // No password-change endpoint exposed on SCIM (the IdP changes
        // its own copy; yauth users authenticate via SSO/passkey/MFA).
        "changePassword": SUPPORTED_FALSE,
        // No sort ordering — clients can issue startIndex paging.
        "sort": SUPPORTED_FALSE,
        // No ETags — last-writer-wins (documented).
        "etag": SUPPORTED_FALSE,
        "authenticationSchemes": [BEARER_AUTH],
    });
    scim_json_response(StatusCode::OK, body)
}

/// `GET /api/scim/v2/organizations/{org_id}/Schemas`
///
/// Returns the Core User + Core Group schema descriptors. We do not
/// surface the enterprise extension here — yauth tolerates it on
/// input but does not persist its fields, and advertising it would
/// imply round-trip fidelity we don't offer.
pub fn schemas() -> Response {
    let user = serde_json::json!({
        "id": super::types::CORE_USER_SCHEMA,
        "name": "User",
        "description": "Core User schema (RFC 7643 §4.1)",
        "attributes": [
            attr("userName", "string", "server"),
            attr("displayName", "string", "none"),
            attr("externalId", "string", "none"),
            attr("active", "boolean", "none"),
            complex_attr("name", &["formatted", "familyName", "givenName"]),
            multi_complex_attr("emails", &["value", "type", "primary"]),
            multi_complex_attr("groups", &["value", "display"]),
        ],
        "meta": {
            "resourceType": "Schema",
            "location": format!("/Schemas/{}", super::types::CORE_USER_SCHEMA),
        }
    });
    let group = serde_json::json!({
        "id": super::types::CORE_GROUP_SCHEMA,
        "name": "Group",
        "description": "Core Group schema (RFC 7643 §4.2)",
        "attributes": [
            attr("displayName", "string", "none"),
            attr("externalId", "string", "none"),
            multi_complex_attr("members", &["value", "display"]),
        ],
        "meta": {
            "resourceType": "Schema",
            "location": format!("/Schemas/{}", super::types::CORE_GROUP_SCHEMA),
        }
    });
    scim_json_response(StatusCode::OK, serde_json::json!([user, group]))
}

/// `GET /api/scim/v2/organizations/{org_id}/ResourceTypes`
pub fn resource_types() -> Response {
    let user = serde_json::json!({
        "schemas": [super::types::RESOURCE_TYPE_SCHEMA],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "User Account",
        "schema": super::types::CORE_USER_SCHEMA,
        "meta": {
            "resourceType": "ResourceType",
            "location": "/ResourceTypes/User",
        }
    });
    let group = serde_json::json!({
        "schemas": [super::types::RESOURCE_TYPE_SCHEMA],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "description": "Group resource",
        "schema": super::types::CORE_GROUP_SCHEMA,
        "meta": {
            "resourceType": "ResourceType",
            "location": "/ResourceTypes/Group",
        }
    });
    scim_json_response(StatusCode::OK, serde_json::json!([user, group]))
}

fn attr(name: &str, t: &str, mutability: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "type": t,
        "multiValued": false,
        "required": false,
        "caseExact": false,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": if name == "userName" { "server" } else { "none" },
    })
}

fn complex_attr(name: &str, sub: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "type": "complex",
        "multiValued": false,
        "required": false,
        "mutability": "readWrite",
        "returned": "default",
        "subAttributes": sub.iter().map(|s| serde_json::json!({"name": s, "type": "string"})).collect::<Vec<_>>(),
    })
}

fn multi_complex_attr(name: &str, sub: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "type": "complex",
        "multiValued": true,
        "required": false,
        "mutability": "readWrite",
        "returned": "default",
        "subAttributes": sub.iter().map(|s| serde_json::json!({"name": s, "type": "string"})).collect::<Vec<_>>(),
    })
}
