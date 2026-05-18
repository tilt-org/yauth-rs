//! SCIM error response helpers.
//!
//! SCIM error responses MUST use the RFC 7644 §3.12 JSON shape — not
//! yauth's normal `{ "error": "..." }` envelope. IdPs (Okta, Entra,
//! OneLogin) parse the SCIM shape; any other shape gets surfaced as a
//! generic IdP-side failure that admins can't easily debug.
//!
//! This wrapper lets handlers return `Result<T, ScimResponseError>`
//! while preserving:
//!
//! - The correct HTTP status code
//! - The RFC 7644 schemas[] URN
//! - `scimType` when one applies (e.g. `noTarget`, `invalidFilter`)
//! - `Content-Type: application/scim+json` (RFC 7644 §3.8)

#![forbid(unsafe_code)]

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::types::ScimError;

/// Content type IdPs expect on a SCIM response. RFC 7644 §3.8.
pub const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// Error envelope returned from a SCIM handler. Implements
/// `IntoResponse` so handlers can use `?` with [`crate::repo::RepoError`]
/// after conversion.
#[derive(Debug)]
pub struct ScimResponseError {
    pub status: StatusCode,
    pub body: ScimError,
}

impl ScimResponseError {
    pub fn new(status: StatusCode, body: ScimError) -> Self {
        Self { status, body }
    }

    /// Shortcut for `400 Bad Request` with `invalidSyntax`.
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: ScimError::new(400, Some("invalidSyntax"), detail),
        }
    }

    /// Shortcut for `404 Not Found` with `noTarget`.
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: ScimError::new(404, Some("noTarget"), detail),
        }
    }

    /// Shortcut for `409 Conflict` with `uniqueness`.
    pub fn conflict(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            body: ScimError::new(409, Some("uniqueness"), detail),
        }
    }

    /// Internal error — payload kept short, no internal traces.
    pub fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: ScimError::new(500, None, "internal error"),
        }
    }

    /// `501 Not Implemented` — used when an SQL backend is stubbed.
    pub fn not_implemented(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            body: ScimError::new(501, None, detail),
        }
    }
}

impl IntoResponse for ScimResponseError {
    fn into_response(self) -> Response {
        // Build the response by hand so we can set the SCIM content
        // type on the response (not just on the request body).
        let json =
            serde_json::to_vec(&self.body).unwrap_or_else(|_| b"{\"status\":\"500\"}".to_vec());
        let mut resp = Response::builder()
            .status(self.status)
            .body(axum::body::Body::from(json))
            .unwrap_or_else(|_| Response::new(axum::body::Body::empty()));
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(SCIM_CONTENT_TYPE),
        );
        resp
    }
}

/// Convert a `RepoError` into a SCIM error response. Used by `?` in
/// handlers so storage failures get the proper SCIM shape.
impl From<crate::repo::RepoError> for ScimResponseError {
    fn from(e: crate::repo::RepoError) -> Self {
        match e {
            crate::repo::RepoError::Conflict(msg) => Self::conflict(msg),
            crate::repo::RepoError::NotFound => Self::not_found("resource not found"),
            crate::repo::RepoError::NotImplemented(detail) => Self::not_implemented(detail),
            crate::repo::RepoError::Internal(err) => {
                crate::otel::record_error("scim_repo_error", &err);
                Self::internal()
            }
        }
    }
}

/// Build an OK response with the SCIM content type.
pub fn scim_json_response<T: serde::Serialize>(status: StatusCode, body: T) -> Response {
    let json = match serde_json::to_vec(&body) {
        Ok(v) => v,
        Err(e) => {
            crate::otel::record_error("scim_response_serialize_failed", &e);
            return ScimResponseError::internal().into_response();
        }
    };
    let mut resp = Response::builder()
        .status(status)
        .body(axum::body::Body::from(json))
        .unwrap_or_else(|_| Response::new(axum::body::Body::empty()));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(SCIM_CONTENT_TYPE),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_string(resp: Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn error_response_sets_scim_content_type() {
        let e = ScimResponseError::bad_request("nope");
        let resp = e.into_response();
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            SCIM_CONTENT_TYPE
        );
    }

    #[tokio::test]
    async fn error_response_uses_messages_error_urn() {
        let e = ScimResponseError::not_found("user not found");
        let resp = e.into_response();
        let body = body_string(resp).await;
        assert!(body.contains("urn:ietf:params:scim:api:messages:2.0:Error"));
        assert!(body.contains("\"status\":\"404\""));
        assert!(body.contains("\"scimType\":\"noTarget\""));
    }

    #[tokio::test]
    async fn ok_response_sets_scim_content_type() {
        let resp = scim_json_response(StatusCode::OK, serde_json::json!({"hello": "world"}));
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            SCIM_CONTENT_TYPE
        );
        let body = body_string(resp).await;
        assert!(body.contains("hello"));
    }
}
