//! OpenAPI specification builder for the yauth API.
//!
//! Builds a complete OpenAPI 3.1 spec from type schemas (via `utoipa::ToSchema`)
//! and route metadata. This replaces the previous `axfetchum`-based client
//! generation — the spec is written to `openapi.json` and then consumed by
//! `orval` to produce the TypeScript client.

use utoipa::openapi::path::{
    HttpMethod, OperationBuilder, ParameterBuilder, ParameterIn, PathItemBuilder,
};
use utoipa::openapi::request_body::RequestBodyBuilder;
use utoipa::openapi::response::ResponseBuilder;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{
    ComponentsBuilder, ContentBuilder, InfoBuilder, OpenApiBuilder, PathsBuilder, RefOr,
};

/// Helper to create a JSON content reference to a schema component.
fn json_ref(schema_name: &str) -> utoipa::openapi::Content {
    ContentBuilder::new()
        .schema(Some(RefOr::Ref(utoipa::openapi::Ref::new(format!(
            "#/components/schemas/{schema_name}"
        )))))
        .build()
}

/// Helper to create an operation with common settings.
fn op(operation_id: &str, tag: &str) -> OperationBuilder {
    OperationBuilder::new()
        .operation_id(Some(operation_id))
        .tag(tag)
}

/// Adds a path parameter (e.g., `{id}`, `{provider}`) to an operation.
fn with_path_param(builder: OperationBuilder, name: &str) -> OperationBuilder {
    builder.parameter(
        ParameterBuilder::new()
            .name(name)
            .parameter_in(ParameterIn::Path)
            .required(utoipa::openapi::Required::True)
            .schema(Some(RefOr::T(
                utoipa::openapi::ObjectBuilder::new()
                    .schema_type(utoipa::openapi::schema::Type::String)
                    .build()
                    .into(),
            )))
            .build(),
    )
}

/// Adds a JSON request body referencing a schema component.
fn with_body(builder: OperationBuilder, schema_name: &str) -> OperationBuilder {
    builder.request_body(Some(
        RequestBodyBuilder::new()
            .content("application/json", json_ref(schema_name))
            .required(Some(utoipa::openapi::Required::True))
            .build(),
    ))
}

/// Adds a 200 response referencing a schema component.
fn with_response(builder: OperationBuilder, schema_name: &str) -> OperationBuilder {
    builder.response(
        "200",
        ResponseBuilder::new()
            .description("Success")
            .content("application/json", json_ref(schema_name))
            .build(),
    )
}

/// Adds a 200 response whose body is an array of items referencing a schema.
#[cfg_attr(not(feature = "organizations"), allow(dead_code))]
fn with_array_response(builder: OperationBuilder, schema_name: &str) -> OperationBuilder {
    let item_ref = utoipa::openapi::Ref::new(format!("#/components/schemas/{schema_name}"));
    let array = utoipa::openapi::schema::ArrayBuilder::new()
        .items(RefOr::Ref(item_ref))
        .build();
    let content = ContentBuilder::new()
        .schema(Some(RefOr::T(array.into())))
        .build();
    builder.response(
        "200",
        ResponseBuilder::new()
            .description("Success")
            .content("application/json", content)
            .build(),
    )
}

/// Adds a 200 response with no body.
fn with_empty_response(builder: OperationBuilder) -> OperationBuilder {
    builder.response("200", ResponseBuilder::new().description("Success").build())
}

/// Adds query parameters from a schema component (each field becomes a query param).
fn with_query_params(builder: OperationBuilder, params: &[(&str, bool)]) -> OperationBuilder {
    let mut b = builder;
    for &(name, required) in params {
        b = b.parameter(
            ParameterBuilder::new()
                .name(name)
                .parameter_in(ParameterIn::Query)
                .required(if required {
                    utoipa::openapi::Required::True
                } else {
                    utoipa::openapi::Required::False
                })
                .schema(Some(RefOr::T(
                    utoipa::openapi::ObjectBuilder::new()
                        .schema_type(utoipa::openapi::schema::Type::String)
                        .build()
                        .into(),
                )))
                .build(),
        );
    }
    b
}

/// Register all schema components from `ToSchema` derives.
fn register_schemas(builder: ComponentsBuilder) -> ComponentsBuilder {
    use crate::middleware::{AuthMethod, AuthUser};
    use crate::plugins::{
        AuthConfigResponse, PatchMeResponse, SessionResponse, UpdateProfileRequest,
    };

    let mut b = builder
        .schema_from::<AuthUser>()
        .schema_from::<AuthMethod>()
        .schema_from::<AuthConfigResponse>()
        .schema_from::<UpdateProfileRequest>()
        .schema_from::<SessionResponse>()
        .schema_from::<PatchMeResponse>();

    #[cfg(feature = "email-password")]
    {
        use crate::plugins::email_password::*;
        b = b
            .schema_from::<RegisterRequest>()
            .schema_from::<LoginRequest>()
            .schema_from::<MessageResponse>()
            .schema_from::<RegisterResponse>()
            .schema_from::<VerifyEmailRequest>()
            .schema_from::<ResendVerificationRequest>()
            .schema_from::<ForgotPasswordRequest>()
            .schema_from::<ResetPasswordRequest>()
            .schema_from::<ChangePasswordRequest>();
    }

    #[cfg(feature = "passkey")]
    {
        use crate::plugins::passkey::*;
        b = b
            .schema_from::<PasskeyLoginBeginRequest>()
            .schema_from::<PasskeyLoginFinishRequest>()
            .schema_from::<RegisterFinishRequest>()
            .schema_from::<PasskeyInfo>()
            .schema_from::<ListPasskeysQuery>()
            .schema_from::<ListPasskeysResponse>();
    }

    #[cfg(feature = "mfa")]
    {
        use crate::plugins::mfa::*;
        b = b
            .schema_from::<ConfirmTotpRequest>()
            .schema_from::<VerifyMfaRequest>()
            .schema_from::<SetupTotpResponse>()
            .schema_from::<MfaMessageResponse>()
            .schema_from::<BackupCodeCountResponse>()
            .schema_from::<BackupCodesResponse>()
            .schema_from::<MfaAuthResponse>();
    }

    #[cfg(feature = "oauth")]
    {
        use crate::plugins::oauth::*;
        b = b
            .schema_from::<AuthorizeQuery>()
            .schema_from::<CallbackBody>()
            .schema_from::<OAuthAuthResponse>()
            .schema_from::<OAuthAccountResponse>()
            .schema_from::<AuthorizeResponse>()
            .schema_from::<ListOAuthAccountsQuery>()
            .schema_from::<ListOAuthAccountsResponse>();
    }

    #[cfg(feature = "bearer")]
    {
        use crate::plugins::bearer::*;
        b = b
            .schema_from::<TokenRequest>()
            .schema_from::<RefreshRequest>()
            .schema_from::<RevokeRequest>()
            .schema_from::<TokenResponse>();
    }

    #[cfg(feature = "api-key")]
    {
        use crate::plugins::api_key::*;
        b = b
            .schema_from::<CreateApiKeyRequest>()
            .schema_from::<CreateApiKeyResponse>()
            .schema_from::<ApiKeyResponse>()
            .schema_from::<ListApiKeysQuery>()
            .schema_from::<ListApiKeysResponse>();
    }

    #[cfg(feature = "magic-link")]
    {
        use crate::plugins::magic_link::*;
        b = b
            .schema_from::<MagicLinkSendRequest>()
            .schema_from::<MagicLinkVerifyRequest>()
            .schema_from::<MagicLinkMessageResponse>();
    }

    #[cfg(feature = "admin")]
    {
        use crate::plugins::admin::*;
        b = b
            .schema_from::<ListUsersQuery>()
            .schema_from::<ListSessionsQuery>()
            .schema_from::<UpdateUserRequest>()
            .schema_from::<BanRequest>()
            .schema_from::<DeleteUserSessionsResponse>()
            .schema_from::<ListAuditQuery>()
            .schema_from::<ListAuditResponse>()
            .schema_from::<AdminAuditEntry>()
            .schema_from::<PaginatedUsersResponse>()
            .schema_from::<AdminUserInfo>()
            .schema_from::<PaginatedSessionsResponse>()
            .schema_from::<AdminSessionInfo>();
    }

    #[cfg(feature = "webhooks")]
    {
        use crate::plugins::webhooks::*;
        b = b
            .schema_from::<CreateWebhookRequest>()
            .schema_from::<UpdateWebhookRequest>()
            .schema_from::<WebhookResponse>()
            .schema_from::<WebhookDetailResponse>()
            .schema_from::<WebhookDeliveryResponse>()
            .schema_from::<WebhookTestResponse>()
            .schema_from::<ListWebhooksQuery>()
            .schema_from::<ListWebhooksResponse>()
            .schema_from::<ListWebhookDeliveriesQuery>()
            .schema_from::<ListWebhookDeliveriesResponse>();
    }

    #[cfg(feature = "account-lockout")]
    {
        use crate::plugins::account_lockout::*;
        b = b
            .schema_from::<RequestUnlockRequest>()
            .schema_from::<UnlockAccountRequest>()
            .schema_from::<AccountLockoutMessageResponse>()
            .schema_from::<LockoutLockedAccount>()
            .schema_from::<LockoutStateResponse>();
    }

    #[cfg(feature = "oauth2-server")]
    {
        use crate::plugins::oauth2_server::*;
        b = b
            .schema_from::<ClientRegistrationRequest>()
            .schema_from::<ClientRegistrationResponse>()
            .schema_from::<Oauth2ConsentRequest>()
            .schema_from::<Oauth2AuthorizeRedirect>();
    }

    #[cfg(all(feature = "admin", feature = "oauth2-server"))]
    {
        use crate::plugins::oauth2_admin::*;
        b = b
            .schema_from::<Oauth2ClientView>()
            .schema_from::<Oauth2BannedClientsResponse>()
            .schema_from::<Oauth2CreateClientRequest>()
            .schema_from::<Oauth2CreateClientResponse>()
            .schema_from::<Oauth2PatchClientRequest>();
    }

    #[cfg(feature = "status")]
    {
        use crate::plugins::status::*;
        b = b.schema_from::<StatusResponse>();
    }

    #[cfg(feature = "organizations")]
    {
        use crate::plugins::organizations::*;
        b = b
            .schema_from::<CreateOrgRequest>()
            .schema_from::<UpdateOrgRequest>()
            .schema_from::<OrganizationResponse>()
            .schema_from::<MembershipResponse>()
            .schema_from::<CreateInvitationRequest>()
            .schema_from::<CreateInvitationResponse>()
            .schema_from::<InvitationResponse>()
            .schema_from::<AcceptInvitationRequest>()
            // RBAC (#88)
            .schema_from::<ChangeRoleRequest>()
            .schema_from::<TransferOwnershipRequest>()
            .schema_from::<PermissionsResponse>();
    }

    b
}

/// Core routes (always available).
fn core_paths(builder: PathsBuilder) -> PathsBuilder {
    builder
        .path(
            "/config",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("getConfig", "admin")
                        .pipe(|b| with_response(b, "AuthConfigResponse"))
                        .build(),
                )
                .build(),
        )
        .path(
            "/session",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("getSession", "email-password")
                        .pipe(|b| with_response(b, "SessionResponse"))
                        .security(utoipa::openapi::security::SecurityRequirement::new::<
                            &str,
                            [&str; 0],
                            &str,
                        >("sessionCookie", []))
                        .build(),
                )
                .build(),
        )
        .path(
            "/logout",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("logout", "email-password")
                        .pipe(with_empty_response)
                        .security(utoipa::openapi::security::SecurityRequirement::new::<
                            &str,
                            [&str; 0],
                            &str,
                        >("sessionCookie", []))
                        .build(),
                )
                .build(),
        )
        .path(
            "/me",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Patch,
                    op("updateProfile", "email-password")
                        .pipe(|b| with_body(b, "UpdateProfileRequest"))
                        .pipe(|b| with_response(b, "PatchMeResponse"))
                        .security(utoipa::openapi::security::SecurityRequirement::new::<
                            &str,
                            [&str; 0],
                            &str,
                        >("sessionCookie", []))
                        .build(),
                )
                .build(),
        )
}

/// Email/password plugin paths.
#[cfg(feature = "email-password")]
fn email_password_paths(builder: PathsBuilder) -> PathsBuilder {
    builder
        .path(
            "/register",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_register", "email-password"),
                            "RegisterResponse",
                        ),
                        "RegisterRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/login",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("emailPassword_login", "email-password")),
                        "LoginRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/verify-email",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_verifyEmail", "email-password"),
                            "MessageResponse",
                        ),
                        "VerifyEmailRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/resend-verification",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_resendVerification", "email-password"),
                            "MessageResponse",
                        ),
                        "ResendVerificationRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/forgot-password",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_forgotPassword", "email-password"),
                            "MessageResponse",
                        ),
                        "ForgotPasswordRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/reset-password",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_resetPassword", "email-password"),
                            "MessageResponse",
                        ),
                        "ResetPasswordRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/change-password",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("emailPassword_changePassword", "email-password"),
                            "MessageResponse",
                        ),
                        "ChangePasswordRequest",
                    )
                    .security(utoipa::openapi::security::SecurityRequirement::new::<
                        &str,
                        [&str; 0],
                        &str,
                    >("sessionCookie", []))
                    .build(),
                )
                .build(),
        )
}

/// Passkey plugin paths.
#[cfg(feature = "passkey")]
fn passkey_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/passkey/login/begin",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("passkey_loginBegin", "passkey")),
                        "PasskeyLoginBeginRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/passkey/login/finish",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("passkey_loginFinish", "passkey")),
                        "PasskeyLoginFinishRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/passkeys/register/begin",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("passkey_registerBegin", "passkey")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/passkeys/register/finish",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("passkey_registerFinish", "passkey")),
                        "RegisterFinishRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/passkeys",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_query_params(
                        op("passkey_list", "passkey"),
                        &[("page", false), ("per_page", false)],
                    )
                    .pipe(|b| with_response(b, "ListPasskeysResponse"))
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/passkeys/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("passkey_delete", "passkey"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// MFA plugin paths.
#[cfg(feature = "mfa")]
fn mfa_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/mfa/totp/setup",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("mfa_setup", "mfa")
                        .pipe(|b| with_response(b, "SetupTotpResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/mfa/totp/confirm",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("mfa_confirm", "mfa"), "MfaMessageResponse"),
                        "ConfirmTotpRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/mfa/totp",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    op("mfa_disable", "mfa")
                        .pipe(|b| with_response(b, "MfaMessageResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/mfa/verify",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("mfa_verify", "mfa"), "MfaAuthResponse"),
                        "VerifyMfaRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/mfa/backup-codes",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("mfa_getBackupCodeCount", "mfa")
                        .pipe(|b| with_response(b, "BackupCodeCountResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/mfa/backup-codes/regenerate",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("mfa_regenerateBackupCodes", "mfa")
                        .pipe(|b| with_response(b, "BackupCodesResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// OAuth plugin paths.
#[cfg(feature = "oauth")]
fn oauth_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/oauth/{provider}/authorize",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("oauth_authorize", "oauth"), "provider")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/{provider}/callback",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("oauth_callbackGet", "oauth"), "provider")
                        .pipe(|b| with_query_params(b, &[("code", false), ("state", false)]))
                        .pipe(|b| with_response(b, "OAuthAuthResponse"))
                        .build(),
                )
                .operation(
                    HttpMethod::Post,
                    with_path_param(
                        with_body(
                            with_response(op("oauth_callback", "oauth"), "OAuthAuthResponse"),
                            "CallbackBody",
                        ),
                        "provider",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/oauth/accounts",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_query_params(
                        op("oauth_accounts", "oauth"),
                        &[("page", false), ("per_page", false)],
                    )
                    .pipe(|b| with_response(b, "ListOAuthAccountsResponse"))
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/oauth/{provider}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("oauth_unlink", "oauth"), "provider")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/{provider}/link",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("oauth_link", "oauth"), "provider")
                        .pipe(|b| with_response(b, "AuthorizeResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Bearer token plugin paths.
#[cfg(feature = "bearer")]
fn bearer_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/token",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("bearer_getToken", "bearer"), "TokenResponse"),
                        "TokenRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/token/refresh",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("bearer_refresh", "bearer"), "TokenResponse"),
                        "RefreshRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/token/revoke",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("bearer_revoke", "bearer")),
                        "RevokeRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
}

/// API key plugin paths.
#[cfg(feature = "api-key")]
fn api_key_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/api-keys",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("apiKeys_create", "api-key"), "CreateApiKeyResponse"),
                        "CreateApiKeyRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Get,
                    with_query_params(
                        op("apiKeys_list", "api-key"),
                        &[("page", false), ("per_page", false)],
                    )
                    .pipe(|b| with_response(b, "ListApiKeysResponse"))
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/api-keys/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("apiKeys_delete", "api-key"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Magic link plugin paths.
#[cfg(feature = "magic-link")]
fn magic_link_paths(builder: PathsBuilder) -> PathsBuilder {
    builder
        .path(
            "/magic-link/send",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("magicLink_send", "magic-link"),
                            "MagicLinkMessageResponse",
                        ),
                        "MagicLinkSendRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/magic-link/verify",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_empty_response(op("magicLink_verify", "magic-link")),
                        "MagicLinkVerifyRequest",
                    )
                    .build(),
                )
                .build(),
        )
}

/// Admin plugin paths.
#[cfg(feature = "admin")]
fn admin_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/admin/users",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_query_params(
                        op("admin_listUsers", "admin"),
                        &[("page", false), ("per_page", false), ("search", false)],
                    )
                    .pipe(|b| with_response(b, "PaginatedUsersResponse"))
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("admin_getUser", "admin"), "id")
                        .pipe(|b| with_response(b, "AdminUserInfo"))
                        .security(auth_req())
                        .build(),
                )
                .operation(
                    HttpMethod::Put,
                    with_path_param(
                        with_body(
                            with_response(op("admin_updateUser", "admin"), "AdminUserInfo"),
                            "UpdateUserRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Patch,
                    with_path_param(
                        with_body(
                            with_response(op("admin_patchUser", "admin"), "AdminUserInfo"),
                            "UpdateUserRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("admin_deleteUser", "admin"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/ban",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(
                        with_body(
                            with_response(op("admin_banUser", "admin"), "AdminUserInfo"),
                            "BanRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/unban",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("admin_unbanUser", "admin"), "id")
                        .pipe(|b| with_response(b, "AdminUserInfo"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/impersonate",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("admin_impersonate", "admin"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/sessions",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("admin_deleteUserSessions", "admin"), "id")
                        .pipe(|b| with_response(b, "DeleteUserSessionsResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/admin/audit",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_query_params(
                        op("admin_listAudit", "admin"),
                        &[
                            ("limit", false),
                            ("offset", false),
                            ("user_id", false),
                            ("type", false),
                        ],
                    )
                    .pipe(|b| with_response(b, "ListAuditResponse"))
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/admin/sessions",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_query_params(
                        op("admin_listSessions", "admin"),
                        &[("page", false), ("per_page", false)],
                    )
                    .pipe(|b| with_response(b, "PaginatedSessionsResponse"))
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/admin/sessions/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("admin_deleteSession", "admin"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// OAuth2 server plugin paths.
#[cfg(feature = "oauth2-server")]
fn oauth2_server_paths(builder: PathsBuilder) -> PathsBuilder {
    builder
        .path(
            "/.well-known/oauth-authorization-server",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oauth2Server_metadata", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/authorize",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oauth2Server_authorize", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_authorizeConsent", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/token",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_token", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/introspect",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_introspect", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/revoke",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_revoke", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/register",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("oauth2Server_register", "oauth2-server"),
                            "ClientRegistrationResponse",
                        ),
                        "ClientRegistrationRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/oauth2/consent",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("oauth2Server_consent", "oauth2-server"),
                            "Oauth2AuthorizeRedirect",
                        ),
                        "Oauth2ConsentRequest",
                    )
                    .security(utoipa::openapi::security::SecurityRequirement::new::<
                        &str,
                        [&str; 0],
                        &str,
                    >("sessionCookie", []))
                    .build(),
                )
                .build(),
        )
        .path(
            "/oauth/device/code",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_deviceAuthorize", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/oauth/device",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oauth2Server_deviceVerify", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .operation(
                    HttpMethod::Post,
                    op("oauth2Server_deviceApprove", "oauth2-server")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
}

/// Webhooks plugin paths.
#[cfg(feature = "webhooks")]
fn webhook_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/webhooks",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(op("webhooks_create", "webhooks"), "WebhookResponse"),
                        "CreateWebhookRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Get,
                    with_query_params(
                        op("webhooks_list", "webhooks"),
                        &[("page", false), ("per_page", false)],
                    )
                    .pipe(|b| with_response(b, "ListWebhooksResponse"))
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/webhooks/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("webhooks_get", "webhooks"), "id")
                        .pipe(|b| with_response(b, "WebhookDetailResponse"))
                        .security(auth_req())
                        .build(),
                )
                .operation(
                    HttpMethod::Put,
                    with_path_param(
                        with_body(
                            with_response(op("webhooks_update", "webhooks"), "WebhookResponse"),
                            "UpdateWebhookRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Patch,
                    with_path_param(
                        with_body(
                            with_response(op("webhooks_patch", "webhooks"), "WebhookResponse"),
                            "UpdateWebhookRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("webhooks_delete", "webhooks"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/webhooks/{id}/test",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("webhooks_test", "webhooks"), "id")
                        .pipe(|b| with_response(b, "WebhookTestResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/webhooks/{id}/deliveries",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("webhooks_listDeliveries", "webhooks"), "id")
                        .pipe(|b| with_query_params(b, &[("page", false), ("per_page", false)]))
                        .pipe(|b| with_response(b, "ListWebhookDeliveriesResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Account lockout plugin paths.
#[cfg(feature = "account-lockout")]
fn account_lockout_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/account/request-unlock",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("accountLockout_requestUnlock", "lockout"),
                            "AccountLockoutMessageResponse",
                        ),
                        "RequestUnlockRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/account/unlock",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("accountLockout_unlock", "lockout"),
                            "AccountLockoutMessageResponse",
                        ),
                        "UnlockAccountRequest",
                    )
                    .build(),
                )
                .build(),
        )
        .path(
            "/admin/users/{id}/unlock",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(op("accountLockout_adminUnlock", "lockout"), "id")
                        .pipe(|b| with_response(b, "AccountLockoutMessageResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/lockout/state",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("accountLockout_state", "lockout")
                        .pipe(|b| with_response(b, "LockoutStateResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// OIDC plugin paths.
#[cfg(feature = "oidc")]
fn oidc_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/.well-known/openid-configuration",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oidc_openidConfiguration", "oidc")
                        .pipe(with_empty_response)
                        .build(),
                )
                .build(),
        )
        .path(
            "/.well-known/jwks.json",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oidc_jwks", "oidc").pipe(with_empty_response).build(),
                )
                .build(),
        )
        .path(
            "/userinfo",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oidc_userinfo", "oidc")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// OAuth2 admin paths (yauth-go convergence — `/oauth2/clients{,/{id}}`).
#[cfg(all(feature = "admin", feature = "oauth2-server"))]
fn oauth2_admin_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/oauth2/clients",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("oauth2Admin_listClients", "oauth2-server")
                        .pipe(|b| with_response(b, "Oauth2BannedClientsResponse"))
                        .security(auth_req())
                        .build(),
                )
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("oauth2Admin_createClient", "oauth2-server"),
                            "Oauth2CreateClientResponse",
                        ),
                        "Oauth2CreateClientRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/oauth2/clients/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("oauth2Admin_getClient", "oauth2-server"), "id")
                        .pipe(|b| with_response(b, "Oauth2ClientView"))
                        .security(auth_req())
                        .build(),
                )
                .operation(
                    HttpMethod::Patch,
                    with_path_param(
                        with_body(
                            with_response(
                                op("oauth2Admin_patchClient", "oauth2-server"),
                                "Oauth2ClientView",
                            ),
                            "Oauth2PatchClientRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("oauth2Admin_deleteClient", "oauth2-server"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Status plugin paths.
#[cfg(feature = "status")]
fn status_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder.path(
        "/status",
        PathItemBuilder::new()
            .operation(
                HttpMethod::Get,
                op("status_get", "status")
                    .pipe(|b| with_response(b, "StatusResponse"))
                    .security(auth_req())
                    .build(),
            )
            .build(),
    )
}

/// Organizations plugin paths.
#[cfg(feature = "organizations")]
fn organizations_paths(builder: PathsBuilder) -> PathsBuilder {
    let auth_req = || {
        utoipa::openapi::security::SecurityRequirement::new::<&str, [&str; 0], &str>(
            "sessionCookie",
            [],
        )
    };

    builder
        .path(
            "/organizations",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    op("organizations_list", "organizations")
                        .pipe(|b| with_array_response(b, "OrganizationResponse"))
                        .security(auth_req())
                        .build(),
                )
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("organizations_create", "organizations"),
                            "OrganizationResponse",
                        ),
                        "CreateOrgRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/organizations/{id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("organizations_get", "organizations"), "id")
                        .pipe(|b| with_response(b, "OrganizationResponse"))
                        .security(auth_req())
                        .build(),
                )
                .operation(
                    HttpMethod::Patch,
                    with_path_param(
                        with_body(
                            with_response(
                                op("organizations_update", "organizations"),
                                "OrganizationResponse",
                            ),
                            "UpdateOrgRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .operation(
                    HttpMethod::Delete,
                    with_path_param(op("organizations_delete", "organizations"), "id")
                        .pipe(with_empty_response)
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/organizations/{id}/members",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("organizations_listMembers", "organizations"), "id")
                        .pipe(|b| with_array_response(b, "MembershipResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
        .path(
            "/organizations/{id}/invitations",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(
                        with_body(
                            with_response(
                                op("organizations_createInvitation", "organizations"),
                                "CreateInvitationResponse",
                            ),
                            "CreateInvitationRequest",
                        ),
                        "id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/invitations/accept",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_body(
                        with_response(
                            op("organizations_acceptInvitation", "organizations"),
                            "MembershipResponse",
                        ),
                        "AcceptInvitationRequest",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        // ── RBAC (#88) ────────────────────────────────────────────────
        .path(
            "/organizations/{id}/members/{user_id}/role",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(
                        with_path_param(
                            with_body(
                                with_response(
                                    op("organizations_changeRole", "organizations"),
                                    "MembershipResponse",
                                ),
                                "ChangeRoleRequest",
                            ),
                            "id",
                        ),
                        "user_id",
                    )
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/organizations/{id}/members/{user_id}",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Delete,
                    with_path_param(
                        with_path_param(op("organizations_removeMember", "organizations"), "id"),
                        "user_id",
                    )
                    .pipe(with_empty_response)
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/organizations/{id}/transfer-ownership",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Post,
                    with_path_param(
                        with_body(
                            op("organizations_transferOwnership", "organizations"),
                            "TransferOwnershipRequest",
                        ),
                        "id",
                    )
                    .pipe(with_empty_response)
                    .security(auth_req())
                    .build(),
                )
                .build(),
        )
        .path(
            "/organizations/{id}/permissions",
            PathItemBuilder::new()
                .operation(
                    HttpMethod::Get,
                    with_path_param(op("organizations_listPermissions", "organizations"), "id")
                        .pipe(|b| with_response(b, "PermissionsResponse"))
                        .security(auth_req())
                        .build(),
                )
                .build(),
        )
}

/// Build the complete OpenAPI specification for yauth.
#[allow(unused_mut)]
pub fn build_openapi_spec() -> utoipa::openapi::OpenApi {
    let info = InfoBuilder::new()
        .title("yauth")
        .version(env!("CARGO_PKG_VERSION"))
        .description(Some(
            "Modular, plugin-based authentication API for Axum applications.",
        ))
        .build();

    let components = register_schemas(ComponentsBuilder::new())
        .security_scheme(
            "sessionCookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("yauth_session"))),
        )
        .security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        )
        .security_scheme(
            "apiKey",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Api-Key"))),
        )
        .build();

    let mut paths = core_paths(PathsBuilder::new());

    #[cfg(feature = "email-password")]
    {
        paths = email_password_paths(paths);
    }

    #[cfg(feature = "passkey")]
    {
        paths = passkey_paths(paths);
    }

    #[cfg(feature = "mfa")]
    {
        paths = mfa_paths(paths);
    }

    #[cfg(feature = "oauth")]
    {
        paths = oauth_paths(paths);
    }

    #[cfg(feature = "bearer")]
    {
        paths = bearer_paths(paths);
    }

    #[cfg(feature = "api-key")]
    {
        paths = api_key_paths(paths);
    }

    #[cfg(feature = "magic-link")]
    {
        paths = magic_link_paths(paths);
    }

    #[cfg(feature = "admin")]
    {
        paths = admin_paths(paths);
    }

    #[cfg(feature = "oauth2-server")]
    {
        paths = oauth2_server_paths(paths);
    }

    #[cfg(all(feature = "admin", feature = "oauth2-server"))]
    {
        paths = oauth2_admin_paths(paths);
    }

    #[cfg(feature = "webhooks")]
    {
        paths = webhook_paths(paths);
    }

    #[cfg(feature = "account-lockout")]
    {
        paths = account_lockout_paths(paths);
    }

    #[cfg(feature = "oidc")]
    {
        paths = oidc_paths(paths);
    }

    #[cfg(feature = "status")]
    {
        paths = status_paths(paths);
    }

    #[cfg(feature = "organizations")]
    {
        paths = organizations_paths(paths);
    }

    OpenApiBuilder::new()
        .info(info)
        .paths(paths.build())
        .components(Some(components))
        .build()
}

/// Helper trait for fluent builder chaining.
trait Pipe: Sized {
    fn pipe(self, f: impl FnOnce(Self) -> Self) -> Self {
        f(self)
    }
}
impl Pipe for OperationBuilder {}
