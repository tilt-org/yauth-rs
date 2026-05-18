// Re-export all generated types and functions for direct use.
// Note: AuthUser and AuthMethod come from generated.ts (matching the actual API wire format).
// For the simplified shared types, import directly from @yackey-labs/yauth-shared.
export * from "./generated";
export { configureClient, type YAuthClientOptions, YAuthError } from "./mutator";

import type {
  AcceptInvitationRequest,
  AdminListSessionsParams,
  AdminListUsersParams,
  BanRequest,
  CallbackBody,
  ChangePasswordRequest,
  ChangeRoleRequest,
  ClientRegistrationRequest,
  ConfirmTotpRequest,
  CreateApiKeyRequest,
  CreateDomainRequest,
  CreateSsoConnectionRequest,
  UpdateSsoConnectionRequest,
  CreateInvitationRequest,
  CreateOrgRequest,
  CreateWebhookRequest,
  ForgotPasswordRequest,
  LoginRequest,
  MagicLinkSendRequest,
  MagicLinkVerifyRequest,
  PasskeyLoginBeginRequest,
  PasskeyLoginFinishRequest,
  RefreshRequest,
  RegisterFinishRequest,
  RegisterRequest,
  RequestUnlockRequest,
  ResendVerificationRequest,
  ResetPasswordRequest,
  RevokeRequest,
  SetActiveOrgRequest,
  TokenRequest,
  UnlockAccountRequest,
  TransferOwnershipRequest,
  UpdateDomainRequest,
  UpdateOrgRequest,
  UpdateProfileRequest,
  UpdateUserRequest,
  UpdateWebhookRequest,
  VerifyEmailRequest,
  VerifyMfaRequest,
} from "./generated";
import {
  accountLockoutAdminUnlock,
  accountLockoutRequestUnlock,
  accountLockoutUnlock,
  adminBanUser,
  adminDeleteSession,
  adminDeleteUser,
  adminGetUser,
  adminImpersonate,
  adminListSessions,
  adminListUsers,
  adminUnbanUser,
  adminUpdateUser,
  apiKeysCreate,
  apiKeysDelete,
  apiKeysList,
  bearerGetToken,
  bearerRefresh,
  bearerRevoke,
  emailPasswordChangePassword,
  emailPasswordForgotPassword,
  emailPasswordLogin,
  emailPasswordRegister,
  emailPasswordResendVerification,
  emailPasswordResetPassword,
  emailPasswordVerifyEmail,
  getConfig,
  getOauthAuthorizeUrl,
  getSession,
  logout,
  magicLinkSend,
  magicLinkVerify,
  mfaConfirm,
  mfaDisable,
  mfaGetBackupCodeCount,
  mfaRegenerateBackupCodes,
  mfaSetup,
  mfaVerify,
  oauth2ServerAuthorize,
  oauth2ServerAuthorizeConsent,
  oauth2ServerDeviceApprove,
  oauth2ServerDeviceAuthorize,
  oauth2ServerDeviceVerify,
  oauth2ServerIntrospect,
  oauth2ServerMetadata,
  oauth2ServerRegister,
  oauth2ServerRevoke,
  oauth2ServerToken,
  oauthAccounts,
  oauthCallback,
  oauthLink,
  oauthUnlink,
  oidcJwks,
  oidcOpenidConfiguration,
  oidcUserinfo,
  organizationsAcceptInvitation,
  organizationsChangeRole,
  organizationsClearActiveOrg,
  organizationsCreate,
  organizationsCreateDomain,
  organizationsCreateInvitation,
  organizationsDelete,
  organizationsDeleteDomain,
  organizationsGet,
  organizationsGetActiveOrg,
  organizationsList,
  organizationsListDomains,
  organizationsListMembers,
  organizationsListPermissions,
  organizationsListSsoConnections,
  organizationsCreateSsoConnection,
  organizationsUpdateSsoConnection,
  organizationsDeleteSsoConnection,
  organizationsTestSsoConnection,
  organizationsRemoveMember,
  organizationsSetActiveOrg,
  organizationsTransferOwnership,
  organizationsUpdate,
  organizationsUpdateDomain,
  organizationsVerifyDomain,
  passkeyDelete,
  passkeyList,
  passkeyLoginBegin,
  passkeyLoginFinish,
  passkeyRegisterBegin,
  passkeyRegisterFinish,
  updateProfile,
  webhooksCreate,
  webhooksDelete,
  webhooksGet,
  webhooksList,
  webhooksTest,
  webhooksUpdate,
} from "./generated";
import { configureClient, type YAuthClientOptions } from "./mutator";

/**
 * Create and configure a yauth client with a backward-compatible API shape.
 *
 * @example
 * ```ts
 * const client = createYAuthClient({ baseUrl: "/api/auth" });
 * const session = await client.getSession();
 * ```
 */
export function createYAuthClient(options: YAuthClientOptions) {
  configureClient(options);

  return {
    getConfig: () => getConfig(),
    getSession: () => getSession(),
    logout: () => logout(),
    updateProfile: (body: UpdateProfileRequest) => updateProfile(body),

    emailPassword: {
      register: (body: RegisterRequest) => emailPasswordRegister(body),
      login: (body: LoginRequest) => emailPasswordLogin(body),
      verify: (body: VerifyEmailRequest) => emailPasswordVerifyEmail(body),
      resendVerification: (body: ResendVerificationRequest) =>
        emailPasswordResendVerification(body),
      forgotPassword: (body: ForgotPasswordRequest) => emailPasswordForgotPassword(body),
      resetPassword: (body: ResetPasswordRequest) => emailPasswordResetPassword(body),
      changePassword: (body: ChangePasswordRequest) => emailPasswordChangePassword(body),
    },

    passkey: {
      loginBegin: (body: PasskeyLoginBeginRequest) => passkeyLoginBegin(body),
      loginFinish: (body: PasskeyLoginFinishRequest) => passkeyLoginFinish(body),
      registerBegin: () => passkeyRegisterBegin(),
      registerFinish: (body: RegisterFinishRequest) => passkeyRegisterFinish(body),
      list: () => passkeyList(),
      delete: (id: string) => passkeyDelete(id),
    },

    mfa: {
      setup: () => mfaSetup(),
      confirm: (body: ConfirmTotpRequest) => mfaConfirm(body),
      disable: () => mfaDisable(),
      verify: (body: VerifyMfaRequest) => mfaVerify(body),
      getBackupCodeCount: () => mfaGetBackupCodeCount(),
      regenerateBackupCodes: () => mfaRegenerateBackupCodes(),
    },

    sso: {
      /** Build the user-facing `/sso/login` redirect URL (issue #93). */
      loginUrl: (opts: { org?: string; domain?: string; redirectTo?: string }) => {
        const params = new URLSearchParams();
        if (opts.org) params.set("org", opts.org);
        if (opts.domain) params.set("domain", opts.domain);
        if (opts.redirectTo) params.set("redirect_to", opts.redirectTo);
        return `${options.baseUrl}/sso/login?${params.toString()}`;
      },
      /** Build the user-facing `/sso/saml/login` redirect URL (issue #94). */
      samlLoginUrl: (opts: { org?: string; domain?: string; redirectTo?: string }) => {
        const params = new URLSearchParams();
        if (opts.org) params.set("org", opts.org);
        if (opts.domain) params.set("domain", opts.domain);
        if (opts.redirectTo) params.set("redirect_to", opts.redirectTo);
        return `${options.baseUrl}/sso/saml/login?${params.toString()}`;
      },
      /**
       * Build the SP metadata XML download URL for a SAML connection
       * (issue #94). Public endpoint — IdP admins import the XML to
       * wire yauth as a service provider on their side.
       */
      samlMetadataUrl: (connectionId: string) =>
        `${options.baseUrl}/sso/saml/metadata/${connectionId}`,
    },

    oauth: {
      authorize: (provider: string, query?: { redirect_url?: string | null }) => {
        let url = `${options.baseUrl}${getOauthAuthorizeUrl(provider)}`;
        if (query?.redirect_url) {
          url += `?redirect_url=${encodeURIComponent(query.redirect_url)}`;
        }
        return url;
      },
      callback: (provider: string, body: CallbackBody) => oauthCallback(provider, body),
      accounts: () => oauthAccounts(),
      unlink: (provider: string) => oauthUnlink(provider),
      link: (provider: string) => oauthLink(provider),
    },

    bearer: {
      getToken: (body: TokenRequest) => bearerGetToken(body),
      refresh: (body: RefreshRequest) => bearerRefresh(body),
      revoke: (body: RevokeRequest) => bearerRevoke(body),
    },

    apiKeys: {
      create: (body: CreateApiKeyRequest) => apiKeysCreate(body),
      list: () => apiKeysList(),
      delete: (id: string) => apiKeysDelete(id),
    },

    magicLink: {
      send: (body: MagicLinkSendRequest) => magicLinkSend(body),
      verify: (body: MagicLinkVerifyRequest) => magicLinkVerify(body),
    },

    admin: {
      listUsers: (params?: AdminListUsersParams) => adminListUsers(params),
      getUser: (id: string) => adminGetUser(id),
      updateUser: (id: string, body: UpdateUserRequest) => adminUpdateUser(id, body),
      deleteUser: (id: string) => adminDeleteUser(id),
      banUser: (id: string, body: BanRequest) => adminBanUser(id, body),
      unbanUser: (id: string) => adminUnbanUser(id),
      impersonate: (id: string) => adminImpersonate(id),
      listSessions: (params?: AdminListSessionsParams) => adminListSessions(params),
      deleteSession: (id: string) => adminDeleteSession(id),
    },

    oauth2Server: {
      metadata: () => oauth2ServerMetadata(),
      authorize: () => oauth2ServerAuthorize(),
      authorizeConsent: () => oauth2ServerAuthorizeConsent(),
      token: () => oauth2ServerToken(),
      introspect: () => oauth2ServerIntrospect(),
      revoke: () => oauth2ServerRevoke(),
      register: (body: ClientRegistrationRequest) => oauth2ServerRegister(body),
      deviceAuthorize: () => oauth2ServerDeviceAuthorize(),
      deviceVerify: () => oauth2ServerDeviceVerify(),
      deviceApprove: () => oauth2ServerDeviceApprove(),
    },

    webhooks: {
      create: (body: CreateWebhookRequest) => webhooksCreate(body),
      list: () => webhooksList(),
      get: (id: string) => webhooksGet(id),
      update: (id: string, body: UpdateWebhookRequest) => webhooksUpdate(id, body),
      delete: (id: string) => webhooksDelete(id),
      test: (id: string) => webhooksTest(id),
    },

    accountLockout: {
      requestUnlock: (body: RequestUnlockRequest) => accountLockoutRequestUnlock(body),
      unlock: (body: UnlockAccountRequest) => accountLockoutUnlock(body),
      adminUnlock: (id: string) => accountLockoutAdminUnlock(id),
    },

    oidc: {
      openidConfiguration: () => oidcOpenidConfiguration(),
      jwks: () => oidcJwks(),
      userinfo: () => oidcUserinfo(),
    },

    organizations: {
      list: () => organizationsList(),
      create: (body: CreateOrgRequest) => organizationsCreate(body),
      get: (id: string) => organizationsGet(id),
      update: (id: string, body: UpdateOrgRequest) => organizationsUpdate(id, body),
      delete: (id: string) => organizationsDelete(id),
      listMembers: (id: string) => organizationsListMembers(id),
      createInvitation: (id: string, body: CreateInvitationRequest) =>
        organizationsCreateInvitation(id, body),
      acceptInvitation: (body: AcceptInvitationRequest) => organizationsAcceptInvitation(body),
      // RBAC (#88)
      listPermissions: (id: string) => organizationsListPermissions(id),
      changeRole: (id: string, userId: string, body: ChangeRoleRequest) =>
        organizationsChangeRole(id, userId, body),
      removeMember: (id: string, userId: string) => organizationsRemoveMember(id, userId),
      transferOwnership: (id: string, body: TransferOwnershipRequest) =>
        organizationsTransferOwnership(id, body),
      // Active organization switcher (#89)
      getActiveOrg: () => organizationsGetActiveOrg(),
      setActiveOrg: (body: SetActiveOrgRequest) => organizationsSetActiveOrg(body),
      clearActiveOrg: () => organizationsClearActiveOrg(),
      // Verified email domains (#90)
      listDomains: (id: string) => organizationsListDomains(id),
      createDomain: (id: string, body: CreateDomainRequest) => organizationsCreateDomain(id, body),
      updateDomain: (id: string, did: string, body: UpdateDomainRequest) =>
        organizationsUpdateDomain(id, did, body),
      deleteDomain: (id: string, did: string) => organizationsDeleteDomain(id, did),
      verifyDomain: (id: string, did: string) => organizationsVerifyDomain(id, did),
      // SSO OIDC connections (#93)
      listSsoConnections: (id: string) => organizationsListSsoConnections(id),
      createSsoConnection: (id: string, body: CreateSsoConnectionRequest) =>
        organizationsCreateSsoConnection(id, body),
      updateSsoConnection: (id: string, cid: string, body: UpdateSsoConnectionRequest) =>
        organizationsUpdateSsoConnection(id, cid, body),
      deleteSsoConnection: (id: string, cid: string) =>
        organizationsDeleteSsoConnection(id, cid),
      testSsoConnection: (id: string, cid: string) =>
        organizationsTestSsoConnection(id, cid),
    },
  };
}

export type YAuthClient = ReturnType<typeof createYAuthClient>;
