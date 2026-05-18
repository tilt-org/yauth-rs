# TypeScript Packages

## @yackey-labs/yauth-client

HTTP client auto-generated from the OpenAPI spec via `utoipa` + `orval`.

```bash
bun add @yackey-labs/yauth-client
```

```typescript
import { createYAuthClient } from "@yackey-labs/yauth-client";

const auth = createYAuthClient({ baseUrl: "/api/auth" });

// Email/password
await auth.emailPassword.register({ email, password });
await auth.emailPassword.login({ email, password, remember_me: true });

// Session
const user = await auth.getSession();
await auth.logout();

// Webhooks, account lockout, OIDC, OAuth2 server, passkey, MFA, etc.
// — all available as namespaced methods on the client
```

### `AuthUser` type

Returned by `getSession()` and available in all composables/contexts:

```typescript
interface AuthUser {
  id: string;
  email: string;
  display_name: string | null;
  email_verified: boolean;
  role: string;
  auth_method: "Session" | "Bearer" | "ApiKey";
}
```

## @yackey-labs/yauth-shared

Shared TypeScript types (`AuthUser`, `AuthSession`, etc.) and an AAGUID authenticator map.

## @yackey-labs/yauth-ui-vue

Pre-built Vue 3 components and composables.

```bash
bun add @yackey-labs/yauth-ui-vue
```

**Install the plugin** in your app entry (`main.ts`):

```typescript
import { createApp } from "vue";
import { YAuthPlugin } from "@yackey-labs/yauth-ui-vue";
import App from "./App.vue";

createApp(App)
  .use(YAuthPlugin, { baseUrl: "/api/auth" })
  .mount("#app");
```

**Login page** — the `LoginForm` component handles email/password and emits `@success` when login succeeds:

```vue
<script setup lang="ts">
import { LoginForm } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const router = useRouter();
</script>

<template>
  <LoginForm @success="router.push('/dashboard')" />
</template>
```

**Dashboard page** — use the `useSession()` composable to access the current user:

```vue
<script setup lang="ts">
import { useSession, useAuth } from "@yackey-labs/yauth-ui-vue";

const { user, isAuthenticated, loading } = useSession();
const { logout } = useAuth();
</script>

<template>
  <div v-if="loading">Loading...</div>
  <div v-else-if="isAuthenticated">
    <p>Logged in as {{ user?.email }}</p>
    <button @click="logout">Logout</button>
  </div>
  <div v-else>Not logged in</div>
</template>
```

### Composables reference

| Composable | Returns | Use for |
|------------|---------|---------|
| `useYAuth()` | `{ client, user, loading, refetch }` | Direct client access |
| `useAuth()` | `{ user, loading, error, submitting, login, register, logout, forgotPassword, resetPassword, changePassword }` | Auth actions with error/loading state |
| `useSession()` | `{ user, loading, isAuthenticated, isEmailVerified, logout }` | Reactive session state checks |
| `useOrganizations()` | `{ organizations, loading, error, refetch, create, remove }` | List the user's orgs; create/delete |
| `useOrganization(id)` | `{ organization, loading, error, refetch, update }` | Single org by id (re-fetches when id changes) |
| `useMembers(orgId)` | `{ members, loading, error, refetch, invite }` | Members + create invitation |
| `useInvitation()` | `{ submitting, error, accept }` | Accept an invitation by token |

### Component props and events

| Component | Props | Events |
|-----------|-------|--------|
| `LoginForm` | `showPasskey?: boolean` | `@success`, `@mfa-required(pendingSessionId)` |
| `RegisterForm` | -- | `@success(message)` |
| `ForgotPasswordForm` | -- | `@success(message)` |
| `ResetPasswordForm` | `token: string` | `@success(message)` |
| `ChangePasswordForm` | -- | `@success(message)` |
| `VerifyEmail` | `token: string` | `@success(message)` |
| `MfaChallenge` | `pendingSessionId: string` | `@success` |
| `MfaSetup` | -- | `@complete` |
| `PasskeyButton` | `mode: "login" \| "register"`, `email?: string` | `@success` |
| `OAuthButtons` | `providers: string[]` | -- |
| `MagicLinkForm` | -- | `@success(message)` |
| `ProfileSettings` | -- | -- |
| `OrganizationList` | `onSelect?(org)` | -- |
| `OrganizationCard` | `organization`, `role?`, `memberCount?`, `onSelect?(org)` | -- |
| `OrganizationCreate` | -- | `@success(org)`, `@error(err)` |
| `OrganizationDetail` | `organizationId: string`, `canInvite?: boolean` | -- |
| `OrganizationSwitcher` | `activeId?: string \| null`, `onSwitch?(org)` | -- |
| `MemberList` | `organizationId: string` | -- |
| `InviteForm` | `organizationId: string` | `@success(result)`, `@error(err)` |
| `InvitationAccept` | `token?: string` | `@success(membership)`, `@error(err)` |

Components check for feature availability — if a feature group isn't present on the client, the component gracefully renders nothing.

### Organizations client surface

When the server enables the `organizations` Cargo feature, the auto-generated
client exposes a `client.organizations.*` namespace:

```typescript
const auth = createYAuthClient({ baseUrl: "/api/auth" });

// CRUD
const orgs = await auth.organizations.list();
const org = await auth.organizations.create({ name: "Acme", slug: "acme" });
await auth.organizations.update(org.id, { display_name: "Acme Inc." });
await auth.organizations.delete(org.id);

// Members + invitations
const members = await auth.organizations.listMembers(org.id);
const { invitation, token } = await auth.organizations.createInvitation(org.id, {
  email: "new-member@example.com",
  role: "member",
});
// token is shown ONCE — deliver it to the invitee (email, link, etc.)

// On the invitee's side, after logging in:
const membership = await auth.organizations.acceptInvitation({ token });
```

`OrganizationSwitcher` is a visual scaffold only — the "active organization"
session claim (which one is currently selected) lives in a separate issue and
is wired by the caller via `activeId` + `onSwitch`.

## @yackey-labs/yauth-ui-solidjs

Pre-built SolidJS components.

```bash
bun add @yackey-labs/yauth-ui-solidjs
```

```tsx
import { YAuthProvider, LoginForm } from "@yackey-labs/yauth-ui-solidjs";

function App() {
  return (
    <YAuthProvider baseUrl="/api/auth">
      <LoginForm onSuccess={() => navigate("/dashboard")} />
    </YAuthProvider>
  );
}
```

Access the session in any child component:

```tsx
import { useYAuth } from "@yackey-labs/yauth-ui-solidjs";

function Dashboard() {
  const { user, refetch } = useYAuth();
  return <p>Logged in as {user()?.email}</p>;
}
```

Same component set as Vue: `LoginForm`, `RegisterForm`, `ProfileSettings`, etc. Plus `ConsentScreen` for OAuth2 authorization consent UI.

`YAuthProvider` / `useYAuth()` accepts `client` or `baseUrl`.
