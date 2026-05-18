import { SsoLoginButton } from "@yackey-labs/yauth-ui-solidjs";

const ORG_SLUG = import.meta.env.VITE_ORG_SLUG ?? "acme";

/**
 * Server B's login page. The user has a single way in: hit the federated
 * IdP. There's no local password form here — that's the point of the
 * demo. (If you want to keep the password form as a fallback, add the
 * `<LoginForm />` component from `@yackey-labs/yauth-ui-solidjs`.)
 */
export function Login() {
  return (
    <div>
      <h1>
        Server B <span class="badge">App</span>
      </h1>
      <p class="muted">
        This is the App side of the cross-IdP demo. Sign in with the
        federated Identity Provider running on port 8080.
      </p>

      <div class="card">
        <h2>Sign in</h2>
        <SsoLoginButton
          orgSlug={ORG_SLUG}
          label="Sign in via Server A IdP"
          redirectTo="/dashboard"
        />
        <p class="muted" style={{ "margin-top": "12px" }}>
          You will be redirected to <code>http://localhost:5173</code>
          (Server A) to authenticate. After consent, Server A bounces
          you back here with an authorization code; Server B exchanges
          it for an ID token and JIT-provisions your account.
        </p>
      </div>
    </div>
  );
}
