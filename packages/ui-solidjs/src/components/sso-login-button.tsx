import { Show, createMemo } from "solid-js";
import { useYAuth } from "../provider";

export interface SsoLoginButtonProps {
  /** Org slug for the explicit-org login path. */
  orgSlug?: string;
  /** Email-domain for the HRD path (e.g. `acme.com`). */
  domain?: string;
  /** Display label override. Default: "Sign in with SSO". */
  label?: string;
  /** Where to redirect after a successful sign-in. */
  redirectTo?: string;
}

export function SsoLoginButton(props: SsoLoginButtonProps) {
  const yauth = useYAuth();
  const url = createMemo(() =>
    yauth.client.sso.loginUrl({
      org: props.orgSlug,
      domain: props.domain,
      redirectTo: props.redirectTo,
    }),
  );
  const canSignIn = createMemo(() => Boolean(props.orgSlug || props.domain));

  return (
    <Show when={canSignIn()}>
      <a
        href={url()}
        class="inline-flex items-center justify-center rounded-md border bg-background px-4 py-2 text-sm font-medium hover:bg-accent"
      >
        <svg
          class="mr-2 h-4 w-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        >
          <title>SSO</title>
          <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3" />
        </svg>
        {props.label ?? "Sign in with SSO"}
      </a>
    </Show>
  );
}
