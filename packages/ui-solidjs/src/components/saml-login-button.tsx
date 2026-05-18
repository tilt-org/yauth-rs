import { Show, createMemo } from "solid-js";
import { useYAuth } from "../provider";

/**
 * "Sign in via SAML" button (issue #94, Phase B).
 *
 * Drives the user-facing SAML federated login flow by redirecting to
 * `/sso/saml/login?org=<slug>&redirect_to=<path>`. Renders nothing if
 * neither `orgSlug` nor `domain` is provided.
 */
export interface SamlLoginButtonProps {
  /** Org slug for the explicit-org login path. */
  orgSlug?: string;
  /** Email-domain for the HRD path (e.g. `acme.com`). */
  domain?: string;
  /** Display label override. Default: "Sign in via SAML". */
  label?: string;
  /** Where to redirect after a successful sign-in. */
  redirectTo?: string;
}

export function SamlLoginButton(props: SamlLoginButtonProps) {
  const yauth = useYAuth();
  const url = createMemo(() =>
    yauth.client.sso.samlLoginUrl({
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
          <title>SAML</title>
          <path d="M21 2H3a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h18a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM7 17l5-5-5-5M13 17h4" />
        </svg>
        {props.label ?? "Sign in via SAML"}
      </a>
    </Show>
  );
}
