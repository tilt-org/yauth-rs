import { createMemo, createSignal } from "solid-js";

/**
 * SCIM settings panel (issue #95).
 *
 * SolidJS mirror of the Vue ScimSettingsPanel. Surfaces the per-org
 * SCIM Base URL and the bound API key requirement to org admins, with
 * copy-pasteable curl snippets an IdP admin can run to verify the
 * connector before wiring it into Okta / Entra / OneLogin.
 *
 * Authentication: SCIM endpoints use Authorization: Bearer <key> where
 * <key> is an org-scoped API key (issue #91) with the `scim:read` and
 * `scim:write` scopes. This component does NOT mint the key — it links
 * to the API Keys panel. We never display the plaintext here.
 */
export interface ScimSettingsPanelProps {
  organizationId: string;
  /** yauth base URL without trailing slash. */
  baseUrl: string;
  /** Route to the API Keys panel; defaults to a sensible path. */
  apiKeysRoute?: string;
}

function stripTrailingSlashes(url: string): string {
  let i = url.length;
  while (i > 0 && url[i - 1] === "/") i--;
  return url.slice(0, i);
}

export function ScimSettingsPanel(props: ScimSettingsPanelProps) {
  const apiKeysRoute = createMemo(
    () =>
      props.apiKeysRoute ??
      `/organizations/${props.organizationId}/settings/api-keys`,
  );
  const scimBaseUrl = createMemo(
    () =>
      `${stripTrailingSlashes(props.baseUrl)}/api/scim/v2/organizations/${props.organizationId}`,
  );
  const curlList = createMemo(
    () => `curl -H "Authorization: Bearer <your-scim-key>" \\
     -H "Accept: application/scim+json" \\
     "${scimBaseUrl()}/Users?count=10"`,
  );
  const curlConfig = createMemo(
    () => `curl -H "Authorization: Bearer <your-scim-key>" \\
     -H "Accept: application/scim+json" \\
     "${scimBaseUrl()}/ServiceProviderConfig"`,
  );

  type CopyKey = "url" | "curl-list" | "curl-config";
  const [copied, setCopied] = createSignal<CopyKey | null>(null);
  const copy = async (value: string, label: CopyKey) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      setTimeout(() => {
        if (copied() === label) setCopied(null);
      }, 1500);
    } catch {
      // Silent no-op outside HTTPS.
    }
  };

  return (
    <section class="space-y-6">
      <header>
        <h2 class="text-base font-semibold">SCIM provisioning</h2>
        <p class="mt-1 text-sm text-muted-foreground">
          Paste the SCIM Base URL and an org-scoped API key into your IdP
          (Okta, Entra ID, OneLogin) so it can provision users into this
          organization.
        </p>
      </header>

      <div class="space-y-2">
        <label class="block text-xs font-medium uppercase tracking-wider text-muted-foreground">
          SCIM Base URL
        </label>
        <div class="flex gap-2">
          <code class="flex-1 truncate rounded-md border bg-muted px-3 py-2 text-xs">
            {scimBaseUrl()}
          </code>
          <button
            type="button"
            class="rounded-md border px-3 py-1 text-xs"
            onClick={() => copy(scimBaseUrl(), "url")}
          >
            {copied() === "url" ? "Copied" : "Copy"}
          </button>
        </div>
      </div>

      <div
        class="rounded-md border bg-muted/30 p-4 text-sm"
        role="region"
        aria-label="API key requirement"
      >
        <div class="mb-2 font-medium">Authentication</div>
        <p class="text-muted-foreground">
          SCIM uses an <strong>org-scoped API key</strong> with the
          {" "}
          <code>scim:read</code> and <code>scim:write</code> scopes. The IdP
          sends it as <code>Authorization: Bearer &lt;key&gt;</code> on every
          request.
        </p>
        <div class="mt-3">
          <a
            href={apiKeysRoute()}
            class="inline-flex items-center rounded-md bg-primary px-3 py-1 text-xs text-primary-foreground"
          >
            Manage API keys →
          </a>
        </div>
        <p class="mt-3 text-xs text-muted-foreground">
          The plaintext key is shown{" "}
          <strong>only at the moment of creation</strong>. We never display it
          here or in the IdP-side view — only the prefix and the {" "}
          <code>scim:*</code> scopes.
        </p>
      </div>

      <div class="space-y-3">
        <h3 class="text-sm font-medium">Verify with curl</h3>
        <p class="text-xs text-muted-foreground">
          Replace <code>&lt;your-scim-key&gt;</code> with the plaintext API key
          you copied during key creation.
        </p>

        <div class="space-y-2">
          <label class="block text-xs font-medium uppercase tracking-wider text-muted-foreground">
            List users
          </label>
          <div class="flex gap-2">
            <pre class="flex-1 overflow-x-auto rounded-md border bg-muted px-3 py-2 text-xs whitespace-pre">
              {curlList()}
            </pre>
            <button
              type="button"
              class="rounded-md border px-3 py-1 text-xs self-start"
              onClick={() => copy(curlList(), "curl-list")}
            >
              {copied() === "curl-list" ? "Copied" : "Copy"}
            </button>
          </div>
        </div>

        <div class="space-y-2">
          <label class="block text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Discover capabilities
          </label>
          <div class="flex gap-2">
            <pre class="flex-1 overflow-x-auto rounded-md border bg-muted px-3 py-2 text-xs whitespace-pre">
              {curlConfig()}
            </pre>
            <button
              type="button"
              class="rounded-md border px-3 py-1 text-xs self-start"
              onClick={() => copy(curlConfig(), "curl-config")}
            >
              {copied() === "curl-config" ? "Copied" : "Copy"}
            </button>
          </div>
        </div>
      </div>

      <div class="rounded-md border bg-muted/30 p-4 text-xs text-muted-foreground">
        <div class="mb-1 font-medium text-foreground">
          Per-IdP setup guides
        </div>
        <ul class="ml-4 list-disc space-y-1">
          <li>
            <a class="underline" href="/docs/scim/okta.md" target="_blank">
              Okta
            </a>
          </li>
          <li>
            <a class="underline" href="/docs/scim/entra.md" target="_blank">
              Microsoft Entra ID
            </a>
          </li>
          <li>
            <a class="underline" href="/docs/scim/onelogin.md" target="_blank">
              OneLogin
            </a>
          </li>
        </ul>
      </div>
    </section>
  );
}
