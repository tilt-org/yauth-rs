import type { OrganizationDomainJSON as CreateDomainResponse } from "@yackey-labs/yauth-client";
import { type Component, createSignal, Show } from "solid-js";
import { createDomains } from "../hooks/create-organizations";

export interface DomainClaimProps {
  organizationId: string;
  onSuccess?: (result: CreateDomainResponse) => void;
  onError?: (error: Error) => void;
}

const isDomain = (v: string) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v.trim());

/**
 * Form for an org admin to claim a new email domain. On success surfaces
 * the verification token + the DNS record name; the parent UI is expected
 * to chain into <DomainVerifyStep /> for the "publish the TXT record" step.
 */
export const DomainClaim: Component<DomainClaimProps> = (props) => {
  const { claim, lastCreated, error, submitting } = createDomains(() => props.organizationId);
  const [domain, setDomain] = createSignal("");
  const [autoJoin, setAutoJoin] = createSignal(false);
  const [requireVerified, setRequireVerified] = createSignal(true);

  const handleSubmit = async (e: SubmitEvent) => {
    e.preventDefault();
    const trimmed = domain().trim().toLowerCase();
    if (!isDomain(trimmed)) return;
    const result = await claim({
      domain: trimmed,
      auto_join_on_signup: autoJoin(),
      require_email_verified: requireVerified(),
    });
    if (result) {
      setDomain("");
      props.onSuccess?.(result);
    } else if (error()) {
      props.onError?.(new Error(error() as string));
    }
  };

  return (
    <form class="space-y-4" on:submit={handleSubmit}>
      <Show when={error()}>
        <div
          class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
          role="alert"
          aria-live="polite"
        >
          {error()}
        </div>
      </Show>

      <div class="space-y-2">
        <label class="text-sm font-medium leading-none" for="yauth-domain-input">
          Domain
        </label>
        <input
          class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
          id="yauth-domain-input"
          name="domain"
          type="text"
          placeholder="acme.com"
          value={domain()}
          on:input={(e) => setDomain(e.currentTarget.value)}
          required
          autocomplete="off"
          disabled={submitting()}
        />
      </div>

      <label class="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={autoJoin()}
          on:change={(e) => setAutoJoin(e.currentTarget.checked)}
          disabled={submitting()}
        />
        Auto-join matching users on signup
      </label>

      <label class="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={requireVerified()}
          on:change={(e) => setRequireVerified(e.currentTarget.checked)}
          disabled={submitting()}
        />
        Require verified email before auto-join
      </label>

      <button
        class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
        type="submit"
        disabled={submitting() || !isDomain(domain().trim())}
      >
        {submitting() ? "Claiming…" : "Claim domain"}
      </button>

      <Show when={lastCreated()}>
        {(result) => (
          <div class="rounded-md border border-input bg-muted/40 p-3 space-y-2">
            <p class="text-xs text-muted-foreground">
              Publish the following DNS TXT record to verify ownership. The token is shown ONCE —
              copy it now.
            </p>
            <div>
              <span class="text-xs font-medium">Record</span>
              <code class="mt-1 block break-all font-mono text-xs">{result().verification_record}</code>
            </div>
            <div>
              <span class="text-xs font-medium">Value</span>
              <code class="mt-1 block break-all font-mono text-xs">
                {result().verification_token}
              </code>
            </div>
          </div>
        )}
      </Show>
    </form>
  );
};
