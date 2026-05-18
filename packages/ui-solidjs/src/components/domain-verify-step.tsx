import type { CreateDomainResponse, VerifyDomainResponse } from "@yackey-labs/yauth-client";
import { type Component, createSignal, Show } from "solid-js";
import { createDomains } from "../hooks/create-organizations";

export interface DomainVerifyStepProps {
  organizationId: string;
  /** The domain claim to verify — usually the result of `<DomainClaim />`. */
  claim: CreateDomainResponse;
  onVerified?: (result: VerifyDomainResponse) => void;
}

/**
 * Final step of the domain-onboarding flow. Displays the DNS TXT record the
 * operator must publish, plus a "Run verification" button that hits the
 * verify endpoint. The verification is best-effort — operators can retry.
 */
export const DomainVerifyStep: Component<DomainVerifyStepProps> = (props) => {
  const { verify, error, submitting } = createDomains(() => props.organizationId);
  const [lastResult, setLastResult] = createSignal<VerifyDomainResponse | null>(null);

  const handleVerify = async () => {
    const result = await verify(props.claim.domain.id);
    setLastResult(result);
    if (result?.verified) {
      props.onVerified?.(result);
    }
  };

  return (
    <div class="space-y-3">
      <div class="rounded-md border border-input bg-muted/40 p-3 space-y-2">
        <p class="text-xs text-muted-foreground">
          Publish the following DNS TXT record at your DNS provider, then click "Run verification".
          Some DNS providers can take up to 60 seconds to propagate.
        </p>
        <div>
          <span class="text-xs font-medium">Record</span>
          <code class="mt-1 block break-all font-mono text-xs">{props.claim.dns_record_name}</code>
        </div>
        <div>
          <span class="text-xs font-medium">Value</span>
          <code class="mt-1 block break-all font-mono text-xs">
            {props.claim.verification_token}
          </code>
        </div>
      </div>

      <Show when={error()}>
        <div
          class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
          role="alert"
          aria-live="polite"
        >
          {error()}
        </div>
      </Show>

      <Show when={lastResult() && !lastResult()?.verified}>
        <div class="rounded-md bg-amber-500/10 px-3 py-2 text-sm text-amber-700">
          Verification did not find the expected DNS TXT record. Double-check the record name +
          value, then retry.
        </div>
      </Show>

      <Show when={lastResult()?.verified}>
        <div class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-700">
          Domain verified. JIT auto-join is now active for matching users.
        </div>
      </Show>

      <button
        type="button"
        class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 disabled:pointer-events-none disabled:opacity-50"
        on:click={handleVerify}
        disabled={submitting()}
      >
        {submitting() ? "Verifying…" : "Run verification"}
      </button>
    </div>
  );
};
