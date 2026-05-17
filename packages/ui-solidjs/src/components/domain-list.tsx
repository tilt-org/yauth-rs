import { type Component, For, Show } from "solid-js";
import { createDomains } from "../hooks/create-organizations";

export interface DomainListProps {
  organizationId: string;
}

const STATUS_LABEL: Record<string, string> = {
  pending: "Pending verification",
  verified: "Verified",
  failed: "Verification failed",
};

/**
 * Read-only-with-actions listing of an org's claimed domains. Admins get
 * verify / remove buttons; non-admins still see the list (the backend gate
 * is on member-of-org rather than admin-of-org).
 */
export const DomainList: Component<DomainListProps> = (props) => {
  const { domains, loading, error, verify, remove, submitting } = createDomains(
    () => props.organizationId,
  );

  return (
    <div class="space-y-3">
      <Show when={error()}>
        <div
          class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
          role="alert"
          aria-live="polite"
        >
          {error()}
        </div>
      </Show>

      <Show when={loading()}>
        <p class="text-sm text-muted-foreground">Loading domains…</p>
      </Show>

      <Show when={!loading() && domains().length === 0}>
        <p class="text-sm text-muted-foreground">No domains claimed yet.</p>
      </Show>

      <ul class="divide-y divide-border">
        <For each={domains()}>
          {(d) => (
            <li class="flex items-center justify-between gap-3 py-2">
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2">
                  <code class="font-mono text-sm">{d.domain}</code>
                  <span
                    class={`rounded-full px-2 py-0.5 text-xs ${
                      d.status === "verified"
                        ? "bg-emerald-500/10 text-emerald-700"
                        : d.status === "failed"
                          ? "bg-destructive/10 text-destructive"
                          : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {STATUS_LABEL[d.status] ?? d.status}
                  </span>
                </div>
                <p class="text-xs text-muted-foreground">
                  Auto-join {d.auto_join_on_signup ? "on" : "off"} · default role{" "}
                  {d.default_role_on_auto_join}
                </p>
              </div>
              <div class="flex gap-2">
                <Show when={d.status !== "verified"}>
                  <button
                    type="button"
                    class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-transparent px-3 text-xs font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-50"
                    on:click={() => verify(d.id)}
                    disabled={submitting()}
                  >
                    Verify
                  </button>
                </Show>
                <button
                  type="button"
                  class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-transparent px-3 text-xs font-medium text-destructive shadow-sm transition-colors hover:bg-destructive/10 disabled:pointer-events-none disabled:opacity-50"
                  on:click={() => remove(d.id)}
                  disabled={submitting()}
                >
                  Remove
                </button>
              </div>
            </li>
          )}
        </For>
      </ul>
    </div>
  );
};
