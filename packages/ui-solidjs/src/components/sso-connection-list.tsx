import { For, Show } from "solid-js";
import { createSsoConnections } from "../hooks/create-sso-connections";

/**
 * SSO connection list (issue #93, Phase B).
 *
 * Mirror of the Vue component — admin view of one org's federation
 * connections with per-row test/enable/disable/delete actions.
 */
export interface SsoConnectionListProps {
  organizationId: string;
  onTest?: (id: string, ok: boolean, detail: string) => void;
}

export function SsoConnectionList(props: SsoConnectionListProps) {
  const { connections, loading, error, disable, enable, remove, test } =
    createSsoConnections(() => props.organizationId);

  const handleTest = async (id: string) => {
    const r = await test(id);
    if (r) props.onTest?.(id, r.ok, r.detail);
  };

  return (
    <div class="space-y-4">
      <Show when={loading()}>
        <div class="text-sm text-muted-foreground">Loading…</div>
      </Show>
      <Show when={error()}>
        <div
          class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
          role="alert"
        >
          {error()}
        </div>
      </Show>
      <Show
        when={!loading() && connections().length > 0}
        fallback={
          <Show when={!loading()}>
            <div class="rounded-md border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">
              No SSO connections yet. Add one to enable federated sign-in for
              this organization.
            </div>
          </Show>
        }
      >
        <ul class="space-y-3">
          <For each={connections()}>
            {(c) => (
              <li class="rounded-md border bg-card p-4">
                <div class="flex items-start justify-between gap-4">
                  <div>
                    <div class="font-medium">{c.name}</div>
                    <div class="text-xs text-muted-foreground">
                      {c.kind} ·{" "}
                      <span
                        classList={{
                          "text-emerald-600": c.status === "active",
                          "text-amber-600": c.status === "draft",
                          "text-muted-foreground": c.status === "disabled",
                        }}
                      >
                        {c.status}
                      </span>
                    </div>
                    <Show when={c.oidc}>
                      <div class="mt-1 text-xs text-muted-foreground">
                        client_id: <code>{c.oidc?.client_id}</code>
                      </div>
                    </Show>
                  </div>
                  <div class="flex gap-2">
                    <button
                      type="button"
                      class="rounded-md border px-3 py-1 text-xs"
                      onClick={() => handleTest(c.id)}
                    >
                      Test
                    </button>
                    <Show
                      when={c.status === "active"}
                      fallback={
                        <button
                          type="button"
                          class="rounded-md border px-3 py-1 text-xs"
                          onClick={() => enable(c.id)}
                        >
                          Enable
                        </button>
                      }
                    >
                      <button
                        type="button"
                        class="rounded-md border px-3 py-1 text-xs"
                        onClick={() => disable(c.id)}
                      >
                        Disable
                      </button>
                    </Show>
                    <button
                      type="button"
                      class="rounded-md border border-destructive px-3 py-1 text-xs text-destructive"
                      onClick={() => remove(c.id)}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </li>
            )}
          </For>
        </ul>
      </Show>
    </div>
  );
}
