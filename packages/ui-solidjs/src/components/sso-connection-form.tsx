import type {
  ConnectionJSON as SsoConnectionResponse,
  CreateConnectionRequest as CreateSsoConnectionRequest,
} from "@yackey-labs/yauth-client";
import { For, Show, createMemo, createSignal } from "solid-js";
import { createSsoConnections } from "../hooks/create-sso-connections";

/**
 * SSO OIDC connection creation form (issue #93, Phase B).
 *
 * Mirror of the Vue component. Drafts a new connection; admin
 * flips it to `active` after testing.
 */
export interface SsoConnectionFormProps {
  organizationId: string;
  onSuccess?: (created: SsoConnectionResponse) => void;
  onError?: (error: Error) => void;
}

export function SsoConnectionForm(props: SsoConnectionFormProps) {
  const { create, error } = createSsoConnections(() => props.organizationId);

  const [name, setName] = createSignal("");
  const [discoveryUrl, setDiscoveryUrl] = createSignal("");
  const [clientId, setClientId] = createSignal("");
  const [clientSecret, setClientSecret] = createSignal("");
  const [scopes, setScopes] = createSignal("openid, email, profile");
  const [externalIdClaim, setExternalIdClaim] = createSignal("sub");
  const [emailClaim, setEmailClaim] = createSignal("email");
  const [displayNameClaim, setDisplayNameClaim] = createSignal("name");
  const [groupsClaim, setGroupsClaim] = createSignal("groups");
  const [groupRoles, setGroupRoles] = createSignal<
    Array<{ group: string; role: string }>
  >([{ group: "", role: "member" }]);
  const [jitEnabled, setJitEnabled] = createSignal(true);
  const [defaultRole, setDefaultRole] = createSignal("member");
  const [submitting, setSubmitting] = createSignal(false);

  const isValid = createMemo(
    () =>
      name().trim() !== "" &&
      discoveryUrl().includes(".well-known/openid-configuration") &&
      clientId().trim() !== "" &&
      clientSecret().trim() !== "",
  );

  const updateGroupRow = (i: number, patch: Partial<{ group: string; role: string }>) => {
    setGroupRoles((rows) =>
      rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)),
    );
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    if (!isValid() || submitting()) return;
    setSubmitting(true);
    const groupMap: Record<string, string> = {};
    for (const { group, role } of groupRoles()) {
      const g = group.trim();
      if (g) groupMap[g] = role;
    }
    const req: CreateSsoConnectionRequest = {
      name: name().trim(),
      kind: "oidc_client",
      oidc: {
        discovery_url: discoveryUrl().trim(),
        client_id: clientId().trim(),
        client_secret: clientSecret(),
        scopes: scopes()
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        claim_mappings: {
          external_id: externalIdClaim().trim() || "sub",
          email: emailClaim().trim() || "email",
          display_name: displayNameClaim().trim() || undefined,
          groups: groupsClaim().trim() || undefined,
          group_to_role: groupMap,
        },
      },
      jit_provisioning_enabled: jitEnabled(),
      default_role_on_jit: defaultRole(),
    };
    const result = await create(req);
    setSubmitting(false);
    if (result) {
      props.onSuccess?.(result);
    } else if (error()) {
      props.onError?.(new Error(error() ?? "create failed"));
    }
  };

  return (
    <form class="space-y-4" onSubmit={handleSubmit}>
      <Show when={error()}>
        <div
          class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
          role="alert"
        >
          {error()}
        </div>
      </Show>
      <div class="grid gap-3 md:grid-cols-2">
        <label class="block">
          <span class="text-xs font-medium">Name</span>
          <input
            value={name()}
            onInput={(e) => setName(e.currentTarget.value)}
            required
            class="mt-1 w-full rounded-md border bg-background px-3 py-2"
            placeholder="Acme Okta"
          />
        </label>
        <label class="block">
          <span class="text-xs font-medium">Discovery URL</span>
          <input
            value={discoveryUrl()}
            onInput={(e) => setDiscoveryUrl(e.currentTarget.value)}
            required
            class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            placeholder="https://idp.example/.well-known/openid-configuration"
          />
        </label>
        <label class="block">
          <span class="text-xs font-medium">Client ID</span>
          <input
            value={clientId()}
            onInput={(e) => setClientId(e.currentTarget.value)}
            required
            class="mt-1 w-full rounded-md border bg-background px-3 py-2"
          />
        </label>
        <label class="block">
          <span class="text-xs font-medium">Client Secret</span>
          <input
            value={clientSecret()}
            onInput={(e) => setClientSecret(e.currentTarget.value)}
            type="password"
            required
            class="mt-1 w-full rounded-md border bg-background px-3 py-2"
          />
        </label>
        <label class="block md:col-span-2">
          <span class="text-xs font-medium">Scopes (comma-separated)</span>
          <input
            value={scopes()}
            onInput={(e) => setScopes(e.currentTarget.value)}
            class="mt-1 w-full rounded-md border bg-background px-3 py-2"
          />
        </label>
      </div>

      <fieldset class="rounded-md border p-3">
        <legend class="px-1 text-xs font-medium">Claim mappings</legend>
        <div class="grid gap-3 md:grid-cols-2">
          <label class="block">
            <span class="text-xs">external_id</span>
            <input
              value={externalIdClaim()}
              onInput={(e) => setExternalIdClaim(e.currentTarget.value)}
              class="mt-1 w-full rounded-md border bg-background px-3 py-2"
            />
          </label>
          <label class="block">
            <span class="text-xs">email</span>
            <input
              value={emailClaim()}
              onInput={(e) => setEmailClaim(e.currentTarget.value)}
              class="mt-1 w-full rounded-md border bg-background px-3 py-2"
            />
          </label>
          <label class="block">
            <span class="text-xs">display_name</span>
            <input
              value={displayNameClaim()}
              onInput={(e) => setDisplayNameClaim(e.currentTarget.value)}
              class="mt-1 w-full rounded-md border bg-background px-3 py-2"
            />
          </label>
          <label class="block">
            <span class="text-xs">groups</span>
            <input
              value={groupsClaim()}
              onInput={(e) => setGroupsClaim(e.currentTarget.value)}
              class="mt-1 w-full rounded-md border bg-background px-3 py-2"
            />
          </label>
        </div>
        <div class="mt-3 space-y-2">
          <div class="text-xs font-medium">group → role</div>
          <For each={groupRoles()}>
            {(row, i) => (
              <div class="flex items-center gap-2">
                <input
                  value={row.group}
                  onInput={(e) => updateGroupRow(i(), { group: e.currentTarget.value })}
                  placeholder="group name"
                  class="flex-1 rounded-md border bg-background px-3 py-2 text-sm"
                />
                <select
                  value={row.role}
                  onChange={(e) => updateGroupRow(i(), { role: e.currentTarget.value })}
                  class="rounded-md border bg-background px-3 py-2 text-sm"
                >
                  <option value="owner">owner</option>
                  <option value="admin">admin</option>
                  <option value="member">member</option>
                </select>
                <button
                  type="button"
                  class="rounded-md border px-2 py-1 text-xs"
                  onClick={() =>
                    setGroupRoles((rows) => rows.filter((_, idx) => idx !== i()))
                  }
                >
                  ✕
                </button>
              </div>
            )}
          </For>
          <button
            type="button"
            class="rounded-md border px-3 py-1 text-xs"
            onClick={() =>
              setGroupRoles((rows) => [...rows, { group: "", role: "member" }])
            }
          >
            + Add mapping
          </button>
        </div>
      </fieldset>

      <div class="flex items-center gap-4">
        <label class="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={jitEnabled()}
            onChange={(e) => setJitEnabled(e.currentTarget.checked)}
          />
          JIT provisioning
        </label>
        <label class="flex items-center gap-2 text-xs">
          Default role:
          <select
            value={defaultRole()}
            onChange={(e) => setDefaultRole(e.currentTarget.value)}
            class="rounded-md border bg-background px-2 py-1"
          >
            <option value="owner">owner</option>
            <option value="admin">admin</option>
            <option value="member">member</option>
          </select>
        </label>
      </div>

      <button
        type="submit"
        disabled={!isValid() || submitting()}
        class="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
      >
        {submitting() ? "Saving…" : "Create connection"}
      </button>
    </form>
  );
}
