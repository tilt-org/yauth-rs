import type {
  CreateSsoConnectionRequest,
  SsoConnectionResponse,
} from "@yackey-labs/yauth-client";
import { For, Show, createMemo, createSignal } from "solid-js";
import { createSsoConnections } from "../hooks/create-sso-connections";

/**
 * SAML 2.0 SP connection creation form (issue #94, Phase B).
 *
 * Mirror of `SamlConnectionForm.vue` — drafts a new SAML SP
 * connection; the admin flips it to `active` after testing.
 *
 * Field shape mirrors `crates/yauth/src/plugins/organizations.rs`'s
 * `SamlConfigInput`. `sp_entity_id` / `sp_acs_url` are server-derived
 * and surfaced on the returned `SsoConnectionResponse.saml` blob; the
 * admin then pastes those into the IdP's "Audience URI" / "ACS URL"
 * fields (or imports the SP metadata XML via the connection list).
 */
export interface SamlConnectionFormProps {
  organizationId: string;
  onSuccess?: (created: SsoConnectionResponse) => void;
  onError?: (error: Error) => void;
}

export function SamlConnectionForm(props: SamlConnectionFormProps) {
  const { create, error } = createSsoConnections(() => props.organizationId);

  const [name, setName] = createSignal("");
  const [idpEntityId, setIdpEntityId] = createSignal("");
  const [idpSsoUrl, setIdpSsoUrl] = createSignal("");
  const [idpSloUrl, setIdpSloUrl] = createSignal("");
  const [idpX509Cert, setIdpX509Cert] = createSignal("");
  const [spPrivateKey, setSpPrivateKey] = createSignal("");
  const [emailAttr, setEmailAttr] = createSignal(
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  );
  const [displayNameAttr, setDisplayNameAttr] = createSignal(
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  );
  const [externalIdAttr, setExternalIdAttr] = createSignal("NameID");
  const [groupsAttr, setGroupsAttr] = createSignal(
    "http://schemas.xmlsoap.org/claims/Group",
  );
  const [groupRoles, setGroupRoles] = createSignal<
    Array<{ group: string; role: string }>
  >([{ group: "", role: "member" }]);
  const [assertionSignedRequired, setAssertionSignedRequired] = createSignal(true);
  const [responseSignedRequired, setResponseSignedRequired] = createSignal(true);
  const [wantEncryptedAssertions, setWantEncryptedAssertions] = createSignal(false);
  const [idpInitiatedSsoAllowed, setIdpInitiatedSsoAllowed] = createSignal(false);
  const [jitEnabled, setJitEnabled] = createSignal(true);
  const [defaultRole, setDefaultRole] = createSignal("member");
  const [submitting, setSubmitting] = createSignal(false);

  const isValid = createMemo(
    () =>
      name().trim() !== "" &&
      idpEntityId().trim() !== "" &&
      idpSsoUrl().trim().startsWith("http") &&
      idpX509Cert().includes("BEGIN CERTIFICATE"),
  );

  const updateGroupRow = (
    i: number,
    patch: Partial<{ group: string; role: string }>,
  ) => {
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
      kind: "saml_sp",
      saml: {
        idp_entity_id: idpEntityId().trim(),
        idp_sso_url: idpSsoUrl().trim(),
        idp_slo_url: idpSloUrl().trim() || null,
        idp_x509_cert: idpX509Cert().trim(),
        sp_private_key: spPrivateKey().trim() || null,
        idp_initiated_sso_allowed: idpInitiatedSsoAllowed(),
        assertion_signed_required: assertionSignedRequired(),
        response_signed_required: responseSignedRequired(),
        want_encrypted_assertions: wantEncryptedAssertions(),
        attribute_mappings: {
          email: emailAttr().trim(),
          display_name: displayNameAttr().trim() || null,
          external_id: externalIdAttr().trim() || "NameID",
          groups: groupsAttr().trim() || null,
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
            placeholder="Acme Okta SAML"
          />
        </label>
        <label class="block">
          <span class="text-xs font-medium">IdP Entity ID</span>
          <input
            value={idpEntityId()}
            onInput={(e) => setIdpEntityId(e.currentTarget.value)}
            required
            class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            placeholder="urn:idp:acme:saml or https://acme.okta.com/..."
          />
        </label>
        <label class="block md:col-span-2">
          <span class="text-xs font-medium">IdP Single Sign-On URL</span>
          <input
            value={idpSsoUrl()}
            onInput={(e) => setIdpSsoUrl(e.currentTarget.value)}
            required
            class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            placeholder="https://acme.okta.com/app/.../sso/saml"
          />
        </label>
        <label class="block md:col-span-2">
          <span class="text-xs font-medium">
            IdP Single Logout URL (optional)
          </span>
          <input
            value={idpSloUrl()}
            onInput={(e) => setIdpSloUrl(e.currentTarget.value)}
            class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            placeholder="https://acme.okta.com/app/.../slo/saml"
          />
        </label>
        <label class="block md:col-span-2">
          <span class="text-xs font-medium">
            IdP X.509 Signing Certificate (PEM)
          </span>
          <textarea
            value={idpX509Cert()}
            onInput={(e) => setIdpX509Cert(e.currentTarget.value)}
            required
            rows="6"
            class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
          />
        </label>
        <label class="block md:col-span-2">
          <span class="text-xs font-medium">
            SP Private Key (PEM) — optional, only for SP signing or encrypted
            assertions
          </span>
          <textarea
            value={spPrivateKey()}
            onInput={(e) => setSpPrivateKey(e.currentTarget.value)}
            rows="4"
            class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            placeholder="-----BEGIN PRIVATE KEY-----"
          />
        </label>
      </div>

      <fieldset class="rounded-md border p-3">
        <legend class="px-1 text-xs font-medium">Attribute mappings</legend>
        <div class="grid gap-3 md:grid-cols-2">
          <label class="block">
            <span class="text-xs">email attribute</span>
            <input
              value={emailAttr()}
              onInput={(e) => setEmailAttr(e.currentTarget.value)}
              class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            />
          </label>
          <label class="block">
            <span class="text-xs">display_name attribute</span>
            <input
              value={displayNameAttr()}
              onInput={(e) => setDisplayNameAttr(e.currentTarget.value)}
              class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            />
          </label>
          <label class="block">
            <span class="text-xs">external_id (default: NameID)</span>
            <input
              value={externalIdAttr()}
              onInput={(e) => setExternalIdAttr(e.currentTarget.value)}
              class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
            />
          </label>
          <label class="block">
            <span class="text-xs">groups attribute</span>
            <input
              value={groupsAttr()}
              onInput={(e) => setGroupsAttr(e.currentTarget.value)}
              class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
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
                  onInput={(e) =>
                    updateGroupRow(i(), { group: e.currentTarget.value })
                  }
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
                  x
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

      <fieldset class="rounded-md border p-3">
        <legend class="px-1 text-xs font-medium">Signing requirements</legend>
        <div class="space-y-2">
          <label class="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={assertionSignedRequired()}
              onChange={(e) => setAssertionSignedRequired(e.currentTarget.checked)}
            />
            Require assertion signature (recommended)
          </label>
          <label class="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={responseSignedRequired()}
              onChange={(e) => setResponseSignedRequired(e.currentTarget.checked)}
            />
            Require response signature (recommended)
          </label>
          <label class="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={wantEncryptedAssertions()}
              onChange={(e) => setWantEncryptedAssertions(e.currentTarget.checked)}
            />
            Require encrypted assertions (requires SP private key)
          </label>
          <label class="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={idpInitiatedSsoAllowed()}
              onChange={(e) => setIdpInitiatedSsoAllowed(e.currentTarget.checked)}
            />
            Allow IdP-initiated SSO (cross-tenant footgun — leave OFF unless
            the IdP sets <code>RelayState=cid:&lt;uuid&gt;</code>)
          </label>
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
        {submitting() ? "Saving..." : "Create SAML connection"}
      </button>
    </form>
  );
}
