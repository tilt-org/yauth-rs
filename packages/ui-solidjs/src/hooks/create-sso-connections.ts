import type {
  ConnectionJSON,
  CreateConnectionRequest,
  TestConnectionResponse,
  UpdateConnectionRequest,
} from "@yackey-labs/yauth-client";
import { type Accessor, createEffect, createSignal } from "solid-js";
import { useYAuth } from "../provider";

// The huma-derived spec renamed/split the SSO connection types. Keep the old
// ergonomic names as local aliases; widen with the optional `saml` payload the
// unified connection list/forms read (the server validates the SAML body).
export interface SamlConnectionRow {
  idp_entity_id?: string;
  idp_sso_url?: string;
  idp_slo_url?: string | null;
  idp_x509_cert?: string;
  sp_entity_id?: string;
  sp_acs_url?: string;
  sp_private_key?: string | null;
  idp_initiated_sso_allowed?: boolean;
  assertion_signed_required?: boolean;
  response_signed_required?: boolean;
  want_encrypted_assertions?: boolean;
  attribute_mappings?: {
    email?: string;
    display_name?: string | null;
    external_id?: string;
    groups?: string | null;
    group_to_role?: Record<string, string>;
  };
}
type SsoConnectionResponse = ConnectionJSON & { saml?: SamlConnectionRow | null };
type CreateSsoConnectionRequest = CreateConnectionRequest & {
  saml?: SamlConnectionRow;
};
type UpdateSsoConnectionRequest = UpdateConnectionRequest;
type SsoConnectionTestResponse = TestConnectionResponse;

/**
 * Headless hook for SSO OIDC connection management (issue #93, Phase B).
 *
 * Mirrors `useSsoConnections` from the Vue package. Pass an `orgId`
 * accessor; the hook auto-refetches on mount and whenever the
 * accessor's value changes.
 */
export function createSsoConnections(orgId: Accessor<string | null | undefined>) {
  const { client } = useYAuth();
  const [connections, setConnections] = createSignal<SsoConnectionResponse[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const refetch = async () => {
    const id = orgId();
    if (!id || !client?.organizations) {
      setConnections([]);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const resp = await client.organizations.listSsoConnections(id);
      setConnections(resp.sso_connections ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load connections");
      setConnections([]);
    } finally {
      setLoading(false);
    }
  };

  createEffect(() => {
    void orgId();
    void refetch();
  });

  const create = async (
    input: CreateSsoConnectionRequest,
  ): Promise<SsoConnectionResponse | null> => {
    const id = orgId();
    if (!id || !client?.organizations) return null;
    setError(null);
    try {
      const created = await client.organizations.createSsoConnection(id, input);
      setConnections((prev) => [...prev, created]);
      return created;
    } catch (e) {
      setError(e instanceof Error ? e.message : "create failed");
      return null;
    }
  };

  const update = async (
    connectionId: string,
    changes: UpdateSsoConnectionRequest,
  ): Promise<SsoConnectionResponse | null> => {
    const id = orgId();
    if (!id || !client?.organizations) return null;
    setError(null);
    try {
      const updated = await client.organizations.updateSsoConnection(
        id,
        connectionId,
        changes,
      );
      setConnections((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
      return updated;
    } catch (e) {
      setError(e instanceof Error ? e.message : "update failed");
      return null;
    }
  };

  const disable = (connectionId: string) =>
    update(connectionId, { status: "disabled" });
  const enable = (connectionId: string) =>
    update(connectionId, { status: "active" });

  const remove = async (connectionId: string): Promise<boolean> => {
    const id = orgId();
    if (!id || !client?.organizations) return false;
    setError(null);
    try {
      await client.organizations.deleteSsoConnection(id, connectionId);
      setConnections((prev) => prev.filter((c) => c.id !== connectionId));
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : "delete failed");
      return false;
    }
  };

  const test = async (
    connectionId: string,
  ): Promise<SsoConnectionTestResponse | null> => {
    const id = orgId();
    if (!id || !client?.organizations) return null;
    setError(null);
    try {
      return await client.organizations.testSsoConnection(id, connectionId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "test failed");
      return null;
    }
  };

  return {
    connections,
    loading,
    error,
    refetch,
    create,
    update,
    disable,
    enable,
    remove,
    test,
  };
}

// Build the user-facing SSO login URL via
// `useYAuth().client.sso.loginUrl({ org, domain, redirectTo })`.
