import type {
  CreateSsoConnectionRequest,
  SsoConnectionResponse,
  SsoConnectionTestResponse,
  UpdateSsoConnectionRequest,
} from "@yackey-labs/yauth-client";
import { type Accessor, createEffect, createSignal } from "solid-js";
import { useYAuth } from "../provider";

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
      const rows = await client.organizations.listSsoConnections(id);
      setConnections(rows);
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
