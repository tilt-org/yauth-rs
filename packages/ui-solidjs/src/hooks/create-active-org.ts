/**
 * Headless hook for the active-organization claim (issue #89).
 *
 * Exposes the currently-active org, the full membership list, and an
 * imperative `switchTo(orgId)` action.
 *
 * Carrier semantics (cookie vs bearer) are abstracted from callers:
 * - Cookie sessions update server-side; no token rotation needed.
 * - Bearer JWT clients receive a freshly-issued token via
 *   `bearer_access_token` on the response; callers are responsible for
 *   adopting it (e.g. via the YAuth client mutator).
 */
import type {
  ActiveOrgResponse,
  OrgMembershipSummary,
  SetActiveOrgRequest,
} from "@yackey-labs/yauth-client";
import { createSignal } from "solid-js";
import { useYAuth } from "../provider";

// The huma-derived spec renamed the per-org membership entry. Keep the old
// ergonomic name as a local alias for callers (e.g. organization-switcher).
export type ActiveOrgEntry = OrgMembershipSummary;

export function createActiveOrg() {
  const { client } = useYAuth();
  const [activeOrgId, setActiveOrgId] = createSignal<string | null>(null);
  const [orgs, setOrgs] = createSignal<ActiveOrgEntry[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const apply = (resp: ActiveOrgResponse) => {
    setActiveOrgId(resp.active_org_id ?? null);
    setOrgs(resp.orgs ?? []);
  };

  const refetch = async () => {
    if (!client?.organizations) {
      setError("Organizations feature is not enabled on this server.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      apply(await client.organizations.getActiveOrg());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  /**
   * Switch into an organization the caller is a member of.
   *
   * Returns the new bearer access token when the caller used JWT auth —
   * the client adopter is responsible for surfacing it onto subsequent
   * requests. Cookie callers receive `null` since no rotation occurs.
   */
  const switchTo = async (orgId: string): Promise<string | null> => {
    if (!client?.organizations) {
      setError("Organizations feature is not enabled on this server.");
      return null;
    }
    setLoading(true);
    setError(null);
    try {
      const body: SetActiveOrgRequest = { organization_id: orgId };
      const resp = await client.organizations.setActiveOrg(body);
      apply(resp);
      // The huma-derived spec no longer mints a bearer token on org switch.
      return null;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return null;
    } finally {
      setLoading(false);
    }
  };

  const clear = async (): Promise<string | null> => {
    if (!client?.organizations) {
      setError("Organizations feature is not enabled on this server.");
      return null;
    }
    setLoading(true);
    setError(null);
    try {
      const resp = await client.organizations.clearActiveOrg();
      apply(resp);
      // See note in switchTo: no bearer token is returned by the new spec.
      return null;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return null;
    } finally {
      setLoading(false);
    }
  };

  void refetch();

  return { activeOrgId, orgs, loading, error, refetch, switchTo, clear };
}
