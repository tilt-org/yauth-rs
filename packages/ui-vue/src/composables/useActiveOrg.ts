/**
 * Composable for the active-organization claim (issue #89).
 *
 * Vue twin of `createActiveOrg` from `@yackey-labs/yauth-ui-solidjs`.
 * Exposes the current active org, the membership list, and an imperative
 * `switchTo(orgId)` action.
 */
import type {
  ActiveOrgEntry,
  ActiveOrgResponse,
  SetActiveOrgRequest,
} from "@yackey-labs/yauth-client";
import { ref } from "vue";
import { useYAuth } from "../provider";

export function useActiveOrg() {
  const { client } = useYAuth();
  const activeOrgId = ref<string | null>(null);
  const orgs = ref<ActiveOrgEntry[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);

  const apply = (resp: ActiveOrgResponse) => {
    activeOrgId.value = resp.active_org_id ?? null;
    orgs.value = resp.orgs;
  };

  const refetch = async () => {
    if (!client?.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return;
    }
    loading.value = true;
    error.value = null;
    try {
      apply(await client.organizations.getActiveOrg());
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
    } finally {
      loading.value = false;
    }
  };

  const switchTo = async (orgId: string): Promise<string | null> => {
    if (!client?.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return null;
    }
    loading.value = true;
    error.value = null;
    try {
      const body: SetActiveOrgRequest = { organization_id: orgId };
      const resp = await client.organizations.setActiveOrg(body);
      apply(resp);
      return resp.bearer_access_token ?? null;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      loading.value = false;
    }
  };

  const clear = async (): Promise<string | null> => {
    if (!client?.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return null;
    }
    loading.value = true;
    error.value = null;
    try {
      const resp = await client.organizations.clearActiveOrg();
      apply(resp);
      return resp.bearer_access_token ?? null;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      loading.value = false;
    }
  };

  void refetch();

  return { activeOrgId, orgs, loading, error, refetch, switchTo, clear };
}
