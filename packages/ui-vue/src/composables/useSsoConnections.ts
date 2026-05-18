/**
 * SSO connection composables (issue #93, Phase B).
 *
 * Reactive wrappers around the SSO admin CRUD endpoints generated in
 * `@yackey-labs/yauth-client`. Surfaces `connections`, `loading`,
 * `error` plus `create` / `update` / `disable` / `enable` / `remove` /
 * `test` actions, with optimistic / pessimistic updates per action's
 * shape.
 *
 * Active-org bookkeeping lives in `useActiveOrg`. This composable is
 * stateless on the route side — the caller passes an `orgId` getter.
 */

import type {
	CreateSsoConnectionRequest,
	SsoConnectionResponse,
	SsoConnectionTestResponse,
	UpdateSsoConnectionRequest,
} from "@yackey-labs/yauth-client";
import { onMounted, ref, watch } from "vue";
import { useYAuth } from "../provider";

/**
 * Headless composable for SSO connection management.
 *
 * Auto-fetches connections on mount + whenever `orgId` changes.
 * Returns a refetch function for callers that need to re-pull after
 * out-of-band updates.
 */
export function useSsoConnections(orgId: () => string | null | undefined) {
	const yauth = useYAuth();
	const connections = ref<SsoConnectionResponse[]>([]);
	const loading = ref(false);
	const error = ref<string | null>(null);

	const fetchConnections = async () => {
		const id = orgId();
		if (!id) {
			connections.value = [];
			return;
		}
		loading.value = true;
		error.value = null;
		try {
			connections.value = await yauth.client.organizations.listSsoConnections(id);
		} catch (e) {
			error.value = e instanceof Error ? e.message : "failed to load connections";
			connections.value = [];
		} finally {
			loading.value = false;
		}
	};

	onMounted(fetchConnections);
	watch(orgId, fetchConnections);

	const create = async (
		input: CreateSsoConnectionRequest,
	): Promise<SsoConnectionResponse | null> => {
		const id = orgId();
		if (!id) return null;
		error.value = null;
		try {
			const created = await yauth.client.organizations.createSsoConnection(id, input);
			connections.value = [...connections.value, created];
			return created;
		} catch (e) {
			error.value = e instanceof Error ? e.message : "create failed";
			return null;
		}
	};

	const update = async (
		connectionId: string,
		changes: UpdateSsoConnectionRequest,
	): Promise<SsoConnectionResponse | null> => {
		const id = orgId();
		if (!id) return null;
		error.value = null;
		try {
			const updated = await yauth.client.organizations.updateSsoConnection(
				id,
				connectionId,
				changes,
			);
			connections.value = connections.value.map((c) =>
				c.id === updated.id ? updated : c,
			);
			return updated;
		} catch (e) {
			error.value = e instanceof Error ? e.message : "update failed";
			return null;
		}
	};

	const disable = (connectionId: string) =>
		update(connectionId, { status: "disabled" });
	const enable = (connectionId: string) =>
		update(connectionId, { status: "active" });

	const remove = async (connectionId: string): Promise<boolean> => {
		const id = orgId();
		if (!id) return false;
		error.value = null;
		try {
			await yauth.client.organizations.deleteSsoConnection(id, connectionId);
			connections.value = connections.value.filter((c) => c.id !== connectionId);
			return true;
		} catch (e) {
			error.value = e instanceof Error ? e.message : "delete failed";
			return false;
		}
	};

	const test = async (
		connectionId: string,
	): Promise<SsoConnectionTestResponse | null> => {
		const id = orgId();
		if (!id) return null;
		error.value = null;
		try {
			return await yauth.client.organizations.testSsoConnection(id, connectionId);
		} catch (e) {
			error.value = e instanceof Error ? e.message : "test failed";
			return null;
		}
	};

	return {
		connections,
		loading,
		error,
		refetch: fetchConnections,
		create,
		update,
		disable,
		enable,
		remove,
		test,
	};
}

// Note: build the user-facing SSO login URL via
// `useYAuth().client.sso.loginUrl({ org, domain, redirectTo })`.
