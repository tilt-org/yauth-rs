import type {
	CreateInvitationRequest,
	CreateInvitationResponse,
	CreateOrgRequest,
	MembershipResponse,
	OrganizationResponse,
	UpdateOrgRequest,
} from "@yackey-labs/yauth-client";
import { onMounted, ref, watch } from "vue";
import { useYAuth } from "../provider";

/**
 * Generate a URL-safe slug from a free-form name.
 * Deterministic + idempotent — safe to recompute on every keystroke.
 */
export function slugify(input: string): string {
	return input
		.toLowerCase()
		.trim()
		.replace(/[^a-z0-9\s-]/g, "")
		.replace(/\s+/g, "-")
		.replace(/-+/g, "-")
		.replace(/^-|-$/g, "")
		.slice(0, 64);
}

/**
 * Headless composable for the current user's organization list.
 *
 * Auto-fetches on mount. Provides `create` / `refetch` helpers and surfaces
 * `loading` + `error` state. The active-organization concept (which one is
 * "currently selected") lives in issue #89 and is intentionally not modeled
 * here — this composable only owns the list.
 */
export function useOrganizations() {
	const { client } = useYAuth();
	const organizations = ref<OrganizationResponse[]>([]);
	const loading = ref(false);
	const error = ref<string | null>(null);

	const refetch = async () => {
		if (!client.organizations) {
			error.value = "Organizations feature is not enabled on this server.";
			return;
		}
		loading.value = true;
		error.value = null;
		try {
			organizations.value = await client.organizations.list();
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
		} finally {
			loading.value = false;
		}
	};

	const create = async (
		body: CreateOrgRequest,
	): Promise<OrganizationResponse | null> => {
		if (!client.organizations) {
			error.value = "Organizations feature is not enabled on this server.";
			return null;
		}
		error.value = null;
		try {
			const org = await client.organizations.create(body);
			organizations.value = [...organizations.value, org];
			return org;
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return null;
		}
	};

	const remove = async (id: string): Promise<boolean> => {
		if (!client.organizations) {
			error.value = "Organizations feature is not enabled on this server.";
			return false;
		}
		error.value = null;
		try {
			await client.organizations.delete(id);
			organizations.value = organizations.value.filter((o) => o.id !== id);
			return true;
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return false;
		}
	};

	onMounted(() => {
		void refetch();
	});

	return { organizations, loading, error, refetch, create, remove };
}

/**
 * Headless composable for a single organization by id.
 * Re-fetches when the id ref changes.
 */
export function useOrganization(id: () => string | null | undefined) {
	const { client } = useYAuth();
	const organization = ref<OrganizationResponse | null>(null);
	const loading = ref(false);
	const error = ref<string | null>(null);

	const refetch = async () => {
		const current = id();
		if (!current) {
			organization.value = null;
			return;
		}
		if (!client.organizations) {
			error.value = "Organizations feature is not enabled on this server.";
			return;
		}
		loading.value = true;
		error.value = null;
		try {
			organization.value = await client.organizations.get(current);
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			organization.value = null;
		} finally {
			loading.value = false;
		}
	};

	const update = async (
		body: UpdateOrgRequest,
	): Promise<OrganizationResponse | null> => {
		const current = id();
		if (!current || !client.organizations) return null;
		error.value = null;
		try {
			const updated = await client.organizations.update(current, body);
			organization.value = updated;
			return updated;
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return null;
		}
	};

	watch(id, () => {
		void refetch();
	});

	onMounted(() => {
		void refetch();
	});

	return { organization, loading, error, refetch, update };
}

/**
 * Headless composable for an organization's members + invitation creation.
 */
export function useMembers(orgId: () => string | null | undefined) {
	const { client } = useYAuth();
	const members = ref<MembershipResponse[]>([]);
	const loading = ref(false);
	const error = ref<string | null>(null);

	const refetch = async () => {
		const current = orgId();
		if (!current) {
			members.value = [];
			return;
		}
		if (!client.organizations) {
			error.value = "Organizations feature is not enabled on this server.";
			return;
		}
		loading.value = true;
		error.value = null;
		try {
			members.value = await client.organizations.listMembers(current);
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
		} finally {
			loading.value = false;
		}
	};

	const invite = async (
		body: CreateInvitationRequest,
	): Promise<CreateInvitationResponse | null> => {
		const current = orgId();
		if (!current || !client.organizations) return null;
		error.value = null;
		try {
			return await client.organizations.createInvitation(current, body);
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return null;
		}
	};

	watch(orgId, () => {
		void refetch();
	});

	onMounted(() => {
		void refetch();
	});

	return { members, loading, error, refetch, invite };
}

/**
 * Headless composable for accepting an invitation by token.
 * Stateless — does not auto-run on mount; caller invokes `accept`.
 */
export function useInvitation() {
	const { client } = useYAuth();
	const submitting = ref(false);
	const error = ref<string | null>(null);

	const accept = async (token: string): Promise<MembershipResponse | null> => {
		if (!client.organizations) {
			error.value = "Organizations feature is not enabled on this server.";
			return null;
		}
		if (!token.trim()) {
			error.value = "Invitation token is required.";
			return null;
		}
		submitting.value = true;
		error.value = null;
		try {
			return await client.organizations.acceptInvitation({ token });
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return null;
		} finally {
			submitting.value = false;
		}
	};

	return { submitting, error, accept };
}
