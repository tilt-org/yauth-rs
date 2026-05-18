import type {
	CreateInvitationRequest,
	CreateInvitationResponse,
	CreateOrgRequest,
	MembershipResponse,
	OrganizationResponse,
	UpdateOrgRequest,
} from "@yackey-labs/yauth-client";
import { type Accessor, createSignal } from "solid-js";
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
 * Headless hook for the current user's organization list.
 *
 * NOTE: We use `createSignal` + manual fetch (rather than `createResource`)
 * because `createResource` requires a tracked source, and we want fully
 * imperative `refetch` semantics matching the Vue composable's shape. The
 * active-organization concept lives in issue #89.
 */
export function createOrganizations() {
	const { client } = useYAuth();
	const [organizations, setOrganizations] = createSignal<
		OrganizationResponse[]
	>([]);
	const [loading, setLoading] = createSignal(false);
	const [error, setError] = createSignal<string | null>(null);

	const refetch = async () => {
		if (!client?.organizations) {
			setError("Organizations feature is not enabled on this server.");
			return;
		}
		setLoading(true);
		setError(null);
		try {
			setOrganizations(await client.organizations.list());
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
		} finally {
			setLoading(false);
		}
	};

	const create = async (
		body: CreateOrgRequest,
	): Promise<OrganizationResponse | null> => {
		if (!client?.organizations) {
			setError("Organizations feature is not enabled on this server.");
			return null;
		}
		setError(null);
		try {
			const org = await client.organizations.create(body);
			setOrganizations([...organizations(), org]);
			return org;
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
			return null;
		}
	};

	const remove = async (id: string): Promise<boolean> => {
		if (!client?.organizations) {
			setError("Organizations feature is not enabled on this server.");
			return false;
		}
		setError(null);
		try {
			await client.organizations.delete(id);
			setOrganizations(organizations().filter((o) => o.id !== id));
			return true;
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
			return false;
		}
	};

	void refetch();

	return { organizations, loading, error, refetch, create, remove };
}

/**
 * Headless hook for a single organization by id accessor.
 */
export function createOrganization(id: Accessor<string | null | undefined>) {
	const { client } = useYAuth();
	const [organization, setOrganization] =
		createSignal<OrganizationResponse | null>(null);
	const [loading, setLoading] = createSignal(false);
	const [error, setError] = createSignal<string | null>(null);

	const refetch = async () => {
		const current = id();
		if (!current) {
			setOrganization(null);
			return;
		}
		if (!client?.organizations) {
			setError("Organizations feature is not enabled on this server.");
			return;
		}
		setLoading(true);
		setError(null);
		try {
			setOrganization(await client.organizations.get(current));
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
			setOrganization(null);
		} finally {
			setLoading(false);
		}
	};

	const update = async (
		body: UpdateOrgRequest,
	): Promise<OrganizationResponse | null> => {
		const current = id();
		if (!current || !client?.organizations) return null;
		setError(null);
		try {
			const updated = await client.organizations.update(current, body);
			setOrganization(updated);
			return updated;
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
			return null;
		}
	};

	void refetch();

	return { organization, loading, error, refetch, update };
}

/**
 * Headless hook for an organization's members + invitation creation.
 */
export function createMembers(orgId: Accessor<string | null | undefined>) {
	const { client } = useYAuth();
	const [members, setMembers] = createSignal<MembershipResponse[]>([]);
	const [loading, setLoading] = createSignal(false);
	const [error, setError] = createSignal<string | null>(null);

	const refetch = async () => {
		const current = orgId();
		if (!current) {
			setMembers([]);
			return;
		}
		if (!client?.organizations) {
			setError("Organizations feature is not enabled on this server.");
			return;
		}
		setLoading(true);
		setError(null);
		try {
			setMembers(await client.organizations.listMembers(current));
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
		} finally {
			setLoading(false);
		}
	};

	const invite = async (
		body: CreateInvitationRequest,
	): Promise<CreateInvitationResponse | null> => {
		const current = orgId();
		if (!current || !client?.organizations) return null;
		setError(null);
		try {
			return await client.organizations.createInvitation(current, body);
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
			return null;
		}
	};

	void refetch();

	return { members, loading, error, refetch, invite };
}

/**
 * Headless hook for accepting an invitation by token.
 * Stateless — caller invokes `accept` explicitly.
 */
export function createInvitation() {
	const { client } = useYAuth();
	const [submitting, setSubmitting] = createSignal(false);
	const [error, setError] = createSignal<string | null>(null);

	const accept = async (token: string): Promise<MembershipResponse | null> => {
		if (!client?.organizations) {
			setError("Organizations feature is not enabled on this server.");
			return null;
		}
		if (!token.trim()) {
			setError("Invitation token is required.");
			return null;
		}
		setSubmitting(true);
		setError(null);
		try {
			return await client.organizations.acceptInvitation({ token });
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
			return null;
		} finally {
			setSubmitting(false);
		}
	};

	return { submitting, error, accept };
}
