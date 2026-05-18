import { type Component, For, Show, createSignal } from "solid-js";
import {
	ROLES,
	createMembers,
	createOrgPermissions,
	createOrgRoles,
} from "../hooks/create-organizations";
import { RoleSelector } from "./role-selector";

export interface MemberListProps {
	organizationId: string;
}

const formatDate = (iso: string | null | undefined): string => {
	if (!iso) return "—";
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString();
};

/**
 * Tailwind badge class for a built-in role. Custom strings render as
 * the default secondary badge.
 */
const roleBadgeClass = (role: string): string => {
	switch (role) {
		case ROLES.OWNER:
			return "bg-amber-500/15 text-amber-700 dark:text-amber-300";
		case ROLES.ADMIN:
			return "bg-blue-500/15 text-blue-700 dark:text-blue-300";
		case ROLES.BILLING_ADMIN:
			return "bg-purple-500/15 text-purple-700 dark:text-purple-300";
		case ROLES.MEMBER:
			return "bg-secondary text-secondary-foreground";
		case ROLES.VIEWER:
			return "bg-muted text-muted-foreground";
		default:
			return "bg-secondary text-secondary-foreground";
	}
};

export const MemberList: Component<MemberListProps> = (props) => {
	const { members, loading, error, refetch } = createMembers(
		() => props.organizationId,
	);
	const { hasPermission } = createOrgPermissions(() => props.organizationId);
	const {
		submitting,
		error: actionError,
		changeRole,
		removeMember,
	} = createOrgRoles(() => props.organizationId);

	const [editingUserId, setEditingUserId] = createSignal<string | null>(null);
	const [editingRole, setEditingRole] = createSignal("");

	const startEdit = (userId: string, role: string) => {
		setEditingUserId(userId);
		setEditingRole(role);
	};

	const cancelEdit = () => {
		setEditingUserId(null);
		setEditingRole("");
	};

	const saveRole = async (userId: string) => {
		const updated = await changeRole(userId, { role: editingRole() });
		if (updated) {
			await refetch();
			cancelEdit();
		}
	};

	const doRemove = async (userId: string) => {
		if (!confirm("Remove this member from the organization?")) return;
		const ok = await removeMember(userId);
		if (ok) await refetch();
	};

	const showActions = () =>
		hasPermission("members:change_role") || hasPermission("members:remove");

	return (
		<div class="space-y-3">
			<Show when={error() || actionError()}>
				<div
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
					role="alert"
					aria-live="polite"
				>
					{error() || actionError()}
				</div>
			</Show>

			<Show when={loading() && members().length === 0}>
				<div class="text-sm text-muted-foreground">Loading members…</div>
			</Show>

			<Show when={members().length > 0}>
				<table class="w-full text-sm" aria-label="Organization members">
					<thead>
						<tr class="border-b border-input text-left text-xs font-medium text-muted-foreground">
							<th scope="col" class="py-2 pr-4">User</th>
							<th scope="col" class="py-2 pr-4">Role</th>
							<th scope="col" class="py-2 pr-4">Status</th>
							<th scope="col" class="py-2 pr-4">Joined</th>
							<Show when={showActions()}>
								<th scope="col" class="py-2 pr-4 text-right">Actions</th>
							</Show>
						</tr>
					</thead>
					<tbody>
						<For each={members()}>
							{(m) => (
								<tr class="border-b border-input/40">
									<td class="py-2 pr-4 font-mono text-xs">{m.user_id}</td>
									<td class="py-2 pr-4">
										<Show
											when={editingUserId() !== m.user_id}
											fallback={
												<RoleSelector
													value={editingRole()}
													disabled={submitting()}
													onChange={setEditingRole}
												/>
											}
										>
											<span
												class={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${roleBadgeClass(m.role)}`}
											>
												{m.role}
											</span>
										</Show>
									</td>
									<td class="py-2 pr-4 text-xs text-muted-foreground">
										{m.status}
									</td>
									<td class="py-2 pr-4 text-xs text-muted-foreground">
										{formatDate(m.joined_at)}
									</td>
									<Show when={showActions()}>
										<td class="py-2 pr-4 text-right">
											<div class="inline-flex gap-2">
												<Show
													when={editingUserId() === m.user_id}
													fallback={
														<>
															<Show
																when={
																	hasPermission("members:change_role") &&
																	m.role !== ROLES.OWNER
																}
															>
																<button
																	type="button"
																	class="rounded-md border border-input px-2 py-1 text-xs hover:bg-secondary"
																	onClick={() => startEdit(m.user_id, m.role)}
																>
																	Change role
																</button>
															</Show>
															<Show
																when={
																	hasPermission("members:remove") &&
																	m.role !== ROLES.OWNER
																}
															>
																<button
																	type="button"
																	class="rounded-md border border-destructive/40 px-2 py-1 text-xs text-destructive hover:bg-destructive/10"
																	disabled={submitting()}
																	onClick={() => doRemove(m.user_id)}
																>
																	Remove
																</button>
															</Show>
														</>
													}
												>
													<button
														type="button"
														class="rounded-md bg-primary px-2 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
														disabled={submitting()}
														onClick={() => saveRole(m.user_id)}
													>
														Save
													</button>
													<button
														type="button"
														class="rounded-md border border-input px-2 py-1 text-xs hover:bg-secondary"
														disabled={submitting()}
														onClick={cancelEdit}
													>
														Cancel
													</button>
												</Show>
											</div>
										</td>
									</Show>
								</tr>
							)}
						</For>
					</tbody>
				</table>
			</Show>

			<Show when={!loading() && members().length === 0}>
				<div class="rounded-md border border-dashed border-input px-4 py-6 text-center text-sm text-muted-foreground">
					No members yet.
				</div>
			</Show>
		</div>
	);
};
