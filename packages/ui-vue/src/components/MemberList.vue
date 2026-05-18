<script setup lang="ts">
import { toRef } from "vue";
import { useMembers } from "../composables/useOrganizations";

const props = defineProps<{
	organizationId: string;
}>();

const orgIdRef = toRef(props, "organizationId");
const { members, loading, error } = useMembers(() => orgIdRef.value);

const formatDate = (iso: string | null | undefined): string => {
	if (!iso) return "—";
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString();
};
</script>

<template>
	<div class="space-y-3">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
			role="alert"
			aria-live="polite"
		>
			{{ error }}
		</div>

		<div
			v-if="loading && members.length === 0"
			class="text-sm text-muted-foreground"
		>
			Loading members…
		</div>

		<table
			v-else-if="members.length > 0"
			class="w-full text-sm"
			aria-label="Organization members"
		>
			<thead>
				<tr class="border-b border-input text-left text-xs font-medium text-muted-foreground">
					<th scope="col" class="py-2 pr-4">User</th>
					<th scope="col" class="py-2 pr-4">Role</th>
					<th scope="col" class="py-2 pr-4">Status</th>
					<th scope="col" class="py-2 pr-4">Joined</th>
				</tr>
			</thead>
			<tbody>
				<tr
					v-for="m in members"
					:key="m.id"
					class="border-b border-input/40"
				>
					<td class="py-2 pr-4 font-mono text-xs">
						{{ m.user_id }}
					</td>
					<td class="py-2 pr-4">
						<span
							class="inline-flex items-center rounded-full bg-secondary px-2 py-0.5 text-xs font-medium text-secondary-foreground"
						>
							{{ m.role }}
						</span>
					</td>
					<td class="py-2 pr-4 text-xs text-muted-foreground">
						{{ m.status }}
					</td>
					<td class="py-2 pr-4 text-xs text-muted-foreground">
						{{ formatDate(m.joined_at) }}
					</td>
				</tr>
			</tbody>
		</table>

		<div
			v-else
			class="rounded-md border border-dashed border-input px-4 py-6 text-center text-sm text-muted-foreground"
		>
			No members yet.
		</div>
	</div>
</template>
