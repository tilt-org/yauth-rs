<script setup lang="ts">
/**
 * SSO connection list (issue #93, Phase B).
 *
 * Admin-side. Lists this org's federation connections, surfaces
 * status, and offers per-row test/enable/disable/delete actions.
 *
 * Renders nothing useful when the user isn't an org admin — the
 * underlying API enforces RBAC (see auth::rbac::require_org_admin).
 */
import { toRef } from "vue";
import { useSsoConnections } from "../composables/useSsoConnections";

const props = defineProps<{
	organizationId: string;
	onTest?: (id: string, ok: boolean, detail: string) => void;
}>();

const orgIdRef = toRef(props, "organizationId");
const { connections, loading, error, disable, enable, remove, test } =
	useSsoConnections(() => orgIdRef.value);

const handleTest = async (id: string) => {
	const r = await test(id);
	if (r) props.onTest?.(id, r.ok, r.detail);
};
</script>

<template>
	<div class="space-y-4">
		<div v-if="loading" class="text-sm text-muted-foreground">Loading…</div>
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
			role="alert"
		>
			{{ error }}
		</div>
		<div
			v-if="!loading && connections.length === 0"
			class="rounded-md border border-dashed px-4 py-6 text-center text-sm text-muted-foreground"
		>
			No SSO connections yet. Add one to enable federated sign-in for this
			organization.
		</div>
		<ul v-else class="space-y-3">
			<li
				v-for="c in connections"
				:key="c.id"
				class="rounded-md border bg-card p-4"
			>
				<div class="flex items-start justify-between gap-4">
					<div>
						<div class="font-medium">{{ c.name }}</div>
						<div class="text-xs text-muted-foreground">
							{{ c.kind }} ·
							<span
								:class="{
									'text-emerald-600': c.status === 'active',
									'text-amber-600': c.status === 'draft',
									'text-muted-foreground': c.status === 'disabled',
								}"
							>
								{{ c.status }}
							</span>
						</div>
						<div v-if="c.oidc" class="mt-1 text-xs text-muted-foreground">
							client_id: <code>{{ c.oidc.client_id }}</code>
						</div>
					</div>
					<div class="flex gap-2">
						<button
							type="button"
							class="rounded-md border px-3 py-1 text-xs"
							@click="handleTest(c.id)"
						>
							Test
						</button>
						<button
							v-if="c.status !== 'active'"
							type="button"
							class="rounded-md border px-3 py-1 text-xs"
							@click="enable(c.id)"
						>
							Enable
						</button>
						<button
							v-else
							type="button"
							class="rounded-md border px-3 py-1 text-xs"
							@click="disable(c.id)"
						>
							Disable
						</button>
						<button
							type="button"
							class="rounded-md border border-destructive px-3 py-1 text-xs text-destructive"
							@click="remove(c.id)"
						>
							Delete
						</button>
					</div>
				</div>
			</li>
		</ul>
	</div>
</template>
