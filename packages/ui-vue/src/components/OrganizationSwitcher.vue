<script setup lang="ts">
import type { OrganizationResponse } from "@yackey-labs/yauth-client";
import { onBeforeUnmount, ref } from "vue";
import { useOrganizations } from "../composables/useOrganizations";

/**
 * UI scaffold for an organization-switcher dropdown.
 *
 * This component owns only the visual shell — list + click handler. The
 * "active organization" concept (server-side session claim, persisted
 * selection, scoping API calls) lives in issue #89. Callers wire `activeId`
 * + `onSwitch` into whatever active-org state they maintain externally.
 */
const props = defineProps<{
	activeId?: string | null;
	onSwitch?: (org: OrganizationResponse) => void;
}>();

const { organizations, loading } = useOrganizations();
const open = ref(false);
const containerRef = ref<HTMLElement | null>(null);

const activeOrg = () =>
	organizations.value.find((o) => o.id === props.activeId) ?? null;

const handleClickOutside = (e: MouseEvent) => {
	if (!containerRef.value) return;
	if (!containerRef.value.contains(e.target as Node)) {
		open.value = false;
	}
};

const toggle = () => {
	open.value = !open.value;
	if (open.value) {
		document.addEventListener("mousedown", handleClickOutside);
	} else {
		document.removeEventListener("mousedown", handleClickOutside);
	}
};

const choose = (org: OrganizationResponse) => {
	open.value = false;
	document.removeEventListener("mousedown", handleClickOutside);
	props.onSwitch?.(org);
};

onBeforeUnmount(() => {
	document.removeEventListener("mousedown", handleClickOutside);
});
</script>

<template>
	<div ref="containerRef" class="relative inline-block w-full">
		<button
			class="inline-flex h-9 w-full cursor-pointer items-center justify-between gap-2 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
			type="button"
			:aria-expanded="open"
			aria-haspopup="listbox"
			aria-label="Switch organization"
			:disabled="loading && organizations.length === 0"
			@click="toggle"
		>
			<span class="truncate">
				{{
					activeOrg()?.display_name ||
					activeOrg()?.name ||
					(loading ? "Loading…" : "Select organization")
				}}
			</span>
			<svg
				class="h-4 w-4 shrink-0 opacity-50"
				viewBox="0 0 24 24"
				fill="none"
				stroke="currentColor"
				stroke-width="2"
				aria-hidden="true"
			>
				<polyline points="6 9 12 15 18 9" />
			</svg>
		</button>

		<div
			v-if="open"
			class="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-md border border-input bg-popover text-popover-foreground shadow-md"
			role="listbox"
		>
			<button
				v-for="org in organizations"
				:key="org.id"
				class="flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
				type="button"
				role="option"
				:aria-selected="org.id === activeId"
				@click="choose(org)"
			>
				<div class="min-w-0 flex-1">
					<div class="truncate font-medium">
						{{ org.display_name || org.name }}
					</div>
					<div class="truncate font-mono text-xs text-muted-foreground">
						@{{ org.slug }}
					</div>
				</div>
				<svg
					v-if="org.id === activeId"
					class="h-4 w-4 shrink-0"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					aria-hidden="true"
				>
					<polyline points="20 6 9 17 4 12" />
				</svg>
			</button>
			<div
				v-if="organizations.length === 0"
				class="px-3 py-2 text-sm text-muted-foreground"
			>
				No organizations.
			</div>
		</div>
	</div>
</template>
