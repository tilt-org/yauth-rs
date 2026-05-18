import type { OrganizationResponse } from "@yackey-labs/yauth-client";
import { type Component, createSignal, For, onCleanup } from "solid-js";
import { Show } from "solid-js/web";
import { createOrganizations } from "../hooks/create-organizations";

export interface OrganizationSwitcherProps {
	activeId?: string | null;
	onSwitch?: (org: OrganizationResponse) => void;
}

/**
 * UI scaffold for an organization-switcher dropdown.
 *
 * Visual shell only. "Active organization" state (server-side session claim,
 * persisted selection, scoping API calls) ships in issue #89.
 */
export const OrganizationSwitcher: Component<OrganizationSwitcherProps> = (
	props,
) => {
	const { organizations, loading } = createOrganizations();
	const [open, setOpen] = createSignal(false);
	let containerEl: HTMLDivElement | undefined;

	const activeOrg = () =>
		organizations().find((o) => o.id === props.activeId) ?? null;

	const handleClickOutside = (e: MouseEvent) => {
		if (!containerEl) return;
		if (!containerEl.contains(e.target as Node)) {
			setOpen(false);
			document.removeEventListener("mousedown", handleClickOutside);
		}
	};

	const toggle = () => {
		const next = !open();
		setOpen(next);
		if (next) {
			document.addEventListener("mousedown", handleClickOutside);
		} else {
			document.removeEventListener("mousedown", handleClickOutside);
		}
	};

	const choose = (org: OrganizationResponse) => {
		setOpen(false);
		document.removeEventListener("mousedown", handleClickOutside);
		props.onSwitch?.(org);
	};

	onCleanup(() => {
		document.removeEventListener("mousedown", handleClickOutside);
	});

	return (
		<div
			ref={containerEl}
			class="relative inline-block w-full"
		>
			<button
				class="inline-flex h-9 w-full cursor-pointer items-center justify-between gap-2 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
				type="button"
				aria-expanded={open()}
				aria-haspopup="listbox"
				aria-label="Switch organization"
				disabled={loading() && organizations().length === 0}
				on:click={toggle}
			>
				<span class="truncate">
					{activeOrg()?.display_name ||
						activeOrg()?.name ||
						(loading() ? "Loading…" : "Select organization")}
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

			<Show when={open()}>
				<div
					class="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-md border border-input bg-popover text-popover-foreground shadow-md"
					role="listbox"
				>
					<For each={organizations()}>
						{(org) => (
							<button
								class="flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
								type="button"
								role="option"
								aria-selected={org.id === props.activeId}
								on:click={() => choose(org)}
							>
								<div class="min-w-0 flex-1">
									<div class="truncate font-medium">
										{org.display_name || org.name}
									</div>
									<div class="truncate font-mono text-xs text-muted-foreground">
										@{org.slug}
									</div>
								</div>
								<Show when={org.id === props.activeId}>
									<svg
										class="h-4 w-4 shrink-0"
										viewBox="0 0 24 24"
										fill="none"
										stroke="currentColor"
										stroke-width="2"
										aria-hidden="true"
									>
										<polyline points="20 6 9 17 4 12" />
									</svg>
								</Show>
							</button>
						)}
					</For>
					<Show when={organizations().length === 0}>
						<div class="px-3 py-2 text-sm text-muted-foreground">
							No organizations.
						</div>
					</Show>
				</div>
			</Show>
		</div>
	);
};
