import type { OrganizationJSON as OrganizationResponse } from "@yackey-labs/yauth-client";
import type { Component } from "solid-js";
import { Show } from "solid-js/web";

export interface OrganizationCardProps {
	organization: OrganizationResponse;
	role?: string | null;
	memberCount?: number | null;
	onSelect?: (org: OrganizationResponse) => void;
}

export const OrganizationCard: Component<OrganizationCardProps> = (props) => {
	return (
		<button
			class="flex w-full items-start justify-between gap-4 rounded-md border border-input bg-card px-4 py-3 text-left text-card-foreground shadow-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
			type="button"
			on:click={() => props.onSelect?.(props.organization)}
		>
			<div class="min-w-0 flex-1">
				<div class="flex items-center gap-2">
					<span class="truncate text-sm font-medium">
						{props.organization.display_name || props.organization.name}
					</span>
					<Show when={props.role}>
						<span class="rounded-full bg-secondary px-2 py-0.5 text-xs font-medium text-secondary-foreground">
							{props.role}
						</span>
					</Show>
				</div>
				<div class="mt-1 truncate text-xs text-muted-foreground">
					@{props.organization.slug}
				</div>
			</div>
			<Show
				when={
					props.memberCount !== null && props.memberCount !== undefined
				}
			>
				<div class="shrink-0 text-xs text-muted-foreground">
					{props.memberCount} {props.memberCount === 1 ? "member" : "members"}
				</div>
			</Show>
		</button>
	);
};
