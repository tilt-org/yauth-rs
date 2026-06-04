import type { OrganizationJSON as OrganizationResponse } from "@yackey-labs/yauth-client";
import { type Component, For } from "solid-js";
import { Show } from "solid-js/web";
import { createOrganizations } from "../hooks/create-organizations";
import { OrganizationCard } from "./organization-card";

export interface OrganizationListProps {
	onSelect?: (org: OrganizationResponse) => void;
}

export const OrganizationList: Component<OrganizationListProps> = (props) => {
	const { organizations, loading, error } = createOrganizations();

	return (
		<div class="space-y-3">
			<Show when={error()}>
				<div
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
					role="alert"
					aria-live="polite"
				>
					{error()}
				</div>
			</Show>

			<Show when={loading() && organizations().length === 0}>
				<div class="text-sm text-muted-foreground">
					Loading organizations…
				</div>
			</Show>

			<Show when={!loading() && organizations().length === 0}>
				<div class="rounded-md border border-dashed border-input px-4 py-6 text-center text-sm text-muted-foreground">
					You're not in any organizations yet.
				</div>
			</Show>

			<Show when={organizations().length > 0}>
				<ul class="space-y-2">
					<For each={organizations()}>
						{(org) => (
							<li>
								<OrganizationCard
									organization={org}
									onSelect={props.onSelect}
								/>
							</li>
						)}
					</For>
				</ul>
			</Show>
		</div>
	);
};
