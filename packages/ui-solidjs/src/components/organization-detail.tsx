import type { Component } from "solid-js";
import { Show } from "solid-js/web";
import { createOrganization } from "../hooks/create-organizations";
import { InviteForm } from "./invite-form";
import { MemberList } from "./member-list";

export interface OrganizationDetailProps {
	organizationId: string;
	/** When false, hide the invite form section. */
	canInvite?: boolean;
}

export const OrganizationDetail: Component<OrganizationDetailProps> = (
	props,
) => {
	const { organization, loading, error } = createOrganization(
		() => props.organizationId,
	);

	return (
		<section class="space-y-6">
			<Show when={error()}>
				<div
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
					role="alert"
					aria-live="polite"
				>
					{error()}
				</div>
			</Show>

			<Show when={loading() && !organization()}>
				<div class="text-sm text-muted-foreground">Loading organization…</div>
			</Show>

			<Show when={organization()}>
				{(org) => (
					<>
						<div class="space-y-2">
							<h2 class="text-lg font-semibold">
								{org().display_name || org().name}
							</h2>
							<p class="font-mono text-xs text-muted-foreground">
								@{org().slug}
							</p>
						</div>

						<div class="space-y-3">
							<h3 class="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
								Members
							</h3>
							<MemberList organizationId={org().id} />
						</div>

						<Show when={props.canInvite !== false}>
							<div class="space-y-3">
								<h3 class="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
									Invite a member
								</h3>
								<InviteForm organizationId={org().id} />
							</div>
						</Show>
					</>
				)}
			</Show>
		</section>
	);
};
