import type { MembershipJSON as MembershipResponse } from "@yackey-labs/yauth-client";
import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { createInvitation } from "../hooks/create-organizations";

export interface InvitationAcceptProps {
	/** Pre-fill the token (e.g. from a query string). */
	token?: string;
	onSuccess?: (membership: MembershipResponse) => void;
	onError?: (error: Error) => void;
}

export const InvitationAccept: Component<InvitationAcceptProps> = (props) => {
	const { accept, submitting, error } = createInvitation();
	const [token, setToken] = createSignal(props.token ?? "");
	const [accepted, setAccepted] = createSignal<MembershipResponse | null>(null);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		const result = await accept(token().trim());
		if (result) {
			setAccepted(result);
			props.onSuccess?.(result);
		} else if (error()) {
			props.onError?.(new Error(error() as string));
		}
	};

	return (
		<form class="space-y-4" on:submit={handleSubmit}>
			<Show when={error()}>
				<div
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
					role="alert"
					aria-live="polite"
				>
					{error()}
				</div>
			</Show>

			<Show when={accepted()}>
				<div
					class="rounded-md bg-primary/10 px-3 py-2 text-sm"
					role="status"
					aria-live="polite"
				>
					Invitation accepted. Welcome to the organization!
				</div>
			</Show>

			<Show when={!accepted()}>
				<div class="space-y-2">
					<label
						class="text-sm font-medium leading-none"
						for="yauth-invitation-accept-token"
					>
						Invitation token
					</label>
					<input
						class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 font-mono text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
						id="yauth-invitation-accept-token"
						name="token"
						type="text"
						value={token()}
						on:input={(e) => setToken(e.currentTarget.value)}
						required
						autocomplete="off"
						disabled={submitting()}
					/>
				</div>

				<button
					class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
					type="submit"
					disabled={submitting() || !token().trim()}
				>
					{submitting() ? "Accepting…" : "Accept invitation"}
				</button>
			</Show>
		</form>
	);
};
