import type { CreateInvitationResponse } from "@yackey-labs/yauth-client";
import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { createMembers } from "../hooks/create-organizations";

export interface InviteFormProps {
	organizationId: string;
	onSuccess?: (result: CreateInvitationResponse) => void;
	onError?: (error: Error) => void;
}

const isEmail = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

export const InviteForm: Component<InviteFormProps> = (props) => {
	const { invite, error } = createMembers(() => props.organizationId);

	const [email, setEmail] = createSignal("");
	const [role, setRole] = createSignal("member");
	const [submitting, setSubmitting] = createSignal(false);
	const [lastToken, setLastToken] = createSignal<string | null>(null);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		const trimmed = email().trim();
		if (!isEmail(trimmed)) return;
		setSubmitting(true);
		const result = await invite({ email: trimmed, role: role() });
		setSubmitting(false);
		if (result) {
			setLastToken(result.token);
			setEmail("");
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

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-invite-email"
				>
					Email
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-invite-email"
					name="email"
					type="email"
					value={email()}
					on:input={(e) => setEmail(e.currentTarget.value)}
					required
					autocomplete="email"
					disabled={submitting()}
				/>
			</div>

			<div class="space-y-2">
				<label class="text-sm font-medium leading-none" for="yauth-invite-role">
					Role
				</label>
				<select
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-invite-role"
					name="role"
					value={role()}
					on:change={(e) => setRole(e.currentTarget.value)}
					disabled={submitting()}
				>
					<option value="member">Member</option>
					<option value="admin">Admin</option>
				</select>
			</div>

			<button
				class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
				type="submit"
				disabled={submitting() || !isEmail(email().trim())}
			>
				{submitting() ? "Sending…" : "Send invitation"}
			</button>

			<Show when={lastToken()}>
				<div class="rounded-md border border-input bg-muted/40 p-3">
					<p class="text-xs text-muted-foreground">
						Invitation created. Deliver this token to the invitee — it will
						not be shown again.
					</p>
					<code class="mt-2 block break-all font-mono text-xs">
						{lastToken()}
					</code>
				</div>
			</Show>
		</form>
	);
};
