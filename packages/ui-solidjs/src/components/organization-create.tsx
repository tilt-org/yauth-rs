import type { OrganizationResponse } from "@yackey-labs/yauth-client";
import { type Component, createEffect, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import {
	createOrganizations,
	slugify,
} from "../hooks/create-organizations";

export interface OrganizationCreateProps {
	onSuccess?: (org: OrganizationResponse) => void;
	onError?: (error: Error) => void;
}

export const OrganizationCreate: Component<OrganizationCreateProps> = (
	props,
) => {
	const { create, error } = createOrganizations();

	const [name, setName] = createSignal("");
	const [displayName, setDisplayName] = createSignal("");
	const [slug, setSlug] = createSignal("");
	const [slugTouched, setSlugTouched] = createSignal(false);
	const [submitting, setSubmitting] = createSignal(false);

	createEffect(() => {
		const auto = slugify(name());
		if (!slugTouched()) {
			setSlug(auto);
		}
	});

	const onSlugInput = (e: InputEvent & { currentTarget: HTMLInputElement }) => {
		setSlugTouched(true);
		setSlug(slugify(e.currentTarget.value));
	};

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		if (!name().trim() || !slug().trim()) return;
		setSubmitting(true);
		const org = await create({
			name: name().trim(),
			slug: slug().trim(),
			display_name: displayName().trim() || undefined,
		});
		setSubmitting(false);
		if (org) {
			props.onSuccess?.(org);
			setName("");
			setDisplayName("");
			setSlug("");
			setSlugTouched(false);
		} else if (error()) {
			props.onError?.(new Error(error() as string));
		}
	};

	return (
		<form class="space-y-6" on:submit={handleSubmit}>
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
					for="yauth-org-create-name"
				>
					Organization name
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-org-create-name"
					name="name"
					type="text"
					value={name()}
					on:input={(e) => setName(e.currentTarget.value)}
					required
					maxlength={120}
					autocomplete="organization"
					disabled={submitting()}
				/>
			</div>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-org-create-slug"
				>
					Slug
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 font-mono text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-org-create-slug"
					name="slug"
					type="text"
					value={slug()}
					on:input={onSlugInput}
					required
					pattern="[a-z0-9-]+"
					maxlength={64}
					aria-describedby="yauth-org-create-slug-hint"
					disabled={submitting()}
				/>
				<p
					id="yauth-org-create-slug-hint"
					class="text-xs text-muted-foreground"
				>
					URL-safe identifier. Lowercase letters, numbers, and hyphens only.
				</p>
			</div>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-org-create-display-name"
				>
					Display name (optional)
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-org-create-display-name"
					name="display_name"
					type="text"
					value={displayName()}
					on:input={(e) => setDisplayName(e.currentTarget.value)}
					maxlength={120}
					disabled={submitting()}
				/>
			</div>

			<button
				class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
				type="submit"
				disabled={submitting() || !name().trim() || !slug().trim()}
			>
				{submitting() ? "Creating…" : "Create organization"}
			</button>
		</form>
	);
};
