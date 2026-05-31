import { type Component, createSignal, For } from "solid-js";
import { Show } from "solid-js/web";
import { isSafeRedirect } from "../safe-redirect";

export interface ConsentScreenProps {
	/** Human-readable client name; falls back to clientId. */
	clientName?: string;
	clientId?: string;
	/** Scope identifiers the client requested (from the consent payload). */
	scopes?: string[];
	/**
	 * Per-scope human-readable descriptions, keyed by scope name. Mirror your
	 * server's `mcpauth.Config.Scopes` catalog here so the consent screen shows
	 * plain language instead of raw scope strings. Scopes without an entry fall
	 * back to showing the raw identifier.
	 */
	scopeDescriptions?: Record<string, string>;
	/** Signed request id from the GET /oauth/authorize consent payload. */
	requestId: string;
	/** Signed CSRF token from the GET /oauth/authorize consent payload. */
	csrfToken: string;
	/** Auth API base URL (default "/api/auth"). */
	authBaseUrl?: string;
	/** Called after a decision is submitted and no redirect was returned. */
	onResult?: (approved: boolean) => void;
	/** Called on error. */
	onError?: (error: Error) => void;
}

/**
 * ConsentScreen renders the second half of the yauth oauth2-server
 * authorization-code flow. The first half — GET {authBaseUrl}/oauth/authorize
 * with the session cookie — returns a consent payload ({ request_id,
 * csrf_token, scopes, client }); pass those in as props (OAuthConsentPage does
 * this for you). On a decision it POSTs {authBaseUrl}/oauth2/consent with
 * { request_id, csrf_token, approved } and follows the returned redirect_url
 * back to the OAuth client.
 */
export const ConsentScreen: Component<ConsentScreenProps> = (props) => {
	const [loading, setLoading] = createSignal(false);
	const [error, setError] = createSignal<string | null>(null);

	const handleDecision = async (approved: boolean) => {
		setError(null);
		setLoading(true);
		try {
			const baseUrl = props.authBaseUrl ?? "/api/auth";
			const response = await fetch(`${baseUrl}/oauth2/consent`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				credentials: "include",
				body: JSON.stringify({
					request_id: props.requestId,
					csrf_token: props.csrfToken,
					approved,
				}),
			});

			const body = await response.json().catch(() => null);
			if (!response.ok) {
				throw new Error(
					body?.error_description ?? body?.error ?? "Authorization failed",
				);
			}
			// The server mints the code and returns the redirect URL (both on
			// approval and on denial, which carries error=access_denied).
			if (body?.redirect_url) {
				if (!isSafeRedirect(body.redirect_url)) {
					throw new Error("Blocked unsafe redirect target");
				}
				window.location.href = body.redirect_url;
				return;
			}
			props.onResult?.(approved);
		} catch (err) {
			const e = err instanceof Error ? err : new Error(String(err));
			setError(e.message);
			props.onError?.(e);
		} finally {
			setLoading(false);
		}
	};

	const displayName = () =>
		props.clientName ?? props.clientId ?? "An application";

	return (
		<div class="mx-auto max-w-md space-y-6 p-6">
			<div class="space-y-2 text-center">
				<h2 class="text-2xl font-semibold tracking-tight">
					Authorize {displayName()}
				</h2>
				<p class="text-sm text-muted-foreground">
					<strong>{displayName()}</strong> is requesting access to your account.
				</p>
			</div>

			<Show when={error()}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{error()}
				</div>
			</Show>

			<Show when={props.scopes && props.scopes.length > 0}>
				<div class="rounded-md border p-4 space-y-3">
					<p class="text-sm font-medium">
						This application is requesting the following permissions:
					</p>
					<ul class="space-y-2">
						<For each={props.scopes}>
							{(scope) => (
								<li class="flex items-start gap-2 text-sm">
									<svg
										class="mt-0.5 h-4 w-4 shrink-0 text-primary"
										fill="none"
										stroke="currentColor"
										viewBox="0 0 24 24"
										aria-label="Checkmark"
										role="img"
									>
										<path
											stroke-linecap="round"
											stroke-linejoin="round"
											stroke-width="2"
											d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
										/>
									</svg>
									<span>
										{props.scopeDescriptions?.[scope] ?? scope}
										<Show when={props.scopeDescriptions?.[scope]}>
											<code class="ml-1 text-xs text-muted-foreground">
												{scope}
											</code>
										</Show>
									</span>
								</li>
							)}
						</For>
					</ul>
				</div>
			</Show>

			<div class="flex gap-3">
				<button
					class="inline-flex h-9 flex-1 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
					type="button"
					disabled={loading()}
					onClick={() => handleDecision(false)}
				>
					Deny
				</button>
				<button
					class="inline-flex h-9 flex-1 cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
					type="button"
					disabled={loading()}
					onClick={() => handleDecision(true)}
				>
					{loading() ? "Authorizing..." : "Authorize"}
				</button>
			</div>

			<p class="text-center text-xs text-muted-foreground">
				By authorizing, you allow this application to access your account with
				the permissions listed above.
			</p>
		</div>
	);
};
