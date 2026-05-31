import { type Component, createResource, Show } from "solid-js";
import { ConsentScreen } from "./consent-screen";
import { isSafeRedirect } from "../safe-redirect";

export interface OAuthConsentPageProps {
	/** Auth API base URL (default "/api/auth"). */
	authBaseUrl?: string;
	/**
	 * Where to send an unauthenticated user. The current URL (authorize request
	 * + query) is appended as `redirect_to` so the flow resumes after login.
	 * Default "/login".
	 */
	loginPath?: string;
	/**
	 * Per-scope descriptions, keyed by scope name — mirror your server's
	 * `mcpauth.Config.Scopes` catalog so users see plain language.
	 */
	scopeDescriptions?: Record<string, string>;
}

/**
 * The consent payload from GET /oauth/authorize. The two yauth servers spell it
 * slightly differently — yauth-go nests `client` and returns a `scopes` array;
 * Rust yauth returns flat `client_id`/`client_name` and a space-delimited
 * `scope` string — so both shapes are optional here and normalized below.
 */
interface ConsentPayload {
	client?: { id: string; name?: string };
	client_id?: string;
	client_name?: string;
	scopes?: string[];
	scope?: string;
	csrf_token: string;
	request_id: string;
	redirect_url?: string;
}

const clientIdOf = (p: ConsentPayload) => p.client?.id ?? p.client_id;
const clientNameOf = (p: ConsentPayload) => p.client?.name ?? p.client_name;
const scopesOf = (p: ConsentPayload): string[] =>
	Array.isArray(p.scopes)
		? p.scopes
		: typeof p.scope === "string" && p.scope.length > 0
			? p.scope.split(/\s+/)
			: [];

/**
 * OAuthConsentPage is a drop-in route for the SPA path you advertise as the
 * authorization endpoint (e.g. "/authorize" — what `mcpauth.Mount` rewrites
 * authorization_endpoint to). Mount it at that route and it handles the whole
 * browser side of the yauth oauth2-server flow:
 *
 *   1. GET {authBaseUrl}/oauth/authorize{window.location.search} with the
 *      session cookie.
 *   2. 401 -> redirect to {loginPath}?redirect_to=<this URL> so the user logs
 *      in and comes back.
 *   3. { redirect_url } (consent already granted) -> follow it.
 *   4. consent payload -> render <ConsentScreen> with the signed request_id +
 *      csrf_token.
 *
 * Example (@solidjs/router):
 *
 *   <Route path="/authorize" component={() =>
 *     <OAuthConsentPage scopeDescriptions={SCOPES} />} />
 */
export const OAuthConsentPage: Component<OAuthConsentPageProps> = (props) => {
	const baseUrl = () => props.authBaseUrl ?? "/api/auth";

	const [payload] = createResource<ConsentPayload | null>(async () => {
		const here = window.location.pathname + window.location.search;
		const res = await fetch(`${baseUrl()}/oauth/authorize${window.location.search}`, {
			method: "GET",
			credentials: "include",
			headers: { Accept: "application/json" },
		});

		if (res.status === 401) {
			const loginPath = props.loginPath ?? "/login";
			window.location.href = `${loginPath}?redirect_to=${encodeURIComponent(here)}`;
			return null;
		}

		const body = (await res.json().catch(() => null)) as ConsentPayload | null;
		if (!res.ok) {
			throw new Error(
				(body as { error_description?: string; error?: string } | null)
					?.error_description ??
					(body as { error?: string } | null)?.error ??
					"Failed to start authorization",
			);
		}
		// Consent already on file: the server returns the redirect directly.
		if (body?.redirect_url) {
			if (!isSafeRedirect(body.redirect_url)) {
				throw new Error("Blocked unsafe redirect target");
			}
			window.location.href = body.redirect_url;
			return null;
		}
		return body;
	});

	return (
		<Show
			when={payload()}
			fallback={
				<Show when={payload.error}>
					<div class="mx-auto max-w-md p-6 text-sm text-destructive">
						{(payload.error as Error)?.message ?? "Authorization error"}
					</div>
				</Show>
			}
		>
			{(p) => (
				<ConsentScreen
					authBaseUrl={baseUrl()}
					clientId={clientIdOf(p())}
					clientName={clientNameOf(p())}
					scopes={scopesOf(p())}
					scopeDescriptions={props.scopeDescriptions}
					requestId={p().request_id}
					csrfToken={p().csrf_token}
				/>
			)}
		</Show>
	);
};
