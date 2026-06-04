import { For, Show, createMemo } from "solid-js";
import { createAuditDestinations } from "../hooks/create-audit-destinations";

/**
 * Audit-export admin destinations list (issue #96).
 *
 * Mirror of the Vue component — shows deployment-wide OR per-org
 * destinations with their sanitized kind JSON, status badge, and
 * last_success_at / last_failure_at timestamps. No secrets are ever
 * displayed (the server strips `hmac_secret`, `hec_token`, Datadog
 * `api_key` before returning).
 */
export interface AuditDestinationListProps {
	/**
	 * `null` => deployment-wide destinations. A UUID string => per-org
	 * destinations for that org.
	 */
	organizationId?: string | null;
}

function fmtDate(s: string | null | undefined): string {
	if (!s) return "—";
	try {
		return new Date(s).toLocaleString();
	} catch {
		return s;
	}
}

export function AuditDestinationList(props: AuditDestinationListProps) {
	const scope = createMemo(() => props.organizationId ?? null);
	const { destinations, loading, error, disable, remove, submitting, refresh } =
		createAuditDestinations(() => scope());

	return (
		<section class="space-y-4">
			<header class="flex items-center justify-between">
				<h2 class="text-lg font-semibold">
					{props.organizationId
						? "Per-org SIEM destinations"
						: "Deployment-wide SIEM destinations"}
				</h2>
				<button
					type="button"
					class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-transparent px-3 text-xs font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-50"
					disabled={loading() || submitting()}
					onClick={() => void refresh()}
				>
					Refresh
				</button>
			</header>

			<Show when={error()}>
				<div
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
					role="alert"
					aria-live="polite"
				>
					{error()}
				</div>
			</Show>

			<Show when={loading()}>
				<p class="text-sm text-muted-foreground">Loading…</p>
			</Show>

			<Show
				when={!loading() && destinations().length > 0}
				fallback={
					<Show when={!loading()}>
						<p class="text-sm text-muted-foreground">
							No destinations configured. Use the “Add destination” form below.
						</p>
					</Show>
				}
			>
				<ul class="divide-y divide-border">
					<For each={destinations()}>
						{(d) => (
							<li class="flex items-start justify-between gap-3 py-3">
								<div class="min-w-0 flex-1 space-y-1">
									<div class="flex flex-wrap items-center gap-2">
										<span class="font-medium">{d.name}</span>
										<span class="rounded-full bg-muted px-2 py-0.5 text-xs uppercase text-muted-foreground">
											{d.kind}
										</span>
										<span
											classList={{
												"rounded-full px-2 py-0.5 text-xs": true,
												"bg-emerald-500/10 text-emerald-700":
													d.status === "active",
												"bg-muted text-muted-foreground":
													d.status === "disabled",
											}}
										>
											{d.status}
										</span>
									</div>
									<pre class="overflow-x-auto rounded-md bg-muted/50 p-2 text-xs leading-snug">
										{JSON.stringify(d.config, null, 2)}
									</pre>
									<p class="text-xs text-muted-foreground">
										Last success: {fmtDate(d.last_success_at)} · Last failure:{" "}
										{fmtDate(d.last_failure_at)}
									</p>
								</div>
								<div class="flex flex-col gap-2">
									<Show when={d.status === "active"}>
										<button
											type="button"
											class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-transparent px-3 text-xs font-medium shadow-sm hover:bg-accent disabled:pointer-events-none disabled:opacity-50"
											disabled={submitting()}
											onClick={() => void disable(d.id)}
										>
											Disable
										</button>
									</Show>
									<button
										type="button"
										class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-destructive bg-transparent px-3 text-xs font-medium text-destructive shadow-sm hover:bg-destructive/10 disabled:pointer-events-none disabled:opacity-50"
										disabled={submitting()}
										onClick={() => void remove(d.id)}
									>
										Delete
									</button>
								</div>
							</li>
						)}
					</For>
				</ul>
			</Show>
		</section>
	);
}
