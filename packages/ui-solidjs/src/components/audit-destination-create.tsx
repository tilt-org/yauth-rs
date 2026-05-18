import { Show, createSignal } from "solid-js";
import {
	type CreateDestinationInput,
	createAuditDestinations,
} from "../hooks/create-audit-destinations";

/**
 * Audit-export admin add-destination form (issue #96).
 *
 * Mirror of the Vue component — kind switcher (webhook / syslog / s3 /
 * splunk / datadog), per-kind fields, and an HMAC secret password input
 * for webhooks with a pointer to the docs verifier helper.
 *
 * Splunk + Datadog branches still warn the user that they're "follow-up";
 * the warnings stay so the wire-shape feedback is unambiguous if the
 * operator picks them in a version of yauth that pre-dates Phase B. The
 * dispatcher itself does the real round-trip in Phase B.
 */
export interface AuditDestinationCreateProps {
	organizationId?: string | null;
	onCreated?: () => void;
}

export function AuditDestinationCreate(props: AuditDestinationCreateProps) {
	const { create, submitting, error } = createAuditDestinations(
		() => props.organizationId ?? null,
	);

	const [kindTag, setKindTag] = createSignal<
		"webhook" | "syslog" | "s3" | "splunk" | "datadog"
	>("webhook");
	const [name, setName] = createSignal("");

	// Webhook
	const [webhookUrl, setWebhookUrl] = createSignal("");
	const [webhookFormat, setWebhookFormat] = createSignal<
		"json" | "cef" | "rfc5424"
	>("json");
	const [webhookHmac, setWebhookHmac] = createSignal("");

	// Syslog
	const [syslogHost, setSyslogHost] = createSignal("");
	const [syslogPort, setSyslogPort] = createSignal(6514);
	const [syslogTransport, setSyslogTransport] = createSignal<
		"tcp" | "udp" | "tls"
	>("tcp");
	const [syslogFacility, setSyslogFacility] = createSignal(13);

	// S3
	const [s3Bucket, setS3Bucket] = createSignal("");
	const [s3Prefix, setS3Prefix] = createSignal("audit");
	const [s3Region, setS3Region] = createSignal("us-east-1");
	const [s3Partition, setS3Partition] = createSignal<
		"by_date" | "by_org" | "by_date_and_org"
	>("by_date");

	// Splunk
	const [splunkHecUrl, setSplunkHecUrl] = createSignal("");
	const [splunkHecToken, setSplunkHecToken] = createSignal("");

	// Datadog
	const [ddSite, setDdSite] = createSignal("datadoghq.com");
	const [ddApiKey, setDdApiKey] = createSignal("");

	const handleSubmit = async (e: Event) => {
		e.preventDefault();
		let kind: CreateDestinationInput["kind"];
		switch (kindTag()) {
			case "webhook":
				kind = {
					type: "webhook",
					url: webhookUrl().trim(),
					format: webhookFormat(),
					hmac_secret: webhookHmac().trim() || undefined,
				};
				break;
			case "syslog":
				kind = {
					type: "syslog",
					host: syslogHost().trim(),
					port: syslogPort(),
					transport: syslogTransport(),
					facility: syslogFacility(),
				};
				break;
			case "s3":
				kind = {
					type: "s3",
					bucket: s3Bucket().trim(),
					prefix: s3Prefix().trim(),
					region: s3Region().trim(),
					partition: s3Partition(),
				};
				break;
			case "splunk":
				kind = {
					type: "splunk",
					hec_url: splunkHecUrl().trim(),
					hec_token: splunkHecToken().trim(),
				};
				break;
			case "datadog":
				kind = {
					type: "datadog",
					site: ddSite().trim(),
					api_key: ddApiKey().trim(),
				};
				break;
		}
		const created = await create({
			name: name().trim(),
			organization_id: props.organizationId ?? null,
			kind,
		});
		if (created) {
			props.onCreated?.();
			setName("");
			setWebhookUrl("");
			setWebhookHmac("");
			setSyslogHost("");
			setS3Bucket("");
			setSplunkHecUrl("");
			setSplunkHecToken("");
			setDdApiKey("");
		}
	};

	return (
		<form
			class="space-y-3 rounded-md border border-border p-4"
			onSubmit={handleSubmit}
		>
			<h3 class="text-base font-semibold">Add destination</h3>

			<Show when={error()}>
				<div
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
					role="alert"
					aria-live="polite"
				>
					{error()}
				</div>
			</Show>

			<label class="block">
				<span class="text-xs font-medium">Name</span>
				<input
					type="text"
					required
					value={name()}
					onInput={(e) => setName(e.currentTarget.value)}
					class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
				/>
			</label>

			<label class="block">
				<span class="text-xs font-medium">Kind</span>
				<select
					value={kindTag()}
					onChange={(e) =>
						setKindTag(
							e.currentTarget.value as
								| "webhook"
								| "syslog"
								| "s3"
								| "splunk"
								| "datadog",
						)
					}
					class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
				>
					<option value="webhook">Webhook (HTTPS POST)</option>
					<option value="syslog">Syslog (RFC 5424)</option>
					<option value="s3">S3-compatible object storage</option>
					<option value="splunk">Splunk HEC</option>
					<option value="datadog">Datadog logs</option>
				</select>
			</label>

			<Show when={kindTag() === "webhook"}>
				<fieldset class="space-y-2">
					<label class="block">
						<span class="text-xs font-medium">URL</span>
						<input
							type="url"
							required
							placeholder="https://hooks.example.com/yauth-audit"
							value={webhookUrl()}
							onInput={(e) => setWebhookUrl(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
					<label class="block">
						<span class="text-xs font-medium">Format</span>
						<select
							value={webhookFormat()}
							onChange={(e) =>
								setWebhookFormat(
									e.currentTarget.value as "json" | "cef" | "rfc5424",
								)
							}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						>
							<option value="json">JSON</option>
							<option value="cef">CEF</option>
							<option value="rfc5424">RFC 5424 syslog body</option>
						</select>
					</label>
					<label class="block">
						<span class="text-xs font-medium">HMAC secret (optional)</span>
						<input
							type="password"
							placeholder="cryptographic random, 32 bytes recommended"
							value={webhookHmac()}
							onInput={(e) => setWebhookHmac(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
						<p class="mt-1 text-xs text-muted-foreground">
							When set, each request carries{" "}
							<code class="font-mono">
								X-Yauth-Signature: t=&lt;unix&gt;,v1=&lt;hex&gt;
							</code>
							. See <code>docs/audit-export/webhook.md</code> for the verifier
							helper (Node + Python).
						</p>
					</label>
				</fieldset>
			</Show>

			<Show when={kindTag() === "syslog"}>
				<fieldset class="space-y-2">
					<label class="block">
						<span class="text-xs font-medium">Host</span>
						<input
							type="text"
							required
							placeholder="siem.example.internal"
							value={syslogHost()}
							onInput={(e) => setSyslogHost(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
					<label class="block">
						<span class="text-xs font-medium">Port</span>
						<input
							type="number"
							required
							min="1"
							max="65535"
							value={syslogPort()}
							onInput={(e) =>
								setSyslogPort(Number(e.currentTarget.value) || 0)
							}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
					<label class="block">
						<span class="text-xs font-medium">Transport</span>
						<select
							value={syslogTransport()}
							onChange={(e) =>
								setSyslogTransport(
									e.currentTarget.value as "tcp" | "udp" | "tls",
								)
							}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						>
							<option value="tcp">TCP (RFC 6587 octet-counted)</option>
							<option value="udp">
								UDP (unauthenticated, not recommended)
							</option>
							<option value="tls">TCP + TLS (port 6514)</option>
						</select>
					</label>
					<label class="block">
						<span class="text-xs font-medium">Facility (0–23)</span>
						<input
							type="number"
							required
							min="0"
							max="23"
							value={syslogFacility()}
							onInput={(e) =>
								setSyslogFacility(Number(e.currentTarget.value) || 0)
							}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
				</fieldset>
			</Show>

			<Show when={kindTag() === "s3"}>
				<fieldset class="space-y-2">
					<label class="block">
						<span class="text-xs font-medium">Bucket</span>
						<input
							type="text"
							required
							value={s3Bucket()}
							onInput={(e) => setS3Bucket(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
					<label class="block">
						<span class="text-xs font-medium">Prefix</span>
						<input
							type="text"
							value={s3Prefix()}
							onInput={(e) => setS3Prefix(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
					<label class="block">
						<span class="text-xs font-medium">Region</span>
						<input
							type="text"
							required
							value={s3Region()}
							onInput={(e) => setS3Region(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
					<label class="block">
						<span class="text-xs font-medium">Partition</span>
						<select
							value={s3Partition()}
							onChange={(e) =>
								setS3Partition(
									e.currentTarget.value as
										| "by_date"
										| "by_org"
										| "by_date_and_org",
								)
							}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						>
							<option value="by_date">By date</option>
							<option value="by_org">By org</option>
							<option value="by_date_and_org">By date and org</option>
						</select>
					</label>
				</fieldset>
			</Show>

			<Show when={kindTag() === "splunk"}>
				<fieldset class="space-y-2">
					<label class="block">
						<span class="text-xs font-medium">HEC URL</span>
						<input
							type="url"
							required
							placeholder="https://splunk.example.com:8088"
							value={splunkHecUrl()}
							onInput={(e) => setSplunkHecUrl(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
					<label class="block">
						<span class="text-xs font-medium">HEC token</span>
						<input
							type="password"
							required
							value={splunkHecToken()}
							onInput={(e) => setSplunkHecToken(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
				</fieldset>
			</Show>

			<Show when={kindTag() === "datadog"}>
				<fieldset class="space-y-2">
					<label class="block">
						<span class="text-xs font-medium">Site</span>
						<select
							value={ddSite()}
							onChange={(e) => setDdSite(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						>
							<option value="datadoghq.com">datadoghq.com (US1)</option>
							<option value="us3.datadoghq.com">us3.datadoghq.com (US3)</option>
							<option value="us5.datadoghq.com">us5.datadoghq.com (US5)</option>
							<option value="datadoghq.eu">datadoghq.eu (EU)</option>
							<option value="ap1.datadoghq.com">ap1.datadoghq.com (AP1)</option>
							<option value="ddog-gov.com">ddog-gov.com (US1-FED)</option>
						</select>
					</label>
					<label class="block">
						<span class="text-xs font-medium">API key</span>
						<input
							type="password"
							required
							value={ddApiKey()}
							onInput={(e) => setDdApiKey(e.currentTarget.value)}
							class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
						/>
					</label>
				</fieldset>
			</Show>

			<button
				type="submit"
				disabled={submitting()}
				class="inline-flex h-9 cursor-pointer items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 disabled:pointer-events-none disabled:opacity-50"
			>
				Add destination
			</button>
		</form>
	);
}
