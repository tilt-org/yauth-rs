// Composable for the audit-export admin surface (issue #96).
//
// Phase B: now uses the typed `@yackey-labs/yauth-client` after the
// routes_meta.rs regeneration registered `/audit/destinations` and friends.
// The raw-fetch fallback from the original commit is gone — every call goes
// through the generated client functions, which apply `credentials:
// 'include'` and route through the shared client `customFetch` mutator.

import { computed, ref, watch } from "vue";
import type {
	AuditDestinationResponse,
	CreateAuditDestinationRequest,
	UpdateAuditDestinationRequest,
} from "@yackey-labs/yauth-client";
import {
	auditExportCreateDestination,
	auditExportDeleteDestination,
	auditExportListDestinationOutbox,
	auditExportListDestinations,
	auditExportUpdateDestination,
} from "@yackey-labs/yauth-client";

export type AuditDestinationKindTag =
	| "webhook"
	| "syslog"
	| "s3"
	| "splunk"
	| "datadog";

/** Re-export the wire type alias under a stable, ergonomic name. */
export type AuditDestination = AuditDestinationResponse;

export interface OutboxEntry {
	id: string;
	audit_log_id: string;
	destination_id: string;
	status: "pending" | "sent" | "failed" | "dead_letter";
	attempts: number;
	last_attempt_at: string | null;
	last_error: string | null;
	created_at: string;
}

/**
 * Discriminated-union helper that maps to the generated
 * `CreateAuditDestinationRequest`. The generated type carries `kind` as an
 * untyped object; this alias narrows the per-kind variants for callers
 * building the form payload.
 */
export type CreateDestinationInput = Omit<
	CreateAuditDestinationRequest,
	"kind"
> & {
	kind:
		| {
				type: "webhook";
				url: string;
				format?: "json" | "cef" | "rfc5424";
				hmac_secret?: string;
				headers?: Record<string, string>;
		  }
		| {
				type: "syslog";
				host: string;
				port: number;
				transport?: "tcp" | "udp" | "tls";
				facility?: number;
		  }
		| {
				type: "s3";
				bucket: string;
				prefix?: string;
				region: string;
				partition?: "by_date" | "by_org" | "by_date_and_org";
		  }
		| { type: "splunk"; hec_url: string; hec_token: string }
		| { type: "datadog"; site: string; api_key: string };
};

/**
 * `baseUrl` is no longer required — the typed client reads its base URL
 * from the global `configureClient` call made by the YAuthPlugin. The
 * option is kept in the signature so existing call sites compile without
 * change.
 */
export interface UseAuditDestinationsOptions {
	baseUrl?: string;
}

export function useAuditDestinations(
	orgScope?: () => string | null,
	_options: UseAuditDestinationsOptions = {},
) {
	const destinations = ref<AuditDestination[]>([]);
	const loading = ref(false);
	const submitting = ref(false);
	const error = ref<string | null>(null);

	async function refresh() {
		loading.value = true;
		error.value = null;
		try {
			const org = orgScope?.();
			const params = org
				? { organization_id: org }
				: { scope: "deployment" };
			destinations.value = await auditExportListDestinations(params);
		} catch (e) {
			error.value = (e as Error).message;
		} finally {
			loading.value = false;
		}
	}

	async function create(
		input: CreateDestinationInput,
	): Promise<AuditDestination> {
		submitting.value = true;
		error.value = null;
		try {
			// The generated wire type widens `kind` to `unknown`; the typed
			// CreateDestinationInput above narrows it for callers.
			const created = await auditExportCreateDestination(
				input as unknown as CreateAuditDestinationRequest,
			);
			await refresh();
			return created;
		} catch (e) {
			error.value = (e as Error).message;
			throw e;
		} finally {
			submitting.value = false;
		}
	}

	async function disable(id: string) {
		submitting.value = true;
		try {
			await auditExportUpdateDestination(id, {
				status: "disabled",
			} as UpdateAuditDestinationRequest);
			await refresh();
		} finally {
			submitting.value = false;
		}
	}

	async function remove(id: string) {
		submitting.value = true;
		try {
			await auditExportDeleteDestination(id);
			await refresh();
		} finally {
			submitting.value = false;
		}
	}

	async function outbox(id: string, limit = 50): Promise<OutboxEntry[]> {
		// The generated response type is an array of objects matching the
		// `OutboxEntryResponse` shape; cast to the local convenience type.
		// `limit` is serialized to a string by the orval-generated wrapper.
		return (await auditExportListDestinationOutbox(id, {
			limit: String(limit),
		})) as unknown as OutboxEntry[];
	}

	watch(
		computed(() => orgScope?.()),
		() => {
			void refresh();
		},
		{ immediate: true },
	);

	return {
		destinations,
		loading,
		submitting,
		error,
		refresh,
		create,
		disable,
		remove,
		outbox,
	};
}
