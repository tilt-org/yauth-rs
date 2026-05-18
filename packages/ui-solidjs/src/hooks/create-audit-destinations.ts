// Hook for the audit-export admin surface (issue #96).
//
// Phase B: now uses the typed `@yackey-labs/yauth-client` after the
// routes_meta.rs regeneration registered `/audit/destinations` and friends.
// The raw-fetch fallback from the initial drop is gone — every call goes
// through the generated client functions, which route via the shared
// `customFetch` mutator.

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
import { type Accessor, createEffect, createSignal } from "solid-js";

export type AuditDestinationKindTag =
	| "webhook"
	| "syslog"
	| "s3"
	| "splunk"
	| "datadog";

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
 * from the global `configureClient` call made by the YAuthProvider. The
 * option is kept in the signature so existing call sites compile without
 * change.
 */
export interface CreateAuditDestinationsOptions {
	baseUrl?: string;
}

/**
 * Headless hook for audit-export destination management (issue #96).
 *
 * Mirrors `useAuditDestinations` from the Vue package. Pass an `orgScope`
 * accessor; the hook auto-fetches on mount and whenever the scope changes
 * (null = deployment-wide).
 */
export function createAuditDestinations(
	orgScope?: Accessor<string | null | undefined>,
	_options: CreateAuditDestinationsOptions = {},
) {
	const [destinations, setDestinations] = createSignal<AuditDestination[]>([]);
	const [loading, setLoading] = createSignal(false);
	const [submitting, setSubmitting] = createSignal(false);
	const [error, setError] = createSignal<string | null>(null);

	const refresh = async () => {
		setLoading(true);
		setError(null);
		try {
			const org = orgScope?.();
			const params = org
				? { organization_id: org }
				: { scope: "deployment" };
			const rows = await auditExportListDestinations(params);
			setDestinations(rows);
		} catch (e) {
			setError(e instanceof Error ? e.message : "failed to load destinations");
			setDestinations([]);
		} finally {
			setLoading(false);
		}
	};

	const create = async (
		input: CreateDestinationInput,
	): Promise<AuditDestination | null> => {
		setSubmitting(true);
		setError(null);
		try {
			const created = await auditExportCreateDestination(
				input as unknown as CreateAuditDestinationRequest,
			);
			await refresh();
			return created;
		} catch (e) {
			setError(e instanceof Error ? e.message : "create failed");
			return null;
		} finally {
			setSubmitting(false);
		}
	};

	const disable = async (id: string): Promise<void> => {
		setSubmitting(true);
		try {
			await auditExportUpdateDestination(id, {
				status: "disabled",
			} as UpdateAuditDestinationRequest);
			await refresh();
		} finally {
			setSubmitting(false);
		}
	};

	const remove = async (id: string): Promise<void> => {
		setSubmitting(true);
		try {
			await auditExportDeleteDestination(id);
			await refresh();
		} finally {
			setSubmitting(false);
		}
	};

	const outbox = async (id: string, limit = 50): Promise<OutboxEntry[]> =>
		(await auditExportListDestinationOutbox(id, {
			limit: String(limit),
		})) as unknown as OutboxEntry[];

	createEffect(() => {
		void orgScope?.();
		void refresh();
	});

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
