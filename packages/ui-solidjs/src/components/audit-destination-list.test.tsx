/**
 * Smoke test for the SolidJS audit-destination hook (issue #96).
 *
 * We test the headless `createAuditDestinations` hook (signal-only, no
 * DOM) so the test suite doesn't need a Solid DOM testing-library. The
 * component itself is a thin wrapper around this hook — covered by
 * typecheck + build.
 */
import { configureClient } from "@yackey-labs/yauth-client";
import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuditDestinations } from "../hooks/create-audit-destinations";

beforeEach(() => {
	// The typed client reads its baseUrl from the global config; tests
	// install an empty baseUrl so the mocked `fetch` sees the raw paths.
	configureClient({ baseUrl: "" });
});

function mockFetch(response: unknown, status = 200) {
	const text = typeof response === "string" ? response : JSON.stringify(response);
	const fn = vi.fn().mockResolvedValue({
		ok: status >= 200 && status < 300,
		status,
		statusText: status === 200 ? "OK" : "ERR",
		text: () => Promise.resolve(text),
		json: () => Promise.resolve(response),
	});
	(globalThis as unknown as { fetch: typeof fetch }).fetch =
		fn as unknown as typeof fetch;
	return fn;
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("createAuditDestinations", () => {
	it("fetches destinations on mount and exposes them via the signal", async () => {
		mockFetch([
			{
				id: "019e36bf-1234-7000-8000-aaaaaaaaaaaa",
				organization_id: null,
				name: "prod-splunk",
				kind_tag: "splunk",
				kind: { type: "splunk", hec_url: "https://splunk.example.com" },
				status: "active",
				last_success_at: null,
				last_failure_at: null,
				created_at: "2026-05-17T12:00:00Z",
				updated_at: "2026-05-17T12:00:00Z",
			},
		]);

		await createRoot(async (dispose) => {
			const hook = createAuditDestinations(() => null);
			// Allow the createEffect → refresh chain to run.
			await new Promise((r) => setTimeout(r, 5));
			expect(hook.destinations()).toHaveLength(1);
			expect(hook.destinations()[0]?.name).toBe("prod-splunk");
			expect(hook.error()).toBeNull();
			dispose();
		});
	});

	it("surfaces fetch errors via the error signal", async () => {
		mockFetch({ error: "audit-export down" }, 500);
		await createRoot(async (dispose) => {
			const hook = createAuditDestinations(() => null);
			await new Promise((r) => setTimeout(r, 5));
			expect(hook.destinations()).toHaveLength(0);
			expect(hook.error()).toMatch(/audit-export down/);
			dispose();
		});
	});

	it("scopes the request to the org path when the accessor returns an id", async () => {
		// The huma-derived spec moved org scoping from an `organization_id`
		// query param to a path segment (`/organizations/{id}/audit/destinations`).
		const fetchSpy = mockFetch([]);
		await createRoot(async (dispose) => {
			createAuditDestinations(() => "org-uuid-123");
			await new Promise((r) => setTimeout(r, 5));
			const callUrl = (fetchSpy.mock.calls[0]?.[0] as string) ?? "";
			expect(callUrl).toContain("/organizations/org-uuid-123/audit/destinations");
			dispose();
		});
	});
});
