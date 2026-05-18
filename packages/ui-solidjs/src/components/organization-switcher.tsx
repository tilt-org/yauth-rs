import type { ActiveOrgEntry } from "@yackey-labs/yauth-client";
import { type Component, createSignal, For, onCleanup } from "solid-js";
import { Show } from "solid-js/web";
import { createActiveOrg } from "../hooks/create-active-org";

export interface OrganizationSwitcherProps {
  /**
   * Override the active org id (e.g. for SSR or test fixtures). When
   * omitted the component reads from `createActiveOrg()` and is fully
   * self-driving.
   */
  activeId?: string | null;
  /**
   * Callback fired after a successful switch — receives the membership
   * entry the caller switched into. Useful for clients that need to
   * adopt a freshly-issued bearer token from `switchTo`.
   */
  onSwitch?: (org: ActiveOrgEntry, bearerToken: string | null) => void;
}

/**
 * Organization-switcher dropdown (issue #89).
 *
 * Self-driving by default: reads the active-org claim and full membership
 * list from the server via `createActiveOrg`, and dispatches switches
 * through the active-org endpoint. Cookie callers update server-side;
 * bearer callers receive a freshly-issued JWT in the response that the
 * `onSwitch` callback can adopt.
 */
export const OrganizationSwitcher: Component<OrganizationSwitcherProps> = (props) => {
  const { activeOrgId, orgs, loading, switchTo } = createActiveOrg();
  const [open, setOpen] = createSignal(false);
  let containerEl: HTMLDivElement | undefined;

  const effectiveActiveId = () => (props.activeId === undefined ? activeOrgId() : props.activeId);
  const activeOrg = () => orgs().find((o) => o.organization_id === effectiveActiveId()) ?? null;

  const handleClickOutside = (e: MouseEvent) => {
    if (!containerEl) return;
    if (!containerEl.contains(e.target as Node)) {
      setOpen(false);
      document.removeEventListener("mousedown", handleClickOutside);
    }
  };

  const toggle = () => {
    const next = !open();
    setOpen(next);
    if (next) {
      document.addEventListener("mousedown", handleClickOutside);
    } else {
      document.removeEventListener("mousedown", handleClickOutside);
    }
  };

  const choose = async (org: ActiveOrgEntry) => {
    setOpen(false);
    document.removeEventListener("mousedown", handleClickOutside);
    const bearerToken = await switchTo(org.organization_id);
    props.onSwitch?.(org, bearerToken);
  };

  onCleanup(() => {
    document.removeEventListener("mousedown", handleClickOutside);
  });

  return (
    <div ref={containerEl} class="relative inline-block w-full">
      <button
        class="inline-flex h-9 w-full cursor-pointer items-center justify-between gap-2 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        type="button"
        aria-expanded={open()}
        aria-haspopup="listbox"
        aria-label="Switch organization"
        disabled={loading() && orgs().length === 0}
        on:click={toggle}
      >
        <span class="truncate">
          {activeOrg()?.display_name ||
            activeOrg()?.slug ||
            (loading() ? "Loading…" : "Select organization")}
        </span>
        <svg
          class="h-4 w-4 shrink-0 opacity-50"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          aria-hidden="true"
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      <Show when={open()}>
        <div
          class="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-md border border-input bg-popover text-popover-foreground shadow-md"
          role="listbox"
        >
          <For each={orgs()}>
            {(org) => (
              <button
                class="flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
                type="button"
                role="option"
                aria-selected={org.organization_id === effectiveActiveId()}
                on:click={() => void choose(org)}
              >
                <div class="min-w-0 flex-1">
                  <div class="truncate font-medium">
                    {org.display_name || org.slug || org.organization_id}
                  </div>
                  <Show when={org.slug}>
                    <div class="truncate font-mono text-xs text-muted-foreground">@{org.slug}</div>
                  </Show>
                </div>
                <Show when={org.organization_id === effectiveActiveId()}>
                  <svg
                    class="h-4 w-4 shrink-0"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    aria-hidden="true"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                </Show>
              </button>
            )}
          </For>
          <Show when={orgs().length === 0}>
            <div class="px-3 py-2 text-sm text-muted-foreground">No organizations.</div>
          </Show>
        </div>
      </Show>
    </div>
  );
};
