import { type Component, For, Show, createMemo, createSignal } from "solid-js";
import { ROLES, createMembers, createOrgRoles } from "../hooks/create-organizations";

export interface TransferOwnershipProps {
  organizationId: string;
  open: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

/**
 * Modal-style component for transferring org ownership to another
 * member.
 */
export const TransferOwnership: Component<TransferOwnershipProps> = (props) => {
  const { members, refetch: refetchMembers } = createMembers(() => props.organizationId);
  const { submitting, error, transferOwnership } = createOrgRoles(() => props.organizationId);
  const [selectedUserId, setSelectedUserId] = createSignal("");
  const [confirmed, setConfirmed] = createSignal(false);

  const eligibleMembers = createMemo(() => members().filter((m) => m.role !== ROLES.OWNER));

  const close = () => {
    setSelectedUserId("");
    setConfirmed(false);
    props.onClose();
  };

  const submit = async () => {
    if (!selectedUserId() || !confirmed()) return;
    const ok = await transferOwnership({
      new_owner_user_id: selectedUserId(),
    });
    if (ok) {
      props.onSuccess?.();
      await refetchMembers();
      close();
    }
  };

  return (
    <Show when={props.open}>
      <div
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
        role="dialog"
        aria-modal="true"
        aria-labelledby="transfer-ownership-title"
      >
        <div class="w-full max-w-md rounded-lg border border-input bg-background p-6 shadow-lg">
          <h2 id="transfer-ownership-title" class="mb-2 text-lg font-semibold">
            Transfer ownership
          </h2>
          <p class="mb-4 text-sm text-muted-foreground">
            Choose a member to promote to owner. You will be demoted to admin. This cannot be undone
            without another transfer.
          </p>

          <Show when={error()}>
            <div
              class="mb-3 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
              role="alert"
            >
              {error()}
            </div>
          </Show>

          <label class="mb-2 block text-sm font-medium" for="successor-select">
            New owner
          </label>
          <select
            id="successor-select"
            value={selectedUserId()}
            disabled={submitting()}
            onChange={(e) => setSelectedUserId(e.currentTarget.value)}
            class="mb-4 w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="" disabled>
              Select a member…
            </option>
            <For each={eligibleMembers()}>
              {(m) => (
                <option value={m.user_id}>
                  {m.user_id} ({m.role})
                </option>
              )}
            </For>
          </select>

          <label class="mb-4 flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={confirmed()}
              disabled={submitting()}
              onChange={(e) => setConfirmed(e.currentTarget.checked)}
              class="mt-0.5"
            />
            <span>I understand I will lose owner privileges in this organization.</span>
          </label>

          <div class="flex justify-end gap-2">
            <button
              type="button"
              class="rounded-md border border-input px-3 py-1.5 text-sm hover:bg-secondary"
              disabled={submitting()}
              onClick={close}
            >
              Cancel
            </button>
            <button
              type="button"
              class="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              disabled={!selectedUserId() || !confirmed() || submitting()}
              onClick={submit}
            >
              {submitting() ? "Transferring…" : "Transfer ownership"}
            </button>
          </div>
        </div>
      </div>
    </Show>
  );
};
