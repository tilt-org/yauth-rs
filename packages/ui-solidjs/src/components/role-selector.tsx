import { type Component } from "solid-js";
import { ROLES } from "../hooks/create-organizations";

export interface RoleSelectorProps {
  value: string;
  disabled?: boolean;
  onChange: (value: string) => void;
}

/**
 * Dropdown for picking a built-in org role.
 *
 * `owner` is intentionally omitted — the documented promotion path is
 * `TransferOwnership`, and the server-side change-role endpoint rejects
 * an `owner` payload with 409.
 */
export const RoleSelector: Component<RoleSelectorProps> = (props) => {
  return (
    <select
      value={props.value}
      disabled={props.disabled}
      class="rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
      aria-label="Member role"
      onChange={(e) => props.onChange(e.currentTarget.value)}
    >
      <option value={ROLES.ADMIN}>Admin</option>
      <option value={ROLES.BILLING_ADMIN}>Billing admin</option>
      <option value={ROLES.MEMBER}>Member</option>
      <option value={ROLES.VIEWER}>Viewer</option>
    </select>
  );
};
