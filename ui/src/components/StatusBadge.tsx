import type { StatusModel } from "../models";

export interface StatusBadgeProps {
  readonly status: StatusModel;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span className={`status status--${status.tone}`}>
      <span className="status__dot" aria-hidden="true" />
      {status.label}
    </span>
  );
}
