import type { StatusModel } from "../models";

export interface StatusBadgeProps {
  readonly status: StatusModel;
  /**
   * `accessible` exposes an icon-only status; `none` is decorative when the
   * same status is already written nearby.
   */
  readonly labelMode?: "visible" | "accessible" | "none";
}

const statusIcons: Readonly<Record<StatusModel["tone"], string>> = {
  neutral: "minus-circle",
  queued: "clock",
  running: "circle-notch",
  success: "check-circle",
  failure: "x-circle",
  warning: "warning-circle",
};

export function StatusBadge({
  status,
  labelMode = "visible",
}: StatusBadgeProps) {
  return (
    <span
      aria-hidden={labelMode === "none" ? "true" : undefined}
      aria-label={labelMode === "accessible" ? status.label : undefined}
      className={`status status--${status.tone}`}
      role={labelMode === "accessible" ? "img" : undefined}
    >
      <i
        aria-hidden="true"
        className={`ph ph-${statusIcons[status.tone]} status__icon`}
      />
      {labelMode === "visible" ? (
        <span className="status__label">{status.label}</span>
      ) : null}
    </span>
  );
}
