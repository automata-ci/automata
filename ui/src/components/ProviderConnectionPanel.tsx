import type { ReactNode } from "react";

export type ProviderConnectionLifecycle =
  | "pending"
  | "active"
  | "suspended"
  | "removed";

export interface ProviderConnectionPanelProps {
  readonly accountLabel: string | null;
  readonly children?: ReactNode;
  readonly controls?: ReactNode;
  readonly headingId: string;
  readonly lifecycle: ProviderConnectionLifecycle;
  readonly providerLabel: string;
}

/**
 * Host-neutral framing for an installed source-control provider.
 *
 * The host owns authorization and mutations and supplies those controls as
 * children. Keeping transport out of this component lets the embedded Rust
 * host and the Cloud SSR host reuse the same presentation without sharing
 * private APIs.
 */
export function ProviderConnectionPanel({
  accountLabel,
  children,
  controls,
  headingId,
  lifecycle,
  providerLabel,
}: ProviderConnectionPanelProps) {
  return (
    <section className="panel provider-connection" aria-labelledby={headingId}>
      <div className="panel__heading provider-connection__heading">
        <h2 id={headingId}>{providerLabel}</h2>
        <span data-provider-connection-state={lifecycle}>
          {lifecycleLabel(lifecycle)}
        </span>
      </div>
      <div className="provider-connection__summary">
        <div>
          <strong>{accountLabel ?? "Installation pending"}</strong>
          <span>{lifecycleDescription(lifecycle, providerLabel)}</span>
        </div>
        {controls}
      </div>
      {children}
    </section>
  );
}

function lifecycleLabel(lifecycle: ProviderConnectionLifecycle): string {
  switch (lifecycle) {
    case "pending":
      return "Pending";
    case "active":
      return "Connected";
    case "suspended":
      return "Suspended";
    case "removed":
      return "Removed";
  }
}

function lifecycleDescription(
  lifecycle: ProviderConnectionLifecycle,
  providerLabel: string,
): string {
  switch (lifecycle) {
    case "pending":
      return `Waiting for ${providerLabel} to confirm this installation.`;
    case "active":
      return `Choose which ${providerLabel} repositories this workspace can use.`;
    case "suspended":
      return `This ${providerLabel} installation is suspended. Existing selections are read-only.`;
    case "removed":
      return `This ${providerLabel} installation was removed. Its repositories are no longer available.`;
  }
}
