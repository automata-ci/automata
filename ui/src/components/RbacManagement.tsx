import { useEffect, useRef, useState } from "react";
import type { PropsWithChildren, ReactNode } from "react";
import type {
  ManagedUserStatus,
  RbacBindingStatus,
  RbacManagementNavigationModel,
  RbacManagementNotice,
  RbacScopeModel,
  ShellModel,
} from "../models";
import { Shell } from "./Shell";

export interface RbacManagementProps extends PropsWithChildren {
  readonly shell: ShellModel;
  readonly managementNav: RbacManagementNavigationModel;
  readonly heading: string;
  readonly summary: string;
  readonly notice: RbacManagementNotice | null;
  readonly shellUtility?: ReactNode;
}

export interface RbacTableRegionProps extends PropsWithChildren {
  readonly labelledBy: string;
}

const managementLinks = [
  { area: "users", hrefKey: "usersHref", label: "Members" },
  { area: "roles", hrefKey: "rolesHref", label: "Roles" },
  {
    area: "direct-bindings",
    hrefKey: "directBindingsHref",
    label: "Direct bindings",
  },
] as const;

/** Shared authenticated shell and landmark structure for RBAC management. */
export function RbacManagement({
  shell,
  managementNav,
  heading,
  summary,
  notice,
  shellUtility,
  children,
}: RbacManagementProps) {
  return (
    <Shell
      repository={null}
      shell={shell}
      utility={shellUtility}
    >
      <div className="layout-width page">
        <div className="rbac-management">
          <nav className="rbac-management__navigation" aria-label="Access management">
            {managementLinks.map((item) => (
              <a
                aria-current={managementNav.current === item.area ? "page" : undefined}
                href={managementNav[item.hrefKey]}
                key={item.area}
              >
                {item.label}
              </a>
            ))}
          </nav>
          <main className="rbac-management__content" id="main-content" tabIndex={-1}>
            <header className="page-heading rbac-management__heading">
              <div>
                <h1>{heading}</h1>
                <p>{summary}</p>
              </div>
            </header>
            {notice === null ? null : <RbacNotice notice={notice} />}
            {children}
          </main>
        </div>
      </div>
    </Shell>
  );
}

function RbacNotice({ notice }: { readonly notice: RbacManagementNotice }) {
  const message = notice === "saved"
    ? "Access management changes were saved."
    : notice === "conflict"
      ? "The access record changed. Review the current values before trying again."
      : "Your current grants do not allow that change.";
  return (
    <p
      className={`rbac-notice rbac-notice--${notice}`}
      role={notice === "saved" ? "status" : "alert"}
    >
      {message}
    </p>
  );
}

/** Keyboard-accessible region for a table that can overflow at narrow widths. */
export function RbacTableRegion({
  labelledBy,
  children,
}: RbacTableRegionProps) {
  const regionRef = useRef<HTMLDivElement>(null);
  const [isOverflowing, setIsOverflowing] = useState(false);

  useEffect(() => {
    const region = regionRef.current;
    if (region === null) return;

    const updateOverflow = () => {
      setIsOverflowing(region.scrollWidth > region.clientWidth);
    };
    updateOverflow();
    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", updateOverflow);
      return () => window.removeEventListener("resize", updateOverflow);
    }

    const observer = new ResizeObserver(updateOverflow);
    observer.observe(region);
    if (region.firstElementChild !== null) {
      observer.observe(region.firstElementChild);
    }
    return () => observer.disconnect();
  }, []);

  return (
    <div
      aria-labelledby={labelledBy}
      className="rbac-table-region"
      ref={regionRef}
      role="region"
      tabIndex={isOverflowing ? 0 : undefined}
    >
      {children}
    </div>
  );
}

export function RbacScope({ scope }: { readonly scope: RbacScopeModel }) {
  const kindLabel = scope.kind === "tenant"
    ? "Tenant"
    : scope.kind === "repository"
      ? "Repository"
      : "Runner group";
  return (
    <span className="rbac-scope">
      <strong>{scope.label}</strong>
      <small>{kindLabel}</small>
    </span>
  );
}

export function RbacStatus({
  status,
}: {
  readonly status: RbacBindingStatus | ManagedUserStatus;
}) {
  const label = status === "active"
    ? "Active"
    : status === "disabled"
      ? "Disabled"
      : "Revoked";
  return <span className={`rbac-status rbac-status--${status}`}>{label}</span>;
}

export function RbacPermissionStatus({ granted }: { readonly granted: boolean }) {
  return (
    <span
      className={`rbac-status rbac-status--${granted ? "granted" : "not-granted"}`}
    >
      {granted ? "Granted" : "Not granted"}
    </span>
  );
}

/** Human-facing provider name while retaining the stable provider ID in data. */
export function rbacProviderLabel(providerId: string): string {
  return providerId.toLowerCase() === "github" ? "GitHub" : providerId;
}
