import type { PropsWithChildren, RefObject } from "react";

export interface RbacTableRegionViewProps extends PropsWithChildren {
  readonly isOverflowing: boolean;
  readonly labelledBy: string;
  readonly regionRef?: RefObject<HTMLDivElement | null>;
}

/** Pure accessible region for an RBAC table; overflow measurement is injected. */
export function RbacTableRegionView({
  children,
  isOverflowing,
  labelledBy,
  regionRef,
}: RbacTableRegionViewProps) {
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
