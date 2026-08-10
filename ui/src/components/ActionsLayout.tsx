import type { PropsWithChildren, ReactNode } from "react";

export interface ActionsLayoutProps extends PropsWithChildren {
  readonly navigation: ReactNode;
}

/** Shared two-column actions layout; responsive behavior belongs to CSS. */
export function ActionsLayout({
  children,
  navigation,
}: ActionsLayoutProps) {
  return (
    <div className="actions-layout">
      {navigation}
      <div className="actions-content" id="main-content" tabIndex={-1}>
        {children}
      </div>
    </div>
  );
}
