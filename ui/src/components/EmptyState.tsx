import type { ReactNode } from "react";
import type { IconName } from "./Icon";
import { Icon } from "./Icon";

export interface EmptyStateProps {
  readonly action?: ReactNode;
  readonly description: ReactNode;
  readonly heading?: string;
  readonly headingLevel?: "h1" | "h3";
  readonly icon?: IconName;
  readonly variant?: "default" | "compact";
}

export function EmptyState({
  action,
  description,
  heading,
  headingLevel = "h3",
  icon,
  variant = "default",
}: EmptyStateProps) {
  if (variant === "compact") {
    return (
      <div className="panel compact-empty-state">
        <p>{description}</p>
        {action}
      </div>
    );
  }

  const Heading = headingLevel;
  return (
    <div className="empty-state">
      {icon === undefined ? null : (
        <span className="empty-state__icon" aria-hidden="true">
          <Icon name={icon} size={24} />
        </span>
      )}
      {heading === undefined ? null : <Heading>{heading}</Heading>}
      <p>{description}</p>
      {action}
    </div>
  );
}
