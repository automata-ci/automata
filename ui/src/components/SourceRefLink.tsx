import type { SourceRefKind, SourceRefModel } from "../models";
import { Icon } from "./Icon";

export interface SourceRefLinkProps {
  readonly className?: string;
  readonly refModel: SourceRefModel;
  readonly size?: 14 | 15;
}

export function SourceRefLink({
  className,
  refModel,
  size = 14,
}: SourceRefLinkProps) {
  const icon =
    refModel.kind === "tag"
      ? "tag"
      : refModel.kind === "ref"
        ? "pull-request"
        : "branch";
  const classes =
    className === undefined
      ? "source-ref-link"
      : `source-ref-link ${className}`;

  return (
    <a
      aria-label={`${sourceRefLabel(refModel.kind)} ${refModel.name}`}
      className={classes}
      href={refModel.href}
    >
      <Icon name={icon} size={size} />
      <span>{refModel.name}</span>
    </a>
  );
}

export function sourceRefLabel(kind: SourceRefKind): string {
  return kind === "branch" ? "Branch" : kind === "tag" ? "Tag" : "Ref";
}
