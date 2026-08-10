import type { CommitModel } from "../models";
import { Icon } from "./Icon";

export interface CommitLinkProps {
  readonly className: string;
  readonly commit: CommitModel;
  readonly iconSize?: 14 | 15;
  readonly messageClassName: string;
  readonly showIcon?: boolean;
}

/** One consistent, unambiguous link to a source commit. */
export function CommitLink({
  className,
  commit,
  iconSize = 14,
  messageClassName,
  showIcon = true,
}: CommitLinkProps) {
  const accessibleLabel =
    commit.message === null
      ? `Commit ${commit.shortSha}`
      : `Commit ${commit.shortSha}: ${commit.message}`;

  return (
    <a aria-label={accessibleLabel} className={className} href={commit.href}>
      {showIcon ? <Icon name="commit" size={iconSize} /> : null}
      <span>{commit.shortSha}</span>
      {commit.message === null ? null : (
        <span className={messageClassName}>{commit.message}</span>
      )}
    </a>
  );
}
