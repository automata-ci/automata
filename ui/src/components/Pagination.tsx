import type { PaginationModel } from "../models";

export interface PaginationProps {
  readonly label: string;
  readonly pagination: PaginationModel;
}

export function Pagination({ label, pagination }: PaginationProps) {
  if (pagination.previousHref === null && pagination.nextHref === null) {
    return null;
  }

  return (
    <nav className="pagination" aria-label={label}>
      {pagination.previousHref === null ? (
        <span className="button button--quiet" aria-disabled="true">
          Previous
        </span>
      ) : (
        <a className="button button--quiet" href={pagination.previousHref} rel="prev">
          Previous
        </a>
      )}
      {pagination.nextHref === null ? (
        <span className="button button--quiet" aria-disabled="true">
          Next
        </span>
      ) : (
        <a className="button button--quiet" href={pagination.nextHref} rel="next">
          Next
        </a>
      )}
    </nav>
  );
}
