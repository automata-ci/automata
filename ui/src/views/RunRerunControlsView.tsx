export interface RunRerunControlsViewProps {
  readonly error: string | null;
  readonly failedJobsAvailable: boolean;
  readonly onRerunAll: () => void;
  readonly onRerunFailed: () => void;
  readonly pending: boolean;
}

export function RunRerunControlsView({
  error,
  failedJobsAvailable,
  onRerunAll,
  onRerunFailed,
  pending,
}: RunRerunControlsViewProps) {
  return (
    <div aria-label="Rerun controls">
      <button className="button button--primary" disabled={pending} onClick={onRerunAll} type="button">
        {pending ? "Starting rerun…" : "Re-run all jobs"}
      </button>
      {failedJobsAvailable ? (
        <button className="button button--quiet" disabled={pending} onClick={onRerunFailed} type="button">
          Re-run failed jobs
        </button>
      ) : null}
      {error === null ? null : <p role="alert">{error}</p>}
    </div>
  );
}
