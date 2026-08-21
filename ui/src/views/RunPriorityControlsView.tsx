export interface RunPriorityControlsViewProps {
  readonly current: number;
  readonly endpoint: string;
  readonly csrfToken: string;
  readonly error: string | null;
  readonly onChange: (level: number) => void;
  readonly onSubmit: () => void;
  readonly pending: boolean;
}

export function RunPriorityControlsView({
  current,
  endpoint,
  csrfToken,
  error,
  onChange,
  onSubmit,
  pending,
}: RunPriorityControlsViewProps) {
  return (
    <form action={endpoint} aria-label="Priority controls" className="run-priority-controls" method="post" onSubmit={(event) => { event.preventDefault(); onSubmit(); }}>
      <input name="csrf_token" type="hidden" value={csrfToken} />
      <label>
        Priority
        <input
          className="form-control form-control--compact"
          disabled={pending}
          max={99}
          min={0}
          onChange={(event) => onChange(event.currentTarget.valueAsNumber)}
          type="number"
          value={current}
        />
      </label>
      <input name="priority" type="hidden" value={current} />
      <button className="button button--primary" disabled={pending} type="submit">
        {pending ? "Updating…" : "Update priority"}
      </button>
      {error === null ? null : <p role="alert">{error}</p>}
    </form>
  );
}
