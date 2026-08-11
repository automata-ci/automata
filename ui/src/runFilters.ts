export const RUN_STATUS_FILTER_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "queued", label: "Queued" },
  { value: "in_progress", label: "In progress" },
  { value: "completed", label: "Completed" },
] as const;

export type RunStatusFilter =
  (typeof RUN_STATUS_FILTER_OPTIONS)[number]["value"];

export const RUN_STATUS_FILTER_VALUES: readonly RunStatusFilter[] =
  Object.freeze(RUN_STATUS_FILTER_OPTIONS.map(({ value }) => value));

export function isRunStatusFilter(value: string | null): value is RunStatusFilter {
  return RUN_STATUS_FILTER_VALUES.some((candidate) => candidate === value);
}
