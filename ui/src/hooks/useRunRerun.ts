import { useCallback, useState } from "react";
import type { RunRerunControlsModel } from "../models";
import { startRunRerun, type RunRerunMode } from "../services/runRerun";

export interface UseRunRerunOptions {
  readonly controls: RunRerunControlsModel;
  readonly runsHref: string;
}

export function useRunRerun({ controls, runsHref }: UseRunRerunOptions) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const rerun = useCallback(async (mode: RunRerunMode) => {
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const runId = await startRunRerun({ controls, mode });
      window.location.assign(`${runsHref}/runs/${runId}`);
    } catch {
      setPending(false);
      setError("The rerun could not be started. Refresh and try again.");
    }
  }, [controls, pending, runsHref]);

  return {
    error,
    pending,
    rerunAll: () => void rerun("entire_workflow"),
    rerunFailed: () => void rerun("failed_jobs_and_dependents"),
  } as const;
}
