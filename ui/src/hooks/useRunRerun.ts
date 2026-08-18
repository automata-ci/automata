import { useCallback, useRef, useState } from "react";
import type { RunRerunControlsModel } from "../models";
import { startRunRerun, type RunRerunMode } from "../services/runRerun";

export interface UseRunRerunOptions {
  readonly controls: RunRerunControlsModel;
  readonly runsHref: string;
}

export function useRunRerun({ controls, runsHref }: UseRunRerunOptions) {
  const [pending, setPending] = useState(false);
  const pendingRef = useRef(false);
  const [error, setError] = useState<string | null>(null);

  const rerun = useCallback(async (mode: RunRerunMode) => {
    if (pendingRef.current) return;
    pendingRef.current = true;
    setPending(true);
    setError(null);
    try {
      const runId = await startRunRerun({ controls, mode });
      window.location.assign(`${runsHref}/runs/${runId}`);
    } catch {
      pendingRef.current = false;
      setPending(false);
      setError("The rerun could not be started. Refresh and try again.");
    }
  }, [controls, runsHref]);

  const rerunAll = useCallback(() => {
    void rerun("entire_workflow");
  }, [rerun]);
  const rerunFailed = useCallback(() => {
    void rerun("failed_jobs_and_dependents");
  }, [rerun]);

  return {
    error,
    pending,
    rerunAll,
    rerunFailed,
  } as const;
}
