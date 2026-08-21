import { useCallback, useRef, useState, type FormEvent } from "react";
import type { RunPriorityControlsModel } from "../models";
import { updateRunPriority } from "../services/runPriority";

export function useRunPriority(controls: RunPriorityControlsModel) {
  const [level, setLevel] = useState(controls.current);
  const [pending, setPending] = useState(false);
  const pendingRef = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const submit = useCallback((event?: FormEvent<HTMLFormElement>) => {
    event?.preventDefault();
    if (pendingRef.current) return;
    pendingRef.current = true;
    setPending(true);
    setError(null);
    void updateRunPriority(controls, level)
      .then(() => window.location.reload())
      .catch(() => {
        pendingRef.current = false;
        setPending(false);
        setError("The priority could not be updated. Refresh and try again.");
      });
  }, [controls, level]);
  return { error, level, pending, setLevel, submit } as const;
}
