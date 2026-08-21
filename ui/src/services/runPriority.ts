import type { RunPriorityControlsModel } from "../models";

export async function updateRunPriority(
  controls: RunPriorityControlsModel,
  priority: number,
  fetcher: typeof fetch = fetch,
): Promise<void> {
  if (!Number.isInteger(priority) || priority < 0 || priority > 99) {
    throw new Error("invalid workflow priority");
  }
  const response = await fetcher(controls.endpoint, {
    method: "PUT",
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
      "x-automata-csrf-token": controls.csrfToken,
    },
    body: JSON.stringify({ priority }),
  });
  if (!response.ok) throw new Error("workflow priority rejected");
  const document: unknown = await response.json();
  if (
    typeof document !== "object" ||
    document === null ||
    !("priority" in document) ||
    document.priority !== priority
  ) {
    throw new Error("invalid workflow priority response");
  }
}
