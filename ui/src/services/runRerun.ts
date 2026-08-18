import type { RunRerunControlsModel } from "../models";

export type RunRerunMode = "entire_workflow" | "failed_jobs_and_dependents";

export interface StartRunRerunOptions {
  readonly controls: RunRerunControlsModel;
  readonly fetcher?: typeof fetch;
  readonly mode: RunRerunMode;
  readonly operationId?: () => string;
}

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

/** Performs and validates the rerun protocol independently of React or navigation. */
export async function startRunRerun({
  controls,
  fetcher = fetch,
  mode,
  operationId = () => crypto.randomUUID(),
}: StartRunRerunOptions): Promise<string> {
  const response = await fetcher(controls.endpoint, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
      "x-automata-csrf-token": controls.csrfToken,
    },
    body: JSON.stringify({
      operation_id: operationId(),
      selection: { mode },
    }),
  });
  if (!response.ok) throw new Error("rerun rejected");
  const document: unknown = await response.json();
  if (
    typeof document !== "object" ||
    document === null ||
    !("run_id" in document) ||
    typeof document.run_id !== "string" ||
    !RUN_ID.test(document.run_id)
  ) {
    throw new Error("invalid rerun response");
  }
  return document.run_id;
}
