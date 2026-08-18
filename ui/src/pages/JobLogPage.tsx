import type { ReactNode } from "react";
import type { JobLogPageModel } from "../models";
import type { LiveLogAccessProvider } from "../logs/protocol";
import type { LiveLogRecord } from "../logs/sse";
import { useJobLogs } from "../hooks/useJobLogs";
import { JobLogPageView } from "../views/JobLogPageView";

export interface JobLogPageProps {
  readonly access?: LiveLogAccessProvider;
  readonly model: JobLogPageModel;
  readonly shellUtility?: ReactNode;
  /** Structured sample records used only by the standalone UI preview. */
  readonly initialRecords?: readonly LiveLogRecord[];
}

/** Connects the resumable log controller to a pure, storyable log view. */
export function JobLogPage({
  access,
  model,
  shellUtility,
  initialRecords = [],
}: JobLogPageProps) {
  const logs = useJobLogs({
    ...(access === undefined ? {} : { access }),
    initialRecords,
    model,
  });
  return <JobLogPageView logs={logs} model={model} shellUtility={shellUtility} />;
}
