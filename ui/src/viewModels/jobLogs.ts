import type { RefObject } from "react";
import type { LogGroupView } from "../presenters/jobLogs";

export type LogConnectionState =
  | "idle"
  | "connecting"
  | "open"
  | "reconnecting"
  | "paused"
  | "complete"
  | "failed";

/** Complete serializable/render callback contract consumed by the log view. */
export interface JobLogsViewState {
  readonly canExpand: boolean;
  readonly connection: LogConnectionState;
  readonly expanded: ReadonlySet<string>;
  readonly following: boolean;
  readonly logToolsAvailable: boolean;
  readonly onQueryChange: (query: string) => void;
  readonly onToggleAll: () => void;
  readonly onToggleFollowing: () => void;
  readonly onToggleGroup: (id: string) => void;
  readonly onViewerScroll: () => void;
  readonly query: string;
  readonly running: boolean;
  readonly streamError: string | null;
  readonly viewerRef?: RefObject<HTMLDivElement | null>;
  readonly visibleGroups: readonly LogGroupView[];
}
