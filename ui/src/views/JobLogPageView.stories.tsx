import type { Meta, StoryObj } from "@storybook/react-vite";
import { fn } from "storybook/test";
import type { JobLogsViewState } from "../viewModels/jobLogs";
import { previewJobLog, previewJobLogRecords } from "../preview/models";
import { replayLogRecords } from "../presenters/jobLogs";
import { PREVIEW_PRIMARY_RUN_ID } from "../preview/sampleData";
import { JobLogPageView } from "./JobLogPageView";

const model = previewJobLog(PREVIEW_PRIMARY_RUN_ID, null);
if (model === null) throw new Error("job-log preview fixture is unavailable");
const initial = replayLogRecords(previewJobLogRecords(PREVIEW_PRIMARY_RUN_ID, null));
const logs: JobLogsViewState = {
  canExpand: false,
  connection: "complete",
  expanded: new Set(initial.ordered.map((group) => group.id)),
  following: true,
  logToolsAvailable: true,
  onQueryChange: fn(),
  onToggleAll: fn(),
  onToggleFollowing: fn(),
  onToggleGroup: fn(),
  onViewerScroll: fn(),
  query: "",
  running: false,
  streamError: null,
  visibleGroups: initial.ordered,
};

const meta = {
  args: { logs, model },
  component: JobLogPageView,
  title: "Pages/Job Logs",
} satisfies Meta<typeof JobLogPageView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Complete: Story = {};
export const Waiting: Story = { args: { logs: { ...logs, connection: "connecting", running: true, visibleGroups: [] } } };
export const StreamFailure: Story = { args: { logs: { ...logs, connection: "failed", streamError: "The log stream could not be opened.", visibleGroups: [] } } };
export const Restricted: Story = { args: { model: { ...model, logVisibility: "restricted", live: null } } };
