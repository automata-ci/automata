import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn } from "storybook/test";
import type { JobLogsViewState } from "../viewModels/jobLogs";
import { previewJobLog, previewJobLogRecords } from "../preview/models";
import { replayLogRecords } from "../presenters/jobLogs";
import { PREVIEW_PRIMARY_RUN_ID } from "../preview/sampleData";
import { JobLogPageView } from "./JobLogPageView";

const model = previewJobLog(PREVIEW_PRIMARY_RUN_ID, null);
if (model === null) throw new Error("job-log preview fixture is unavailable");
const initial = replayLogRecords(
  previewJobLogRecords(PREVIEW_PRIMARY_RUN_ID, null),
);
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
  parameters: { layout: "fullscreen" },
  title: "Pages/Job Logs",
} satisfies Meta<typeof JobLogPageView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Complete: Story = {
  args: {
    logs: {
      ...logs,
      onQueryChange: fn(),
      onToggleAll: fn(),
      onToggleFollowing: fn(),
      onToggleGroup: fn(),
    },
  },
  play: async ({ args, canvas, canvasElement, userEvent }) => {
    await userEvent.click(canvas.getByRole("button", { name: "Collapse all" }));
    await expect(args.logs.onToggleAll).toHaveBeenCalledOnce();
    await userEvent.click(canvas.getByRole("button", { name: "Following" }));
    await expect(args.logs.onToggleFollowing).toHaveBeenCalledOnce();

    const firstGroup = initial.ordered[0];
    if (firstGroup === undefined)
      throw new Error("job-log story has no groups");
    const groupName = canvas.getByText(firstGroup.name, {
      selector: ".log-group__name",
    });
    await userEvent.click(groupName);
    await expect(args.logs.onToggleGroup).toHaveBeenCalledWith(firstGroup.id);

    const search = canvas.getByRole("searchbox", { name: "Search job logs" });
    await userEvent.type(search, "error");
    await expect(args.logs.onQueryChange).toHaveBeenCalled();
    search.blur();
    canvasElement.ownerDocument.defaultView?.scrollTo(0, 0);
  },
};
export const Waiting: Story = {
  args: {
    logs: {
      ...logs,
      connection: "connecting",
      running: true,
      visibleGroups: [],
    },
  },
};
export const StreamFailure: Story = {
  args: {
    logs: {
      ...logs,
      connection: "failed",
      streamError: "The log stream could not be opened.",
      visibleGroups: [],
    },
  },
};
export const Restricted: Story = {
  args: { model: { ...model, logVisibility: "restricted", live: null } },
};
