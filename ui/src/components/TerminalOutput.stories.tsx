import type { Meta, StoryObj } from "@storybook/react-vite";
import { TerminalTranscript } from "../logs/terminal";
import type { LogGroupView } from "../presenters/jobLogs";
import { TerminalOutput } from "./TerminalOutput";

const transcript = new TerminalTranscript();
const lines = [
  ...transcript.push({
    channel: "stdout",
    data: new TextEncoder().encode("\u001b[1;97mBuilding\u001b[0m café 🚀\nFinished successfully\n"),
    emittedAtMs: 1_777_890_010_000,
    groupId: "build",
    part: 0,
    sequence: "1",
    streamId: "00000000-0000-4000-8000-000000000099",
    type: "output",
  }),
  ...transcript.finish(),
];
const group: LogGroupView = {
  conclusion: "success",
  finishedAtMs: 1_777_890_011_000,
  id: "build",
  kind: "step",
  lines,
  name: "Build application",
  ordinal: 0,
  parentId: null,
  startedAtMs: 1_777_890_010_000,
};

const meta = {
  component: TerminalOutput,
  parameters: { layout: "fullscreen" },
  title: "Components/TerminalOutput",
} satisfies Meta<typeof TerminalOutput>;

export default meta;
type Story = StoryObj<typeof meta>;

export const StyledUnicodeOutput: Story = {
  args: {
    group,
    panelId: "terminal-output-story",
    subscribeOutput: undefined,
  },
  render: (args) => <div className="log-viewer"><div className="log-groups"><TerminalOutput {...args} /></div></div>,
};
