import type { Meta, StoryObj } from "@storybook/react-vite";
import { fn } from "storybook/test";
import { RunRerunControlsView } from "./RunRerunControlsView";

const meta = {
  args: {
    error: null,
    failedJobsAvailable: true,
    onRerunAll: fn(),
    onRerunFailed: fn(),
    pending: false,
  },
  component: RunRerunControlsView,
  parameters: { layout: "centered" },
  title: "Features/Runs/RerunControls",
} satisfies Meta<typeof RunRerunControlsView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Ready: Story = {};
export const NoFailedJobs: Story = { args: { failedJobsAvailable: false } };
export const Pending: Story = { args: { pending: true } };
export const Failed: Story = { args: { error: "The rerun could not be started. Refresh and try again." } };
