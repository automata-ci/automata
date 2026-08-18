import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRunnerDirectory } from "../preview/models";
import { RunnerDirectoryPage } from "./RunnerDirectoryPage";

const model = previewRunnerDirectory();
const meta = {
  component: RunnerDirectoryPage,
  parameters: { layout: "fullscreen" },
  title: "Pages/Runners",
} satisfies Meta<typeof RunnerDirectoryPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Fleet: Story = { args: { model } };
export const Empty: Story = {
  args: {
    model: {
      ...model,
      runners: [],
      summary: "No runners are currently enrolled.",
    },
  },
};
export const PublicDirectory: Story = {
  args: { model: { ...model, visibility: "public" } },
};
