import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRunDetail } from "../preview/models";
import { PREVIEW_PRIMARY_RUN_ID } from "../preview/sampleData";
import { RunDetailPage } from "./RunDetailPage";

const model = previewRunDetail(PREVIEW_PRIMARY_RUN_ID);
if (model === null)
  throw new Error("run-detail preview fixture is unavailable");
const meta = {
  component: RunDetailPage,
  parameters: { layout: "fullscreen" },
  title: "Pages/Run Summary",
} satisfies Meta<typeof RunDetailPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Complete: Story = { args: { model } };
export const JobsRestricted: Story = {
  args: {
    model: {
      ...model,
      jobs: { ...model.jobs, items: [], visibility: "restricted" },
    },
  },
};
