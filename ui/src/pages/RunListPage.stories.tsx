import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRunList } from "../preview/models";
import { RunListPage } from "./RunListPage";

const populated = previewRunList(new URLSearchParams("view=runs"));
const meta = {
  component: RunListPage,
  parameters: { layout: "fullscreen" },
  title: "Pages/Workflow Runs",
} satisfies Meta<typeof RunListPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Populated: Story = { args: { model: populated } };
export const Empty: Story = { args: { model: { ...populated, runs: [] } } };
