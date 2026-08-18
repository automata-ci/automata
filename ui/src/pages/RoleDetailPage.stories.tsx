import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRoleDetail } from "../preview/rbacModels";
import { RoleDetailPage } from "./RoleDetailPage";

const model = previewRoleDetail();
if (model === null) throw new Error("role preview fixture is unavailable");
const meta = {
  component: RoleDetailPage,
  parameters: { layout: "fullscreen" },
  title: "Pages/Access/Role Detail",
} satisfies Meta<typeof RoleDetailPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Custom: Story = { args: { model } };
export const BuiltIn: Story = {
  args: { model: previewRoleDetail("tenant-viewer") ?? model },
};
