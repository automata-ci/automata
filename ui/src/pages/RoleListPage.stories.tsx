import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewRoleList } from "../preview/rbacModels";
import { RoleListPage } from "./RoleListPage";

const model = previewRoleList();
const meta = {
  component: RoleListPage,
  parameters: { layout: "fullscreen" },
  title: "Pages/Access/Roles",
} satisfies Meta<typeof RoleListPage>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Populated: Story = { args: { model } };
export const Empty: Story = { args: { model: { ...model, roles: [] } } };
