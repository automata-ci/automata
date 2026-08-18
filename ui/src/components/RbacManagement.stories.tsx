import type { Meta, StoryObj } from "@storybook/react-vite";
import { previewUserList } from "../preview/rbacModels";
import { RbacManagement, RbacPermissionStatus, RbacScope, RbacStatus } from "./RbacManagement";

const model = previewUserList();
const meta = {
  args: { shell: model.shell, managementNav: model.managementNav, heading: "Members", summary: "Manage tenant access.", notice: null, children: <section className="panel rbac-panel"><div className="panel__heading"><h2>Member presentation</h2></div><div style={{ display: "flex", flexWrap: "wrap", gap: 16, padding: 16 }}><RbacStatus status="active" /><RbacPermissionStatus granted={true} /><RbacScope scope={{ kind: "tenant", label: "Automata tenant" }} /></div></section> },
  component: RbacManagement,
  title: "Components/RBAC/ManagementLayout",
} satisfies Meta<typeof RbacManagement>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Members: Story = {};
export const Saved: Story = { args: { notice: "saved" } };
export const Conflict: Story = { args: { notice: "conflict" } };
