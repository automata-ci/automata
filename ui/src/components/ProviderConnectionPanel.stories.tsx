import type { Meta, StoryObj } from "@storybook/react-vite";
import { ProviderConnectionPanel } from "./ProviderConnectionPanel";

const meta = { component: ProviderConnectionPanel, parameters: { layout: "padded" }, title: "Components/Providers/ConnectionPanel" } satisfies Meta<typeof ProviderConnectionPanel>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Connected: Story = { args: { accountLabel: "automata-ci", controls: <button className="button">Manage</button>, headingId: "provider-story", lifecycle: "active", providerLabel: "GitHub", children: <p style={{ padding: 16 }}>12 repositories available</p> } };
export const Pending: Story = { args: { ...Connected.args, accountLabel: null, lifecycle: "pending" } };
export const Suspended: Story = { args: { ...Connected.args, lifecycle: "suspended" } };
