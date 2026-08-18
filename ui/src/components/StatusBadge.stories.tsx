import type { Meta, StoryObj } from "@storybook/react-vite";
import { StatusBadge } from "./StatusBadge";

const meta = {
  component: StatusBadge,
  parameters: { layout: "centered" },
  title: "Foundations/StatusBadge",
} satisfies Meta<typeof StatusBadge>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Success: Story = {
  args: { status: { label: "Succeeded", tone: "success" } },
};

export const Running: Story = {
  args: { status: { label: "In progress", tone: "running" } },
};

export const StatusMatrix: Story = {
  args: { status: { label: "Queued", tone: "queued" } },
  render: () => (
    <div
      style={{
        alignItems: "flex-start",
        display: "flex",
        flexDirection: "column",
        gap: 12,
      }}
    >
      <StatusBadge status={{ label: "Queued", tone: "queued" }} />
      <StatusBadge status={{ label: "In progress", tone: "running" }} />
      <StatusBadge status={{ label: "Succeeded", tone: "success" }} />
      <StatusBadge status={{ label: "Failed", tone: "failure" }} />
      <StatusBadge status={{ label: "Cancelled", tone: "warning" }} />
      <StatusBadge status={{ label: "Skipped", tone: "neutral" }} />
      <StatusBadge status={{ label: "Lost", tone: "failure" }} />
    </div>
  ),
};
