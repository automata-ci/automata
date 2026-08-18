import type { Meta, StoryObj } from "@storybook/react-vite";
import { EmptyState } from "./EmptyState";

const meta = {
  component: EmptyState,
  parameters: { layout: "padded" },
  title: "Components/Feedback/EmptyState",
} satisfies Meta<typeof EmptyState>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Default: Story = {
  args: {
    action: (
      <a className="button button--primary" href="#create">
        Create workflow
      </a>
    ),
    description: "Add a workflow file to start running continuous integration.",
    heading: "No workflow runs yet",
    icon: "actions",
  },
};
export const Compact: Story = {
  args: { description: "No artifacts were produced.", variant: "compact" },
};
