import type { Meta, StoryObj } from "@storybook/react-vite";
import { MetadataSeparator } from "./MetadataSeparator";

const meta = {
  component: MetadataSeparator,
  parameters: { layout: "centered" },
  title: "Foundations/MetadataSeparator",
} satisfies Meta<typeof MetadataSeparator>;
export default meta;
type Story = StoryObj<typeof meta>;
export const Inline: Story = {
  render: () => (
    <p>
      main
      <MetadataSeparator />
      082b454
      <MetadataSeparator />2 minutes
    </p>
  ),
};
