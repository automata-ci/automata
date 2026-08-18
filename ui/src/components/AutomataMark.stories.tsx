import type { Meta, StoryObj } from "@storybook/react-vite";
import { AutomataMark } from "./AutomataMark";

const meta = {
  component: AutomataMark,
  parameters: { layout: "centered" },
  title: "Foundations/Automata Mark",
} satisfies Meta<typeof AutomataMark>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {};
