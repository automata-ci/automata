import type { Meta, StoryObj } from "@storybook/react-vite";
import { fn } from "storybook/test";
import { ThemeToggleView } from "./ThemeToggleView";

const meta = {
  args: { onToggle: fn() },
  component: ThemeToggleView,
  parameters: { layout: "centered" },
  title: "Components/ThemeToggle",
} satisfies Meta<typeof ThemeToggleView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Light: Story = { args: { theme: "light" } };
export const Dark: Story = { args: { theme: "dark" } };
export const Hydrating: Story = { args: { theme: null } };
