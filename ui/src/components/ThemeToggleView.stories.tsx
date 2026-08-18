import type { Meta, StoryObj } from "@storybook/react-vite";
import { expect, fn } from "storybook/test";
import { ThemeToggleView } from "./ThemeToggleView";

const meta = {
  args: { onToggle: fn() },
  component: ThemeToggleView,
  parameters: { layout: "centered" },
  title: "Components/ThemeToggle",
} satisfies Meta<typeof ThemeToggleView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Light: Story = {
  args: { onToggle: fn(), theme: "light" },
  play: async ({ args, canvas, userEvent }) => {
    await userEvent.click(canvas.getByRole("button", { name: "Use dark theme" }));
    await expect(args.onToggle).toHaveBeenCalledOnce();
  },
};
export const Dark: Story = { args: { theme: "dark" } };
export const Hydrating: Story = { args: { theme: null } };
