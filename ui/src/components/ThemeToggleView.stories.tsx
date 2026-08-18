import type { Meta, StoryObj } from "@storybook/react-vite";
import { useEffect, useState } from "react";
import { expect, fn } from "storybook/test";
import { ThemeToggleView } from "./ThemeToggleView";
import type { ThemeToggleViewProps } from "./ThemeToggleView";

function InteractiveThemeToggle(args: ThemeToggleViewProps) {
  const [theme, setTheme] = useState(args.theme);

  useEffect(() => setTheme(args.theme), [args.theme]);

  const handleToggle = () => {
    args.onToggle();
    setTheme(theme === "dark" ? "light" : "dark");
  };

  return <ThemeToggleView {...args} onToggle={handleToggle} theme={theme} />;
}

const meta = {
  args: { onToggle: fn() },
  component: ThemeToggleView,
  parameters: { layout: "centered" },
  render: InteractiveThemeToggle,
  title: "Components/ThemeToggle",
} satisfies Meta<typeof ThemeToggleView>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Light: Story = {
  args: { onToggle: fn(), theme: "light" },
  play: async ({ args, canvas, userEvent }) => {
    await userEvent.click(
      canvas.getByRole("button", { name: "Use dark theme" }),
    );
    await expect(args.onToggle).toHaveBeenCalledOnce();
    await expect(
      await canvas.findByRole("button", { name: "Use light theme" }),
    ).toBeVisible();
    await userEvent.click(
      canvas.getByRole("button", { name: "Use light theme" }),
    );
    await expect(args.onToggle).toHaveBeenCalledTimes(2);
    canvas.getByRole("button", { name: "Use dark theme" }).blur();
  },
};
export const Dark: Story = { args: { theme: "dark" } };
export const Hydrating: Story = { args: { theme: null } };
