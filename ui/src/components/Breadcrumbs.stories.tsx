import type { Meta, StoryObj } from "@storybook/react-vite";
import { Breadcrumbs } from "./Breadcrumbs";

const meta = {
  component: Breadcrumbs,
  parameters: { layout: "padded" },
  title: "Components/Navigation/Breadcrumbs",
} satisfies Meta<typeof Breadcrumbs>;
export default meta;
type Story = StoryObj<typeof meta>;
export const RunJob: Story = {
  args: {
    items: [
      { href: "/actions", label: "Actions" },
      { href: "/workflows/ci", label: "CI" },
      { href: "/runs/42", label: "Run #42" },
      { href: null, label: "test-linux" },
    ],
  },
};
